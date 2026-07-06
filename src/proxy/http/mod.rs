use hyper::{StatusCode, Uri};
use libp2p::PeerId;
use proxy_signature::ProxySign;
use std::{
    net::SocketAddr,
    str::FromStr,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    sync::LazyLock,
    time::{Duration, Instant},
};
use timed_map::{MapKind, StdClock, TimedMap};
use tokio::sync::Mutex;

use crate::{
    address_status::{AddressStatus, AddressStatusOperations},
    ctx::{AppConfig, ProxyRoute},
    db::Db,
    kdf_rpc_interface::peer_connection_healthcheck_rpc,
    logger::tracked_log,
    rate_limiter::RateLimitOperations,
};

pub(crate) mod gasfree;
pub(crate) mod get;
pub(crate) mod post;

const MAX_SIGNATURE_EXP_SECS: u64 = 15;

/// hang-debug: monotonically increasing id assigned to every request entering
/// `validation_middleware`, used to correlate log lines of one request.
static VALIDATION_REQ_ID: AtomicU64 = AtomicU64::new(0);

/// hang-debug: number of tasks currently blocked waiting for the KNOWN_PEERS lock.
static KNOWN_PEERS_LOCK_WAITERS: AtomicUsize = AtomicUsize::new(0);

pub(crate) async fn validation_middleware(
    cfg: &AppConfig,
    signed_message: &ProxySign,
    proxy_route: &ProxyRoute,
    req_uri: &Uri,
    remote_addr: &SocketAddr,
) -> Result<(), StatusCode> {
    // If KDF access checks are disabled via config, bypass signature, peer and rate-limit validations.
    if !cfg.kdf_access_only {
        return Ok(());
    }

    let req_id = VALIDATION_REQ_ID.fetch_add(1, Ordering::Relaxed);
    let t_start = Instant::now();
    tracked_log(
        log::Level::Debug,
        remote_addr.ip(),
        &signed_message.address,
        req_uri,
        format!("hang-debug: [req#{req_id}] validation started"),
    );

    let t_redis = Instant::now();
    let mut db = Db::create_instance(cfg).await;
    tracked_log(
        log::Level::Debug,
        remote_addr.ip(),
        &signed_message.address,
        req_uri,
        format!(
            "hang-debug: [req#{req_id}] redis connection acquired in {}ms",
            t_redis.elapsed().as_millis()
        ),
    );

    let t_status = Instant::now();
    let address_status = db.read_address_status(&signed_message.address).await;
    tracked_log(
        log::Level::Debug,
        remote_addr.ip(),
        &signed_message.address,
        req_uri,
        format!(
            "hang-debug: [req#{req_id}] address status read as {:?} in {}ms",
            address_status,
            t_status.elapsed().as_millis()
        ),
    );

    match address_status {
        AddressStatus::Trusted => Ok(()),
        AddressStatus::Blocked => Err(StatusCode::FORBIDDEN),
        AddressStatus::None => {
            let t_hc = Instant::now();
            let hc_result =
                peer_connection_healthcheck(cfg, signed_message, req_uri, remote_addr, req_id)
                    .await;
            tracked_log(
                log::Level::Debug,
                remote_addr.ip(),
                &signed_message.address,
                req_uri,
                format!(
                    "hang-debug: [req#{req_id}] peer_connection_healthcheck finished in {}ms (result: {:?})",
                    t_hc.elapsed().as_millis(),
                    hc_result
                ),
            );
            hc_result?;

            let t_sig = Instant::now();
            let sig_valid = signed_message.is_valid_message(MAX_SIGNATURE_EXP_SECS);
            tracked_log(
                log::Level::Debug,
                remote_addr.ip(),
                &signed_message.address,
                req_uri,
                format!(
                    "hang-debug: [req#{req_id}] signature validation done in {}ms (valid: {sig_valid})",
                    t_sig.elapsed().as_millis()
                ),
            );

            if !sig_valid {
                tracked_log(
                    log::Level::Warn,
                    remote_addr.ip(),
                    &signed_message.address,
                    req_uri,
                    "Request has invalid signed message, returning 401",
                );

                return Err(StatusCode::UNAUTHORIZED);
            }

            let rate_limiter_key =
                format!("{}:{}", proxy_route.inbound_route, signed_message.address);

            let rate_limiter = proxy_route
                .rate_limiter
                .as_ref()
                .unwrap_or(&cfg.rate_limiter);
            let t_rate = Instant::now();
            let rate_result = db.rate_exceeded(&rate_limiter_key, rate_limiter).await;
            tracked_log(
                log::Level::Debug,
                remote_addr.ip(),
                &signed_message.address,
                req_uri,
                format!(
                    "hang-debug: [req#{req_id}] rate_exceeded checked in {}ms",
                    t_rate.elapsed().as_millis()
                ),
            );
            match rate_result {
                Ok(false) => {}
                Ok(true) => {
                    tracked_log(
                        log::Level::Warn,
                        remote_addr.ip(),
                        &signed_message.address,
                        req_uri,
                        format!("Rate exceed for {}, returning 406.", rate_limiter_key),
                    );
                    return Err(StatusCode::NOT_ACCEPTABLE);
                }
                Err(e) => {
                    tracked_log(
                        log::Level::Error,
                        remote_addr.ip(),
                        &signed_message.address,
                        req_uri,
                        format!(
                            "Rate exceeded check failed for node '{}': {}, returning 500.",
                            signed_message.address, e
                        ),
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }

            if let Err(e) = db.rate_address(rate_limiter_key).await {
                tracked_log(
                    log::Level::Error,
                    remote_addr.ip(),
                    &signed_message.address,
                    req_uri,
                    format!(
                        "Rate incrementing failed for node '{}': {}, returning 500.",
                        signed_message.address, e
                    ),
                );
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            };

            tracked_log(
                log::Level::Debug,
                remote_addr.ip(),
                &signed_message.address,
                req_uri,
                format!(
                    "hang-debug: [req#{req_id}] validation finished OK, total {}ms",
                    t_start.elapsed().as_millis()
                ),
            );

            Ok(())
        }
    }
}

async fn peer_connection_healthcheck(
    cfg: &AppConfig,
    signed_message: &ProxySign,
    req_uri: &Uri,
    remote_addr: &SocketAddr,
    req_id: u64,
) -> Result<(), StatusCode> {
    // Once we know a peer is connected to the KDF network, we can assume they are connected
    // for 10 seconds without asking again.
    let know_peer_expiration = Duration::from_secs(cfg.peer_healthcheck_caching_secs);

    static KNOWN_PEERS: LazyLock<Mutex<TimedMap<StdClock, PeerId, ()>>> = LazyLock::new(|| {
        Mutex::new(TimedMap::new_with_map_kind(MapKind::FxHashMap).expiration_tick_cap(25))
    });

    let waiters = KNOWN_PEERS_LOCK_WAITERS.fetch_add(1, Ordering::SeqCst) + 1;
    tracked_log(
        log::Level::Debug,
        remote_addr.ip(),
        &signed_message.address,
        req_uri,
        format!("hang-debug: [req#{req_id}] waiting for KNOWN_PEERS lock (waiters incl. this one: {waiters})"),
    );

    let t_lock_wait = Instant::now();
    let mut know_peers = KNOWN_PEERS.lock().await;
    let t_lock_held = Instant::now();
    let waiters_left = KNOWN_PEERS_LOCK_WAITERS.fetch_sub(1, Ordering::SeqCst) - 1;
    tracked_log(
        log::Level::Debug,
        remote_addr.ip(),
        &signed_message.address,
        req_uri,
        format!(
            "hang-debug: [req#{req_id}] KNOWN_PEERS lock ACQUIRED after {}ms wait (waiters still queued: {waiters_left})",
            t_lock_wait.elapsed().as_millis()
        ),
    );

    // hang-debug: log lock hold duration on every exit path of the critical section.
    macro_rules! log_lock_release {
        ($outcome:expr) => {
            tracked_log(
                log::Level::Debug,
                remote_addr.ip(),
                &signed_message.address,
                req_uri,
                format!(
                    "hang-debug: [req#{req_id}] KNOWN_PEERS lock RELEASED after being held {}ms (outcome: {})",
                    t_lock_held.elapsed().as_millis(),
                    $outcome
                ),
            );
        };
    }

    let Ok(peer_id) = PeerId::from_str(&signed_message.address) else {
        tracked_log(
            log::Level::Warn,
            remote_addr.ip(),
            &signed_message.address,
            req_uri,
            format!(
                "Peer id '{}' isn't valid, returning 401",
                signed_message.address
            ),
        );
        log_lock_release!("invalid peer id, 401");
        return Err(StatusCode::UNAUTHORIZED);
    };

    let is_known = know_peers.get(&peer_id).is_some();
    tracked_log(
        log::Level::Debug,
        remote_addr.ip(),
        &signed_message.address,
        req_uri,
        format!("hang-debug: [req#{req_id}] KNOWN_PEERS cache lookup: {}", if is_known { "HIT (skipping KDF RPC)" } else { "MISS (KDF RPC required, WHILE HOLDING THE LOCK)" }),
    );

    if !is_known {
        let t_rpc = Instant::now();
        let rpc_result = peer_connection_healthcheck_rpc(cfg, &signed_message.address).await;
        tracked_log(
            log::Level::Debug,
            remote_addr.ip(),
            &signed_message.address,
            req_uri,
            format!(
                "hang-debug: [req#{req_id}] peer_connection_healthcheck RPC to KDF took {}ms, response: {}",
                t_rpc.elapsed().as_millis(),
                match &rpc_result {
                    Ok(v) => v.to_string(),
                    Err(e) => format!("ERROR: {e}"),
                }
            ),
        );
        match rpc_result {
            Ok(response) => {
                if response["result"] == serde_json::json!(true) {
                    know_peers.insert_expirable(peer_id, (), know_peer_expiration);
                } else {
                    tracked_log(
                        log::Level::Warn,
                        remote_addr.ip(),
                        &signed_message.address,
                        req_uri,
                        "Peer isn't connected to KDF network, returning 401",
                    );

                    log_lock_release!("peer not connected, 401");
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
            Err(error) => {
                tracked_log(
                    log::Level::Error,
                    remote_addr.ip(),
                    &signed_message.address,
                    req_uri,
                    format!(
                        "`peer_connection_healthcheck` RPC failed, returning 500. Error: {}",
                        error
                    ),
                );
                log_lock_release!("RPC error, 500");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    log_lock_release!("ok");
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyper::{header, Body, Request, StatusCode};

    use crate::proxy::http::get::modify_request_uri;
    use crate::proxy::{remove_hop_by_hop_headers, HeaderValue, APPLICATION_JSON, X_AUTH_PAYLOAD};
    use crate::{ctx, proxy::response_by_status};

    use super::*;
    use hyper::header::HeaderName;
    use hyper::Method;
    use libp2p::identity;
    use proxy_signature::RawMessage;

    fn generate_ed25519_keypair(mut p2p_key: [u8; 32]) -> identity::Keypair {
        let secret = identity::ed25519::SecretKey::try_from_bytes(&mut p2p_key)
            .expect("Secret length is 32 bytes");
        let keypair = identity::ed25519::Keypair::from(secret);
        identity::Keypair::from(keypair)
    }

    #[test]
    fn test_get_proxy_route_by_inbound() {
        use hyper::Uri;
        use std::str::FromStr;

        let cfg = ctx::get_app_config_test_instance();

        let proxy_route = cfg.get_proxy_route_by_inbound("/test").unwrap();

        assert_eq!(proxy_route.outbound_route, "https://komodoplatform.com");

        let proxy_route = cfg.get_proxy_route_by_inbound("/test-2").unwrap();

        assert_eq!(proxy_route.outbound_route, "https://atomicdex.io");

        let url = Uri::from_str("https://komodo.proxy:5535/nft-test").unwrap();
        let path = url.path().to_string();
        let proxy_route = cfg.get_proxy_route_by_inbound(&path).unwrap();
        assert_eq!(proxy_route.outbound_route, "https://nft.proxy");
    }

    #[test]
    fn test_get_proxy_route_by_uri_inbound() {
        use hyper::Uri;
        use std::str::FromStr;

        let cfg = ctx::get_app_config_test_instance();

        // test "/nft-test" inbound case
        let mut url = Uri::from_str("https://komodo.proxy:5535/nft-test/nft/api/v2.2/0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326/nft/transfers?chain=eth&format=decimal&order=DESC").unwrap();
        let proxy_route = cfg.get_proxy_route_by_uri(&mut url).unwrap();
        assert_eq!(proxy_route.outbound_route, "https://nft.proxy");

        // test "/nft-test/special" inbound case
        let mut url = Uri::from_str("https://komodo.proxy:3333/nft-test/special/api/v2.2/0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326/nft/transfers?chain=eth&format=decimal&order=DESC").unwrap();
        let proxy_route = cfg.get_proxy_route_by_uri(&mut url).unwrap();
        assert_eq!(proxy_route.outbound_route, "https://nft.special");

        // test "/" inbound case
        let mut url = Uri::from_str("https://komodo.proxy:0333/api/v2.2/0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326/nft/transfers?chain=eth&format=decimal&order=DESC").unwrap();
        let proxy_route = cfg.get_proxy_route_by_uri(&mut url).unwrap();
        assert_eq!(proxy_route.outbound_route, "https://adex.io");
    }

    #[test]
    fn test_respond_by_status() {
        let all_supported_status_codes = [
            100, 101, 102, 200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302, 303,
            304, 305, 307, 308, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412,
            413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 426, 428, 429, 431, 451, 500, 501,
            502, 503, 504, 505, 506, 507, 508, 510, 511,
        ];

        for status_code in all_supported_status_codes {
            let status_type = StatusCode::from_u16(status_code).unwrap();
            let res = response_by_status(status_type).unwrap();
            assert_eq!(res.status(), status_type);
        }
    }

    #[tokio::test]
    async fn sign_serialize_and_send() {
        let keypair = generate_ed25519_keypair([0; 32]);
        let proxy_sign =
            RawMessage::sign(&keypair, &Uri::from_static("http://example.com"), 0, 5).unwrap();
        let serialized_proxy_sign = serde_json::to_string(&proxy_sign).unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .header(header::ACCEPT, HeaderValue::from_static(APPLICATION_JSON))
            .header(
                crate::proxy::X_AUTH_PAYLOAD,
                HeaderValue::from_str(&serialized_proxy_sign).unwrap(),
            )
            .body(Body::empty())
            .unwrap();

        let (mut req, deserialized_proxy_sign) =
            crate::proxy::parse_auth_header(req).await.unwrap();

        let body_bytes = hyper::body::to_bytes(req.body_mut()).await.unwrap();
        assert!(
            body_bytes.is_empty(),
            "Body should be empty for GET methods"
        );

        assert_eq!(deserialized_proxy_sign, proxy_sign);
        assert!(deserialized_proxy_sign.is_valid_message(MAX_SIGNATURE_EXP_SECS));

        let additional_headers = &[
            header::CONTENT_LENGTH,
            HeaderName::from_bytes(X_AUTH_PAYLOAD.as_bytes()).unwrap(),
        ];
        remove_hop_by_hop_headers(&mut req, additional_headers).unwrap();
    }

    #[tokio::test]
    async fn test_modify_request_uri() {
        use crate::proxy::ProxyType;
        use std::str::FromStr;

        const EXPECTED_URI: &str = "http://localhost:8000/api/v2.2/0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326/nft/transfers?chain=eth&format=decimal&order=DESC";

        let mut req = Request::builder()
        .uri("https://komodo.proxy:5535/nft-test/nft/api/v2.2/0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326/nft/transfers?chain=eth&format=decimal&order=DESC")
        .body(Body::empty())
        .unwrap();
        let proxy_route = ProxyRoute {
            inbound_route: String::from_str("/nft-test").unwrap(),
            outbound_route: "http://localhost:8000".to_string(),
            proxy_type: ProxyType::Moralis,
            authorized: false,
            allowed_rpc_methods: vec![],
            rate_limiter: None,
        };
        modify_request_uri(&mut req, &proxy_route).unwrap();
        assert_eq!(
        req.uri(),
        "http://localhost:8000/nft/api/v2.2/0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326/nft/transfers?chain=eth&format=decimal&order=DESC"
    );

        let mut req = Request::builder()
        .uri("https://komodo.proxy:5535/nft-test/special/api/v2.2/0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326/nft/transfers?chain=eth&format=decimal&order=DESC")
        .body(Body::empty())
        .unwrap();
        let proxy_route = ProxyRoute {
            inbound_route: String::from_str("/nft-test/special").unwrap(),
            outbound_route: "http://localhost:8000".to_string(),
            proxy_type: ProxyType::Moralis,
            authorized: false,
            allowed_rpc_methods: vec![],
            rate_limiter: None,
        };
        modify_request_uri(&mut req, &proxy_route).unwrap();
        assert_eq!(req.uri(), EXPECTED_URI);

        let mut req = Request::builder()
        .uri("https://komodo.proxy:5535/api/v2.2/0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326/nft/transfers?chain=eth&format=decimal&order=DESC")
        .body(Body::empty())
        .unwrap();
        let proxy_route = ProxyRoute {
            inbound_route: String::from_str("/").unwrap(),
            outbound_route: "http://localhost:8000".to_string(),
            proxy_type: ProxyType::Moralis,
            authorized: false,
            allowed_rpc_methods: vec![],
            rate_limiter: None,
        };
        modify_request_uri(&mut req, &proxy_route).unwrap();
        assert_eq!(req.uri(), EXPECTED_URI);
    }
}
