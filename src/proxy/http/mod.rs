use hyper::{StatusCode, Uri};
use proxy_signature::ProxySign;
use std::{net::SocketAddr, sync::LazyLock, time::Duration};
use tokio::sync::Mutex;

use crate::{
    address_status::{AddressStatus, AddressStatusOperations},
    ctx::{AppConfig, ProxyRoute},
    db::Db,
    expirable_map::ExpirableMap,
    kdf::peer_connection_healthcheck_rpc,
    logger::tracked_log,
    rate_limiter::RateLimitOperations,
};

pub(crate) mod get;
pub(crate) mod post;

pub(crate) async fn validation_middleware(
    cfg: &AppConfig,
    signed_message: &ProxySign,
    proxy_route: &ProxyRoute,
    req_uri: &Uri,
    remote_addr: &SocketAddr,
) -> Result<(), StatusCode> {
    let mut db = Db::create_instance(cfg).await;

    // Once we know a peer is connected to the KDF network, we can assume they are connected
    // for 10 seconds without asking again.
    const KNOW_PEER_EXPIRATION: Duration = Duration::from_secs(10);
    static KNOWN_PEERS: LazyLock<Mutex<ExpirableMap<String, ()>>> =
        LazyLock::new(|| Mutex::new(ExpirableMap::new()));

    let mut know_peers = KNOWN_PEERS.lock().await;

    know_peers.clear_expired_entries();
    let is_known = know_peers.get(&signed_message.address).is_some();

    if !is_known {
        match peer_connection_healthcheck_rpc(cfg, &signed_message.address).await {
            Ok(response) => {
                if response["result"] == serde_json::json!(true) {
                    know_peers.insert(signed_message.address.clone(), (), KNOW_PEER_EXPIRATION);
                } else {
                    tracked_log(
                        log::Level::Warn,
                        remote_addr.ip(),
                        &signed_message.address,
                        req_uri,
                        "Peer isn't connected to KDF network, returning 401",
                    );

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
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    drop(know_peers);

    match db.read_address_status(&signed_message.address).await {
        AddressStatus::Trusted => Ok(()),
        AddressStatus::Blocked => Err(StatusCode::FORBIDDEN),
        AddressStatus::None => {
            if !signed_message.is_valid_message() {
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
            match db.rate_exceeded(&rate_limiter_key, rate_limiter).await {
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

            Ok(())
        }
    }
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
        assert!(deserialized_proxy_sign.is_valid_message());

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
