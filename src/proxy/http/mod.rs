use hyper::{StatusCode, Uri};
use libp2p::{identity::PublicKey, PeerId};
use proxy_signature::ProxySign;
use std::{
    collections::HashMap,
    net::SocketAddr,
    str::FromStr,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    sync::{Arc, LazyLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
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

/// How many bytes the signer used for `RawMessage.body_size` (a `usize`) when
/// encoding the message for signing.
#[derive(Clone, Copy)]
enum BodySizeEncoding {
    /// 8 bytes — what `usize::to_ne_bytes()` produces on native 64-bit platforms,
    /// and the only encoding `proxy_signature::is_valid_message` verifies against.
    Native8,
    /// 4 bytes — what `usize::to_ne_bytes()` produces on wasm32 (browser-wallet
    /// KDF builds).
    Wasm32_4,
}

/// Outcome of the local `X-Auth-Payload` signature verification.
#[derive(Debug)]
enum SignatureVerdict {
    /// Ed25519 verified over the canonical encoding (`body_size` as 8 bytes).
    ValidNative,
    /// Ed25519 verified over the wasm32-compat encoding (`body_size` as 4 bytes).
    ValidWasm32Compat,
    /// Rejected, with the reason.
    Invalid(String),
}

/// `proxy_signature::RawMessage::encode()` equivalent with a configurable
/// `body_size` width. The byte layout must stay in lockstep with the crate:
/// prefix + public_key_encoded + uri + body_size + expires_at (8-byte LE i64).
fn encode_raw_message(sign: &ProxySign, body_size_encoding: BodySizeEncoding) -> Vec<u8> {
    const PREFIX: &[u8] = b"Encoded Message for KDP\n";
    let raw = &sign.raw_message;
    let mut bytes = PREFIX.to_vec();
    bytes.extend_from_slice(&raw.public_key_encoded);
    bytes.extend_from_slice(raw.uri.as_bytes());
    match body_size_encoding {
        BodySizeEncoding::Native8 => bytes.extend_from_slice(&(raw.body_size as u64).to_le_bytes()),
        BodySizeEncoding::Wasm32_4 => bytes.extend_from_slice(&(raw.body_size as u32).to_le_bytes()),
    }
    bytes.extend_from_slice(&raw.expires_at.to_le_bytes());
    bytes
}

/// Re-implementation of `proxy_signature::ProxySign::is_valid_message` (crate rev
/// `e65fefe5`, the one pinned in Cargo.lock) with one addition: when the signature
/// does not verify over the canonical encoding, it is retried with `body_size`
/// encoded as 4 bytes.
///
/// Rationale: `RawMessage::encode()` in the crate serializes `body_size` (a `usize`)
/// with `to_ne_bytes()`, which is 4 bytes on wasm32 but 8 bytes here, so a correctly
/// signed request from a WASM client (browser wallet) can never pass the stock
/// verification — see GLEECBTC/komodo-defi-proxy#30. Drop the fallback once
/// `proxy_signature` encodes `body_size` as a fixed-width `u64` and the wallet WASM
/// builds are rebuilt against it.
fn verify_signature_wasm_compat(sign: &ProxySign, max_message_exp_secs: u64) -> SignatureVerdict {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX);

    let remaining = u64::try_from(sign.raw_message.expires_at.saturating_sub(now)).unwrap_or(0);
    if remaining == 0 {
        return SignatureVerdict::Invalid("message expired".into());
    }
    if remaining > max_message_exp_secs {
        return SignatureVerdict::Invalid(format!(
            "expiration {remaining}s ahead exceeds the allowed {max_message_exp_secs}s window"
        ));
    }

    let Ok(public_key) = PublicKey::try_decode_protobuf(&sign.raw_message.public_key_encoded)
    else {
        return SignatureVerdict::Invalid(
            "public key doesn't decode as libp2p protobuf".into(),
        );
    };

    if sign.address != public_key.to_peer_id().to_string() {
        return SignatureVerdict::Invalid(
            "address doesn't match the embedded public key".into(),
        );
    }

    if public_key.verify(
        &encode_raw_message(sign, BodySizeEncoding::Native8),
        &sign.signature_bytes,
    ) {
        return SignatureVerdict::ValidNative;
    }

    if public_key.verify(
        &encode_raw_message(sign, BodySizeEncoding::Wasm32_4),
        &sign.signature_bytes,
    ) {
        return SignatureVerdict::ValidWasm32Compat;
    }

    SignatureVerdict::Invalid(
        "Ed25519 signature doesn't verify (tried both 8-byte and 4-byte body_size encodings)"
            .into(),
    )
}

/// hang-debug: monotonically increasing id assigned to every request entering
/// `validation_middleware`, used to correlate log lines of one request.
static VALIDATION_REQ_ID: AtomicU64 = AtomicU64::new(0);

/// hang-debug: number of tasks currently blocked waiting for a per-peer healthcheck lock.
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
            // The signature check is cheap and local, so it runs before the networked
            // peer healthcheck; unauthenticated requests must not trigger KDF RPCs.
            let t_sig = Instant::now();
            let sig_verdict = verify_signature_wasm_compat(signed_message, MAX_SIGNATURE_EXP_SECS);
            tracked_log(
                log::Level::Debug,
                remote_addr.ip(),
                &signed_message.address,
                req_uri,
                format!(
                    "hang-debug: [req#{req_id}] signature validation done in {}ms (verdict: {sig_verdict:?})",
                    t_sig.elapsed().as_millis()
                ),
            );

            match &sig_verdict {
                SignatureVerdict::ValidNative => {}
                SignatureVerdict::ValidWasm32Compat => {
                    tracked_log(
                        log::Level::Info,
                        remote_addr.ip(),
                        &signed_message.address,
                        req_uri,
                        "Signature accepted via wasm32 4-byte body_size fallback encoding \
                         (proxy_signature portability bug, issue #30)",
                    );
                }
                SignatureVerdict::Invalid(reason) => {
                    tracked_log(
                        log::Level::Warn,
                        remote_addr.ip(),
                        &signed_message.address,
                        req_uri,
                        format!("Request has invalid signed message ({reason}), returning 401"),
                    );

                    return Err(StatusCode::UNAUTHORIZED);
                }
            }

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

/// Checks whether the peer has been confirmed as connected to the KDF network,
/// asking KDF via RPC on cache misses.
///
/// The `KNOWN_PEERS` cache mutex is only ever held for map lookups/inserts — never
/// across the KDF RPC await. Concurrent healthchecks for the *same* peer are
/// deduplicated through a per-peer mutex, so requests for different peers proceed
/// in parallel and a slow healthcheck only delays the peer that caused it.
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

    /// Peers confirmed as connected to the KDF network, mapped to the moment the
    /// confirmation expires. Plain `HashMap` + `Instant` on purpose: `timed-map` 1.1.0
    /// had an infinite loop in its expiry cleanup that hard-froze this proxy in
    /// production (see issue #30), and this cache is trivial enough to not need a crate.
    static KNOWN_PEERS: LazyLock<Mutex<HashMap<PeerId, Instant>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    /// Per-peer locks serializing concurrent healthchecks of the same peer id.
    static IN_FLIGHT_HEALTHCHECKS: LazyLock<Mutex<HashMap<PeerId, Arc<Mutex<()>>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

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
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Fast path: cache lookup under a short-lived lock.
    if KNOWN_PEERS
        .lock()
        .await
        .get(&peer_id)
        .is_some_and(|&expires_at| expires_at > Instant::now())
    {
        tracked_log(
            log::Level::Debug,
            remote_addr.ip(),
            &signed_message.address,
            req_uri,
            format!("hang-debug: [req#{req_id}] KNOWN_PEERS cache lookup: HIT (skipping KDF RPC)"),
        );
        return Ok(());
    }

    // Cache miss: serialize with other in-flight healthchecks for this peer only.
    let peer_lock = IN_FLIGHT_HEALTHCHECKS
        .lock()
        .await
        .entry(peer_id)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone();

    let waiters = KNOWN_PEERS_LOCK_WAITERS.fetch_add(1, Ordering::SeqCst) + 1;
    tracked_log(
        log::Level::Debug,
        remote_addr.ip(),
        &signed_message.address,
        req_uri,
        format!("hang-debug: [req#{req_id}] cache MISS, waiting for per-peer healthcheck lock (healthcheck waiters incl. this one: {waiters})"),
    );

    let t_lock_wait = Instant::now();
    let result = {
        let _guard = peer_lock.lock().await;
        KNOWN_PEERS_LOCK_WAITERS.fetch_sub(1, Ordering::SeqCst);
        tracked_log(
            log::Level::Debug,
            remote_addr.ip(),
            &signed_message.address,
            req_uri,
            format!(
                "hang-debug: [req#{req_id}] per-peer healthcheck lock ACQUIRED after {}ms wait",
                t_lock_wait.elapsed().as_millis()
            ),
        );

        // Re-check the cache: another request for this peer may have completed the
        // healthcheck while we were waiting for the per-peer lock.
        if KNOWN_PEERS
            .lock()
            .await
            .get(&peer_id)
            .is_some_and(|&expires_at| expires_at > Instant::now())
        {
            tracked_log(
                log::Level::Debug,
                remote_addr.ip(),
                &signed_message.address,
                req_uri,
                format!("hang-debug: [req#{req_id}] KNOWN_PEERS cache lookup after wait: HIT (skipping KDF RPC)"),
            );
            Ok(())
        } else {
            let t_rpc = Instant::now();
            let rpc_result = peer_connection_healthcheck_rpc(cfg, &signed_message.address).await;
            tracked_log(
                log::Level::Debug,
                remote_addr.ip(),
                &signed_message.address,
                req_uri,
                format!(
                    "hang-debug: [req#{req_id}] peer_connection_healthcheck RPC to KDF took {}ms (lock-free), response: {}",
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
                        let mut known_peers = KNOWN_PEERS.lock().await;
                        let now = Instant::now();
                        // Evict stale entries in passing; the map only ever holds peers
                        // seen within the TTL window, so this stays tiny.
                        known_peers.retain(|_, &mut expires_at| expires_at > now);
                        known_peers.insert(peer_id, now + know_peer_expiration);
                        Ok(())
                    } else {
                        tracked_log(
                            log::Level::Warn,
                            remote_addr.ip(),
                            &signed_message.address,
                            req_uri,
                            "Peer isn't connected to KDF network, returning 401",
                        );
                        Err(StatusCode::UNAUTHORIZED)
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
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
    };

    // Drop this peer's in-flight entry unless other requests still hold it
    // (map + our clone = 2 strong refs when nobody else is waiting).
    {
        let mut in_flight = IN_FLIGHT_HEALTHCHECKS.lock().await;
        if Arc::strong_count(&peer_lock) <= 2 {
            in_flight.remove(&peer_id);
        }
    }

    result
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

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Builds a ProxySign the way a wasm32 signer does: the Ed25519 signature is
    /// computed over the encoding where `body_size` (usize) takes 4 bytes.
    fn build_wasm32_style_proxy_sign(
        keypair: &identity::Keypair,
        uri: &str,
        expires_at: i64,
    ) -> ProxySign {
        let sign = ProxySign {
            signature_bytes: vec![],
            address: keypair.public().to_peer_id().to_string(),
            raw_message: proxy_signature::RawMessage {
                uri: uri.to_string(),
                body_size: 0,
                public_key_encoded: keypair.public().encode_protobuf(),
                expires_at,
            },
        };
        let message = encode_raw_message(&sign, BodySizeEncoding::Wasm32_4);
        ProxySign {
            signature_bytes: keypair.sign(&message).unwrap(),
            ..sign
        }
    }

    #[test]
    fn test_verify_signature_native_and_wasm32_compat() {
        let keypair = generate_ed25519_keypair([7; 32]);
        let uri = "https://example.com/gasfree/test";

        // Native signer (the proxy_signature crate itself, 8-byte body_size).
        let native_sign =
            RawMessage::sign(&keypair, &Uri::from_static("https://example.com/gasfree/test"), 0, 5)
                .unwrap();
        assert!(matches!(
            verify_signature_wasm_compat(&native_sign, MAX_SIGNATURE_EXP_SECS),
            SignatureVerdict::ValidNative
        ));

        // wasm32-style signer (4-byte body_size) is accepted via the fallback.
        let wasm_sign = build_wasm32_style_proxy_sign(&keypair, uri, now_secs() + 5);
        assert!(matches!(
            verify_signature_wasm_compat(&wasm_sign, MAX_SIGNATURE_EXP_SECS),
            SignatureVerdict::ValidWasm32Compat
        ));

        // Tampered signature fails both encodings.
        let mut tampered = native_sign.clone();
        tampered.signature_bytes[0] ^= 1;
        assert!(matches!(
            verify_signature_wasm_compat(&tampered, MAX_SIGNATURE_EXP_SECS),
            SignatureVerdict::Invalid(_)
        ));

        // Expired message is rejected before any crypto.
        let expired = build_wasm32_style_proxy_sign(&keypair, uri, now_secs() - 1);
        assert!(matches!(
            verify_signature_wasm_compat(&expired, MAX_SIGNATURE_EXP_SECS),
            SignatureVerdict::Invalid(_)
        ));

        // Signed too far in the future (beyond the 15s window) is rejected.
        let too_long = build_wasm32_style_proxy_sign(&keypair, uri, now_secs() + 300);
        assert!(matches!(
            verify_signature_wasm_compat(&too_long, MAX_SIGNATURE_EXP_SECS),
            SignatureVerdict::Invalid(_)
        ));
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
