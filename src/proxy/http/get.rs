use crate::ctx::{AppConfig, ProxyRoute};
use crate::logger::tracked_log;
use crate::proxy::{
    insert_jwt_to_http_header, remove_hop_by_hop_headers, response_by_status, APPLICATION_JSON,
    X_FORWARDED_FOR,
};
use crate::GenericResult;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{header, Body, Request, Response, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use proxy_signature::ProxySign;
use std::net::SocketAddr;

pub(crate) async fn proxy(
    cfg: &AppConfig,
    mut req: Request<Body>,
    remote_addr: &SocketAddr,
    signed_message: ProxySign,
    x_forwarded_for: HeaderValue,
    proxy_route: &ProxyRoute,
) -> GenericResult<Response<Body>> {
    if proxy_route.authorized {
        if let Err(e) = insert_jwt_to_http_header(cfg, req.headers_mut()).await {
            tracked_log(
                log::Level::Error,
                remote_addr.ip(),
                signed_message.address,
                req.uri(),
                format!(
                    "Error inserting JWT into HTTP header: {}, returning 500.",
                    e
                ),
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let original_req_uri = req.uri().clone();

    if let Err(e) = modify_request_uri(&mut req, proxy_route) {
        tracked_log(
            log::Level::Error,
            remote_addr.ip(),
            signed_message.address,
            original_req_uri,
            format!("Error modifying request base Uri: {}, returning 500.", e),
        );
        return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    remove_hop_by_hop_headers(&mut req, &[header::CONTENT_LENGTH])?;

    req.headers_mut()
        .insert(HeaderName::from_static(X_FORWARDED_FOR), x_forwarded_for);
    req.headers_mut()
        .insert(header::ACCEPT, APPLICATION_JSON.parse()?);

    let https = HttpsConnector::new();
    let client = hyper::Client::builder().build(https);

    let target_uri = req.uri().clone();
    let res = match client.request(req).await {
        Ok(t) => t,
        Err(e) => {
            tracked_log(
                log::Level::Warn,
                remote_addr.ip(),
                signed_message.address,
                original_req_uri,
                format!("Couldn't reach {}: {}. Returning 503.", target_uri, e),
            );
            return response_by_status(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    Ok(res)
}

/// This function removes the matched inbound route from the request URI and
/// replaces request base URI with the outbound route specified in the proxy route.
pub(crate) fn modify_request_uri(
    req: &mut Request<Body>,
    proxy_route: &ProxyRoute,
) -> GenericResult<()> {
    let proxy_base_uri = proxy_route.outbound_route.parse::<Uri>()?;
    let original_uri = req.uri();

    let original_path_and_query = original_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("");
    // Remove the "inbound_route" part from the original path and query
    let remaining_path_and_query = if proxy_route.inbound_route == "/" {
        original_path_and_query
    } else {
        original_path_and_query
            .strip_prefix(&proxy_route.inbound_route)
            .ok_or("Route doesn't match with the given inbound URL.")?
    };

    let mut base_uri_parts = proxy_base_uri.into_parts();
    base_uri_parts.path_and_query = Some(remaining_path_and_query.parse()?);
    let new_uri = Uri::from_parts(base_uri_parts)?;
    *req.uri_mut() = new_uri;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::proxy::X_AUTH_PAYLOAD;

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
