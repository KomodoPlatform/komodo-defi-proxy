use crate::address_status::{AddressStatus, AddressStatusOperations};
use crate::ctx::{AppConfig, ProxyRoute};
use crate::db::Db;
use crate::http::{
    insert_jwt_to_http_header, response_by_status, APPLICATION_JSON, X_FORWARDED_FOR,
};
use crate::proxy::remove_hop_by_hop_headers;
use crate::rate_limiter::RateLimitOperations;
use crate::sign::{SignOps, SignedMessage};
use crate::{log_format, GenericResult};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{header, Body, Request, Response, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use std::net::SocketAddr;

pub(crate) async fn proxy_moralis(
    cfg: &AppConfig,
    mut req: Request<Body>,
    remote_addr: &SocketAddr,
    signed_message: SignedMessage,
    x_forwarded_for: HeaderValue,
    proxy_route: &ProxyRoute,
) -> GenericResult<Response<Body>> {
    if proxy_route.authorized {
        if let Err(e) = insert_jwt_to_http_header(cfg, req.headers_mut()).await {
            log::error!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    signed_message.address,
                    req.uri(),
                    "Error inserting JWT into HTTP header: {}, returning 500.",
                    e
                )
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let original_req_uri = req.uri().clone();

    if let Err(e) = modify_request_uri(&mut req, proxy_route) {
        log::error!(
            "{}",
            log_format!(
                remote_addr.ip(),
                signed_message.address,
                original_req_uri,
                "Error modifying request base Uri: {}, returning 500.",
                e
            )
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
            log::warn!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    signed_message.address,
                    original_req_uri,
                    "Couldn't reach {}: {}. Returning 503.",
                    target_uri,
                    e
                )
            );
            return response_by_status(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    Ok(res)
}

/// This function removes the matched inbound route from the request URI and
/// replaces request base URI with the outbound route specified in the proxy route.
fn modify_request_uri(req: &mut Request<Body>, proxy_route: &ProxyRoute) -> GenericResult<()> {
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

pub(crate) async fn validation_middleware_moralis(
    cfg: &AppConfig,
    signed_message: &SignedMessage,
    proxy_route: &ProxyRoute,
    req_uri: &Uri,
    remote_addr: &SocketAddr,
) -> Result<(), StatusCode> {
    let mut db = Db::create_instance(cfg).await;

    match db.read_address_status(&signed_message.address).await {
        AddressStatus::Trusted => Ok(()),
        AddressStatus::Blocked => Err(StatusCode::FORBIDDEN),
        AddressStatus::None => {
            match signed_message.verify_message() {
                Ok(true) => {}
                Ok(false) => {
                    log::warn!(
                        "{}",
                        log_format!(
                            remote_addr.ip(),
                            signed_message.address,
                            req_uri,
                            "Request has invalid signed message, returning 401"
                        )
                    );

                    return Err(StatusCode::UNAUTHORIZED);
                }
                Err(e) => {
                    log::error!(
                        "{}",
                        log_format!(
                            remote_addr.ip(),
                            signed_message.address,
                            req_uri,
                            "verify_message failed in coin {}: {}, returning 500.",
                            signed_message.coin_ticker,
                            e
                        )
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }

            let rate_limiter_key =
                format!("{}:{}", signed_message.coin_ticker, signed_message.address);

            let rate_limiter = proxy_route
                .rate_limiter
                .as_ref()
                .unwrap_or(&cfg.rate_limiter);
            match db.rate_exceeded(&rate_limiter_key, rate_limiter).await {
                Ok(false) => {}
                Ok(true) => {
                    log::warn!(
                        "{}",
                        log_format!(
                            remote_addr.ip(),
                            signed_message.address,
                            req_uri,
                            "Rate exceed for {}, returning 406.",
                            rate_limiter_key,
                        )
                    );
                    return Err(StatusCode::NOT_ACCEPTABLE);
                }
                Err(e) => {
                    log::error!(
                        "{}",
                        log_format!(
                            remote_addr.ip(),
                            signed_message.address,
                            req_uri,
                            "Rate exceeded check failed in coin {}: {}, returning 500.",
                            signed_message.coin_ticker,
                            e
                        )
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }

            if let Err(e) = db.rate_address(rate_limiter_key).await {
                log::error!(
                    "{}",
                    log_format!(
                        remote_addr.ip(),
                        signed_message.address,
                        req_uri,
                        "Rate incrementing failed in coin {}: {}, returning 500.",
                        signed_message.coin_ticker,
                        e
                    )
                );
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            };

            Ok(())
        }
    }
}

#[tokio::test]
async fn test_parse_moralis_payload() {
    use super::{parse_auth_header, X_AUTH_PAYLOAD};
    use hyper::header::HeaderName;
    use hyper::Method;

    let serialized_payload = serde_json::json!({
        "coin_ticker": "BTC",
        "address": "dummy-value",
        "timestamp_message": 1655320000,
        "signature": "dummy-value",
    })
    .to_string();

    let req = Request::builder()
        .method(Method::GET)
        .header(header::ACCEPT, HeaderValue::from_static(APPLICATION_JSON))
        .header(
            X_AUTH_PAYLOAD,
            HeaderValue::from_str(&serialized_payload).unwrap(),
        )
        .body(Body::empty())
        .unwrap();

    let (mut req, payload) = parse_auth_header(req).await.unwrap();

    let body_bytes = hyper::body::to_bytes(req.body_mut()).await.unwrap();
    assert!(
        body_bytes.is_empty(),
        "Body should be empty for GET methods"
    );

    let header_value = req.headers().get(header::ACCEPT).unwrap();

    let expected_payload = SignedMessage {
        coin_ticker: String::from("BTC"),
        address: String::from("dummy-value"),
        timestamp_message: 1655320000,
        signature: String::from("dummy-value"),
    };

    assert_eq!(payload, expected_payload);
    assert_eq!(header_value, APPLICATION_JSON);

    let additional_headers = &[
        header::CONTENT_LENGTH,
        HeaderName::from_bytes(X_AUTH_PAYLOAD.as_bytes()).unwrap(),
    ];
    remove_hop_by_hop_headers(&mut req, additional_headers).unwrap();
}

#[tokio::test]
async fn test_modify_request_uri() {
    use super::ProxyType;
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
