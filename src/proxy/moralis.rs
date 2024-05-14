use crate::address_status::{AddressStatus, AddressStatusOperations};
use crate::ctx::{AppConfig, ProxyRoute};
use crate::db::Db;
use crate::http::{
    insert_jwt_to_http_header, response_by_status, APPLICATION_JSON, X_FORWARDED_FOR,
};
use crate::rate_limiter::RateLimitOperations;
use crate::sign::{SignOps, SignedMessage};
use crate::{log_format, GenericResult};
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::uri::PathAndQuery;
use hyper::{header, Body, Request, Response, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use url::Url;

/// Represents a payload for HTTP GET requests, specifically parsed for the Moralis API within the proxy.
/// This struct contains the destination URL that the proxy will forward the GET request to, ensuring correct service routing.
/// It also includes a `SignedMessage` for authentication and validation, confirming the legitimacy of the request and enhancing security.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct MoralisPayload {
    uri: Url,
    pub(crate) signed_message: SignedMessage,
}

pub(crate) async fn proxy_moralis(
    cfg: &AppConfig,
    mut req: Request<Body>,
    remote_addr: &SocketAddr,
    payload: MoralisPayload,
    x_forwarded_for: HeaderValue,
    proxy_route: &ProxyRoute,
) -> GenericResult<Response<Body>> {
    if proxy_route.authorized {
        if let Err(e) = insert_jwt_to_http_header(cfg, req.headers_mut()).await {
            log::error!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    payload.signed_message.address,
                    req.uri(),
                    "Error inserting JWT into HTTP header: {}, returning 500.",
                    e
                )
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let original_req_uri = req.uri().clone();

    if let Err(e) = modify_request_uri(&mut req, &payload, proxy_route).await {
        log::error!(
            "{}",
            log_format!(
                remote_addr.ip(),
                payload.signed_message.address,
                original_req_uri,
                "Error modifying request Uri: {}, returning 500.",
                e
            )
        );
        return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // drop hop headers
    for key in &[
        header::ACCEPT_ENCODING,
        header::CONNECTION,
        header::HOST,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRANSFER_ENCODING,
        header::TRAILER,
        header::UPGRADE,
        header::CONTENT_LENGTH,
        header::HeaderName::from_static("keep-alive"),
    ] {
        req.headers_mut().remove(key);
    }

    req.headers_mut()
        .insert(HeaderName::from_static(X_FORWARDED_FOR), x_forwarded_for);
    req.headers_mut()
        .insert(header::CONTENT_TYPE, APPLICATION_JSON.parse()?);

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
                    payload.signed_message.address,
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

/// Modifies the URI of an HTTP request by replacing it to outbound URI specified in `ProxyRoute`,
/// while incorporating the path and query parameters from the payload's URI.
async fn modify_request_uri(
    req: &mut Request<Body>,
    payload: &MoralisPayload,
    proxy_route: &ProxyRoute,
) -> GenericResult<()> {
    let mut proxy_outbound_parts = proxy_route.outbound_route.parse::<Uri>()?.into_parts();

    let payload_uri: Uri = payload.uri.as_str().parse()?;

    let path_and_query =
        PathAndQuery::from_str(payload_uri.path_and_query().map_or("/", |pq| pq.as_str()))?;
    // Append the path and query from the payload URI to the proxy outbound URI.
    proxy_outbound_parts.path_and_query = Some(path_and_query);

    // Reconstruct the full URI with the updated parts.
    let new_uri = Uri::from_parts(proxy_outbound_parts)?;

    // Update the request URI.
    *req.uri_mut() = new_uri;
    Ok(())
}

pub(crate) async fn validation_middleware_moralis(
    cfg: &AppConfig,
    payload: &MoralisPayload,
    proxy_route: &ProxyRoute,
    req_uri: &Uri,
    remote_addr: &SocketAddr,
) -> Result<(), StatusCode> {
    let mut db = Db::create_instance(cfg).await;

    match db
        .read_address_status(&payload.signed_message.address)
        .await
    {
        AddressStatus::Trusted => Ok(()),
        AddressStatus::Blocked => Err(StatusCode::FORBIDDEN),
        AddressStatus::None => {
            match payload.signed_message.verify_message() {
                Ok(true) => {}
                Ok(false) => {
                    log::warn!(
                        "{}",
                        log_format!(
                            remote_addr.ip(),
                            payload.signed_message.address,
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
                            payload.signed_message.address,
                            req_uri,
                            "verify_message failed in coin {}: {}, returning 500.",
                            payload.signed_message.coin_ticker,
                            e
                        )
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }

            let rate_limiter_key = format!(
                "{}:{}",
                payload.signed_message.coin_ticker, payload.signed_message.address
            );

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
                            payload.signed_message.address,
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
                            payload.signed_message.address,
                            req_uri,
                            "Rate exceeded check failed in coin {}: {}, returning 500.",
                            payload.signed_message.coin_ticker,
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
                        payload.signed_message.address,
                        req_uri,
                        "Rate incrementing failed in coin {}: {}, returning 500.",
                        payload.signed_message.coin_ticker,
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
    use super::parse_payload;

    let serialized_payload = serde_json::json!({
        "uri": "https://example.com/test-path",
        "signed_message": {
            "coin_ticker": "BTC",
            "address": "dummy-value",
            "timestamp_message": 1655320000,
            "signature": "dummy-value",
         }
    })
    .to_string();

    let mut req = Request::new(Body::from(serialized_payload));
    req.headers_mut().insert(
        HeaderName::from_static("accept"),
        APPLICATION_JSON.parse().unwrap(),
    );

    let (mut req, payload) = parse_payload::<MoralisPayload>(req, true).await.unwrap();

    let body_bytes = hyper::body::to_bytes(req.body_mut()).await.unwrap();
    assert!(
        body_bytes.is_empty(),
        "Body should be empty for GET methods"
    );

    let header_value = req.headers().get("accept").unwrap();

    let expected_payload = MoralisPayload {
        uri: Url::from_str("https://example.com/test-path").unwrap(),
        signed_message: SignedMessage {
            coin_ticker: String::from("BTC"),
            address: String::from("dummy-value"),
            timestamp_message: 1655320000,
            signature: String::from("dummy-value"),
        },
    };

    assert_eq!(payload, expected_payload);
    assert_eq!(header_value, APPLICATION_JSON);
}

#[tokio::test]
async fn test_modify_request_uri() {
    use super::ProxyType;

    let orig_uri_str = "https://proxy.example:3535/test-inbound";
    let mut req = Request::builder()
        .uri(orig_uri_str)
        .body(Body::empty())
        .unwrap();

    let payload = MoralisPayload {
        uri: Url::from_str("https://proxy.example:3535/api/v2/item/0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB/1?chain=eth&format=decimal&normalizeMetadata=true&media_items=false").unwrap(),
        signed_message: SignedMessage {
            coin_ticker: String::from("BTC"),
            address: String::from("dummy-value"),
            timestamp_message: 1655320000,
            signature: String::from("dummy-value"),
        },
    };

    let proxy_route = ProxyRoute {
        inbound_route: String::from_str("/test-inbound").unwrap(),
        outbound_route: "http://localhost:8000".to_string(),
        proxy_type: ProxyType::Moralis,
        authorized: false,
        allowed_methods: vec![],
        rate_limiter: None,
    };

    modify_request_uri(&mut req, &payload, &proxy_route)
        .await
        .unwrap();

    assert_eq!(
        req.uri(),
        "http://localhost:8000/api/v2/item/0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB/1?chain=eth&format=decimal&normalizeMetadata=true&media_items=false"
    );
}
