use std::net::SocketAddr;
use std::str::FromStr;

use address_status::{get_address_status_list, post_address_status};
use ctx::{AppConfig, ProxyRoute, ProxyType};
use hyper::header::HeaderName;
use hyper::http::uri::PathAndQuery;
use hyper::{
    header::{self, HeaderValue},
    Body, HeaderMap, Method, Request, Response, StatusCode, Uri,
};
use hyper_tls::HttpsConnector;
use jwt::{get_cached_token_or_generate_one, JwtClaims};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sign::SignedMessage;
use url::Url;

use super::*;
use crate::server::{is_private_ip, validation_middleware};

/// Value
pub(crate) const APPLICATION_JSON: &str = "application/json";
/// Header
pub(crate) const X_FORWARDED_FOR: &str = "x-forwarded-for";
async fn get_healthcheck() -> GenericResult<Response<Body>> {
    let json = json!({
        "health": "ok",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        .header(header::CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(json.to_string()))?)
}

fn handle_preflight() -> GenericResult<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        .body(Body::from(Vec::new()))?)
}

pub(crate) fn response_by_status(status: StatusCode) -> GenericResult<Response<Body>> {
    Ok(Response::builder()
        .status(status)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        .body(Body::from(Vec::new()))?)
}

pub(crate) async fn insert_jwt_to_http_header(
    cfg: &AppConfig,
    headers: &mut HeaderMap<HeaderValue>,
) -> GenericResult<()> {
    let claims = &JwtClaims::new(cfg.token_expiration_time());
    let auth_token = get_cached_token_or_generate_one(cfg, claims).await?;
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", auth_token).parse()?,
    );

    Ok(())
}

/// Asynchronously parses an HTTP request's body into a specified type `T`. If the request method is `GET`,
/// the function modifies the request to have an empty body. For other methods, it retains the original body.
/// The function ensures that the body is not empty before attempting deserialization into the non-optional type `T`.
async fn parse_payload<T>(req: Request<Body>, get_req: bool) -> GenericResult<(Request<Body>, T)>
where
    T: serde::de::DeserializeOwned,
{
    let (mut parts, body) = req.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await?;

    if body_bytes.is_empty() {
        return Err("Empty body cannot be deserialized into non-optional type T".into());
    }

    let payload: T = serde_json::from_slice(&body_bytes)?;

    let new_req = if get_req {
        parts.method = Method::GET;
        Request::from_parts(parts, Body::empty())
    } else {
        Request::from_parts(parts, Body::from(body_bytes))
    };

    Ok((new_req, payload))
}

/// Represents a JSON-RPC Call payload parsed from a proxy request. It combines standard JSON RPC method call
/// fields with a `SignedMessage` for authentication and validation by the proxy.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct JsonRpcPayload {
    pub(crate) method: String,
    pub(crate) params: serde_json::value::Value,
    pub(crate) id: usize,
    pub(crate) jsonrpc: String,
    pub(crate) signed_message: SignedMessage,
}

/// Represents a payload for HTTP GET request parsed from a proxy request. This struct contains the URL
/// that the proxy will forward the GET request to, along with a `SignedMessage` for authentication and validation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct HttpGetPayload {
    uri: Url,
    pub(crate) signed_message: SignedMessage,
}

/// Enumerates the types of payloads that can be processed by the proxy.
/// Each variant holds a specific payload type relevant to the proxy operation being performed.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PayloadData {
    JsonRpc(JsonRpcPayload),
    HttpGet(HttpGetPayload),
}

impl PayloadData {
    /// Returns a reference to the `SignedMessage` contained within the payload.
    fn signed_message(&self) -> &SignedMessage {
        match self {
            PayloadData::JsonRpc(json_rpc_payload) => &json_rpc_payload.signed_message,
            PayloadData::HttpGet(http_get_payload) => &http_get_payload.signed_message,
        }
    }
}

/// Asynchronously generates and parses payload data from an HTTP request based on the specified proxy type.
/// Returns a tuple containing the modified (if necessary) request and the parsed payload from req Body as `PayloadData`.
async fn generate_payload_from_req(
    req: Request<Body>,
    proxy_type: &ProxyType,
) -> GenericResult<(Request<Body>, PayloadData)> {
    match proxy_type {
        ProxyType::JsonRpc => {
            let (req, payload) = parse_payload::<JsonRpcPayload>(req, false).await?;
            Ok((req, PayloadData::JsonRpc(payload)))
        }
        ProxyType::HttpGet => {
            let (req, payload) = parse_payload::<HttpGetPayload>(req, true).await?;
            Ok((req, PayloadData::HttpGet(payload)))
        }
    }
}

async fn proxy(
    cfg: &AppConfig,
    req: Request<Body>,
    remote_addr: &SocketAddr,
    payload: PayloadData,
    x_forwarded_for: HeaderValue,
    proxy_route: &ProxyRoute,
) -> GenericResult<Response<Body>> {
    match payload {
        PayloadData::JsonRpc(payload) => {
            proxy_json_rpc(cfg, req, remote_addr, payload, x_forwarded_for, proxy_route).await
        }
        PayloadData::HttpGet(payload) => {
            proxy_http_get(cfg, req, remote_addr, payload, x_forwarded_for, proxy_route).await
        }
    }
}

async fn proxy_json_rpc(
    cfg: &AppConfig,
    mut req: Request<Body>,
    remote_addr: &SocketAddr,
    payload: JsonRpcPayload,
    x_forwarded_for: HeaderValue,
    proxy_route: &ProxyRoute,
) -> GenericResult<Response<Body>> {
    // check if requested method allowed
    if !proxy_route.allowed_methods.contains(&payload.method) {
        log::warn!(
            "{}",
            log_format!(
                remote_addr.ip(),
                payload.signed_message.address,
                req.uri(),
                "Method {} not allowed for, returning 403.",
                payload.method
            )
        );
        return response_by_status(StatusCode::FORBIDDEN);
    }

    if proxy_route.authorized {
        // modify outgoing request
        if insert_jwt_to_http_header(cfg, req.headers_mut())
            .await
            .is_err()
        {
            log::error!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    payload.signed_message.address,
                    req.uri(),
                    "Error inserting JWT into http header, returning 500."
                )
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let original_req_uri = req.uri().clone();
    *req.uri_mut() = match proxy_route.outbound_route.parse() {
        Ok(uri) => uri,
        Err(e) => {
            log::error!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    payload.signed_message.address,
                    original_req_uri,
                    "Error type casting value of {} into Uri: {}, returning 500.",
                    proxy_route.outbound_route,
                    e
                )
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

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

async fn proxy_http_get(
    cfg: &AppConfig,
    mut req: Request<Body>,
    remote_addr: &SocketAddr,
    payload: HttpGetPayload,
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
    payload: &HttpGetPayload,
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

pub(crate) async fn http_handler(
    cfg: &AppConfig,
    req: Request<Body>,
    remote_addr: SocketAddr,
) -> GenericResult<Response<Body>> {
    let req_uri = req.uri().clone();

    let is_private_ip = is_private_ip(&remote_addr.ip());

    if is_private_ip {
        log::info!(
            "{}",
            log_format!(
                remote_addr.ip(),
                String::from("-"),
                req.uri(),
                "Request received from the same network. Security middlewares will be by-passed."
            )
        );

        match (req.method(), req_uri.path()) {
            (&Method::GET, "/") => return get_healthcheck().await,
            (&Method::GET, "/address-status") => return get_address_status_list(cfg).await,
            (&Method::POST, "/address-status") => return post_address_status(cfg, req).await,
            _ => {}
        };
    };

    if req.method() == Method::OPTIONS {
        return handle_preflight();
    }

    // create proxy_route before payload, as we need proxy_type from it for payload generation
    let proxy_route = match cfg.get_proxy_route_by_inbound(req.uri().path().to_string()) {
        Some(proxy_route) => proxy_route,
        None => {
            log::warn!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    String::from("-"),
                    req.uri(),
                    "Proxy route not found, returning 404."
                )
            );
            return response_by_status(StatusCode::NOT_FOUND);
        }
    };

    let (req, payload) = match generate_payload_from_req(req, &proxy_route.proxy_type).await {
        Ok(t) => t,
        Err(_) => {
            log::warn!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    String::from("-"),
                    req_uri,
                    "Received invalid http payload, returning 401."
                )
            );
            return response_by_status(StatusCode::UNAUTHORIZED);
        }
    };

    log::info!(
        "{}",
        log_format!(
            remote_addr.ip(),
            payload.signed_message().address,
            req_uri,
            "Request and payload data received."
        )
    );

    let x_forwarded_for: HeaderValue = match remote_addr.ip().to_string().parse() {
        Ok(t) => t,
        Err(_) => {
            log::error!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    payload.signed_message().address,
                    req_uri,
                    "Error type casting of IpAddr into HeaderValue, returning 500."
                )
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if is_private_ip {
        return proxy(
            cfg,
            req,
            &remote_addr,
            payload,
            x_forwarded_for,
            proxy_route,
        )
        .await;
    }

    if let Err(status_code) =
        validation_middleware(cfg, &payload, proxy_route, req.uri(), &remote_addr).await
    {
        return response_by_status(status_code);
    }

    proxy(
        cfg,
        req,
        &remote_addr,
        payload,
        x_forwarded_for,
        proxy_route,
    )
    .await
}

#[test]
fn test_rpc_payload_serialzation_and_deserialization() {
    let json_payload = json!({
        "method": "dummy-value",
        "params": [],
        "id": 1,
        "jsonrpc": "2.0",
        "signed_message": {
            "coin_ticker": "ETH",
            "address": "dummy-value",
            "timestamp_message": 1655319963,
            "signature": "dummy-value",
         }
    });

    let actual_payload: JsonRpcPayload = serde_json::from_str(&json_payload.to_string()).unwrap();

    let expected_payload = JsonRpcPayload {
        method: String::from("dummy-value"),
        params: json!([]),
        id: 1,
        jsonrpc: String::from("2.0"),
        signed_message: SignedMessage {
            coin_ticker: String::from("ETH"),
            address: String::from("dummy-value"),
            timestamp_message: 1655319963,
            signature: String::from("dummy-value"),
        },
    };

    assert_eq!(actual_payload, expected_payload);

    // Backwards
    let json = serde_json::to_value(expected_payload).unwrap();
    assert_eq!(json_payload, json);
    assert_eq!(json_payload.to_string(), json.to_string());
}

#[test]
fn test_get_proxy_route_by_inbound() {
    use std::str::FromStr;

    let cfg = ctx::get_app_config_test_instance();

    // If we leave this code line `let proxy_route = match cfg.get_proxy_route_by_inbound(req.uri().to_string()) {`
    // inbound_route cant be "/test", as it's not uri. I suppose inbound actually should be a Path.
    // Two options: in `req.uri().to_string()` path() is missing or "/test" in test is wrong and the whole url should be.
    let proxy_route = cfg
        .get_proxy_route_by_inbound(String::from("/test"))
        .unwrap();

    assert_eq!(proxy_route.outbound_route, "https://komodoplatform.com");

    let proxy_route = cfg
        .get_proxy_route_by_inbound(String::from("/test-2"))
        .unwrap();

    assert_eq!(proxy_route.outbound_route, "https://atomicdex.io");

    let url = Uri::from_str("https://komodo.proxy:5535/nft-test").unwrap();
    let path = url.path().to_string();
    let proxy_route = cfg.get_proxy_route_by_inbound(path).unwrap();
    assert_eq!(proxy_route.outbound_route, "https://nft.proxy");
}

#[test]
fn test_respond_by_status() {
    let all_supported_status_codes = [
        100, 101, 102, 200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302, 303, 304,
        305, 307, 308, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414,
        415, 416, 417, 418, 421, 422, 423, 424, 426, 428, 429, 431, 451, 500, 501, 502, 503, 504,
        505, 506, 507, 508, 510, 511,
    ];

    for status_code in all_supported_status_codes {
        let status_type = StatusCode::from_u16(status_code).unwrap();
        let res = response_by_status(status_type).unwrap();
        assert_eq!(res.status(), status_type);
    }
}

#[tokio::test]
async fn test_parse_json_rpc_payload() {
    let serialized_payload = json!({
        "method": "dummy-value",
        "params": [],
        "id": 1,
        "jsonrpc": "2.0",
        "signed_message": {
            "coin_ticker": "ETH",
            "address": "dummy-value",
            "timestamp_message": 1655319963,
            "signature": "dummy-value",
         }
    })
    .to_string();

    let mut req = Request::builder()
        .method(Method::POST)
        .body(Body::from(serialized_payload))
        .unwrap();
    req.headers_mut().insert(
        HeaderName::from_static("dummy-header"),
        "dummy-value".parse().unwrap(),
    );

    let (mut req, payload): (Request<Body>, JsonRpcPayload) =
        parse_payload(req, false).await.unwrap();

    let body_bytes = hyper::body::to_bytes(req.body_mut()).await.unwrap();
    assert!(
        !body_bytes.is_empty(),
        "Body should not be empty for non-GET methods"
    );

    let header_value = req.headers().get("dummy-header").unwrap();

    let expected_payload = JsonRpcPayload {
        method: String::from("dummy-value"),
        params: json!([]),
        id: 1,
        jsonrpc: String::from("2.0"),
        signed_message: SignedMessage {
            coin_ticker: String::from("ETH"),
            address: String::from("dummy-value"),
            timestamp_message: 1655319963,
            signature: String::from("dummy-value"),
        },
    };

    assert_eq!(payload, expected_payload);
    assert_eq!(header_value, "dummy-value");
}

#[tokio::test]
async fn test_parse_http_get_payload() {
    let serialized_payload = json!({
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

    let (mut req, payload): (Request<Body>, HttpGetPayload) =
        parse_payload(req, true).await.unwrap();

    let body_bytes = hyper::body::to_bytes(req.body_mut()).await.unwrap();
    assert!(
        body_bytes.is_empty(),
        "Body should be empty for GET methods"
    );

    let header_value = req.headers().get("accept").unwrap();

    let expected_payload = HttpGetPayload {
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
    let orig_uri_str = "https://proxy.example:3535/test-inbound";
    let mut req = Request::builder()
        .uri(orig_uri_str)
        .body(Body::empty())
        .unwrap();

    let payload = HttpGetPayload {
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
        proxy_type: ProxyType::HttpGet,
        authorized: false,
        allowed_methods: vec![],
    };

    modify_request_uri(&mut req, &payload, &proxy_route)
        .await
        .unwrap();

    assert_eq!(
        req.uri(),
        "http://localhost:8000/api/v2/item/0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB/1?chain=eth&format=decimal&normalizeMetadata=true&media_items=false"
    );
}
