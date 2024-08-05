use crate::address_status::{get_address_status_list, post_address_status};
use crate::ctx::{AppConfig, GenericResult, ProxyRoute};
use crate::jwt::{get_cached_token_or_generate_one, JwtClaims};
use crate::logger::tracked_log;
use crate::rpc::RpcPayload;
use crate::server::is_private_ip;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{header, HeaderMap, Method};
use hyper::{Body, Request, Response, StatusCode, Uri};
use proxy_signature::ProxySign;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;

pub(crate) mod http;
pub(crate) mod websocket;

pub(crate) const APPLICATION_JSON: &str = "application/json";
pub(crate) const X_FORWARDED_FOR: &str = "x-forwarded-for";

const X_AUTH_PAYLOAD: &str = "X-Auth-Payload";
const KEEP_ALIVE: &str = "keep-alive";

/// Enumerates different proxy types supported by the application, focusing on separating feature logic.
/// This allows for differentiated handling based on what the proxy should do with the request,
/// directing each to the appropriate service or API based on its designated proxy type.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProxyType {
    Quicknode,
    Moralis,
    BlockPi,
}

/// Represents the types of payloads that can be processed by the proxy, with each variant tailored to a specific proxy type.
/// This helps in managing the logic for routing and processing requests appropriately within the proxy layer.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PayloadData {
    /// Quicknode feature requires body payload and Signed Message in X-Auth-Payload header
    Quicknode {
        payload: RpcPayload,
        proxy_sign: ProxySign,
    },
    /// Moralis feature requires only Signed Message in X-Auth-Payload header and doesn't have body
    Moralis(ProxySign),
    /// BlockPi feature requires body payload and Signed Message in X-Auth-Payload header
    BlockPi {
        payload: RpcPayload,
        proxy_sign: ProxySign,
    },
}

impl PayloadData {
    /// Returns a reference to the `ProxySign` contained within the payload.
    pub(crate) fn proxy_sign(&self) -> &ProxySign {
        match self {
            PayloadData::Quicknode { proxy_sign, .. } => proxy_sign,
            PayloadData::Moralis(proxy_sign) => proxy_sign,
            PayloadData::BlockPi { proxy_sign, .. } => proxy_sign,
        }
    }
}

/// Asynchronously generates and organizes payload data from an HTTP request based on the specified proxy type.
/// This function ensures that requests are properly formatted to the correct service,
/// returning a tuple with the request and the structured payload.
pub(crate) async fn generate_payload_from_req(
    req: Request<Body>,
    proxy_type: &ProxyType,
) -> GenericResult<(Request<Body>, PayloadData)> {
    match proxy_type {
        ProxyType::Quicknode => {
            let (req, payload, proxy_sign) = parse_body_and_auth_header::<RpcPayload>(req).await?;
            let payload_data = PayloadData::Quicknode {
                payload,
                proxy_sign,
            };
            Ok((req, payload_data))
        }
        ProxyType::Moralis => {
            let (req, proxy_sign) = parse_auth_header(req).await?;
            Ok((req, PayloadData::Moralis(proxy_sign)))
        }
        ProxyType::BlockPi => {
            let (req, payload, proxy_sign) = parse_body_and_auth_header::<RpcPayload>(req).await?;
            let payload_data = PayloadData::BlockPi {
                payload,
                proxy_sign,
            };
            Ok((req, payload_data))
        }
    }
}

pub(crate) async fn proxy(
    cfg: &AppConfig,
    req: Request<Body>,
    remote_addr: &SocketAddr,
    payload: PayloadData,
    x_forwarded_for: HeaderValue,
    proxy_route: &ProxyRoute,
) -> GenericResult<Response<Body>> {
    match payload {
        PayloadData::Quicknode {
            payload,
            proxy_sign,
        } => {
            http::post::proxy(
                cfg,
                req,
                remote_addr,
                payload,
                proxy_sign,
                x_forwarded_for,
                proxy_route,
            )
            .await
        }
        PayloadData::Moralis(proxy_sign) => {
            http::get::proxy(
                cfg,
                req,
                remote_addr,
                proxy_sign,
                x_forwarded_for,
                proxy_route,
            )
            .await
        }
        PayloadData::BlockPi {
            payload,
            proxy_sign,
        } => {
            http::post::proxy(
                cfg,
                req,
                remote_addr,
                payload,
                proxy_sign,
                x_forwarded_for,
                proxy_route,
            )
            .await
        }
    }
}

pub(crate) async fn validation_middleware(
    cfg: &AppConfig,
    payload: &PayloadData,
    proxy_route: &ProxyRoute,
    req_uri: &Uri,
    remote_addr: &SocketAddr,
) -> Result<(), StatusCode> {
    let proxy_sign = payload.proxy_sign();
    http::validation_middleware(cfg, proxy_sign, proxy_route, req_uri, remote_addr).await
}

/// Parses the request body and the `X-Auth-Payload` header into a payload and signed message.
///
/// This function extracts the `X-Auth-Payload` header from the request, parses it into a `SignedMessage`,
/// and then reads and deserializes the request body into a specified type `T`.
/// If the body is empty or the header is missing, an error is returned.
async fn parse_body_and_auth_header<T>(
    req: Request<Body>,
) -> GenericResult<(Request<Body>, T, ProxySign)>
where
    T: DeserializeOwned,
{
    let (parts, body) = req.into_parts();
    let header_value = parts
        .headers
        .get(X_AUTH_PAYLOAD)
        .ok_or("Missing X-Auth-Payload header")?
        .to_str()?;
    let proxy_sign: ProxySign = serde_json::from_str(header_value)?;
    let body_bytes = hyper::body::to_bytes(body).await?;
    if body_bytes.is_empty() {
        return Err("Empty body cannot be deserialized into non-optional type T".into());
    }
    let payload: T = serde_json::from_slice(&body_bytes)?;
    let new_req = Request::from_parts(parts, Body::from(body_bytes));
    Ok((new_req, payload, proxy_sign))
}

/// Parses [ProxySign] value from X-Auth-Payload header
async fn parse_auth_header(req: Request<Body>) -> GenericResult<(Request<Body>, ProxySign)> {
    let (parts, body) = req.into_parts();
    let header_value = parts
        .headers
        .get(X_AUTH_PAYLOAD)
        .ok_or("Missing X-Auth-Payload header")?
        .to_str()?;
    let payload: ProxySign = serde_json::from_str(header_value)?;
    let new_req = Request::from_parts(parts, body);
    Ok((new_req, payload))
}

fn remove_hop_by_hop_headers(
    req: &mut Request<hyper::Body>,
    additional_headers_to_remove: &[HeaderName],
) -> GenericResult<()> {
    // List of common hop headers to be removed
    let mut headers_to_remove = vec![
        header::ACCEPT_ENCODING,
        header::CONNECTION,
        header::HOST,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRANSFER_ENCODING,
        header::TRAILER,
        header::UPGRADE,
        HeaderName::from_static(KEEP_ALIVE),
        HeaderName::from_bytes(X_AUTH_PAYLOAD.as_bytes())?,
    ];

    // Extend with additional headers to remove
    headers_to_remove.extend_from_slice(additional_headers_to_remove);

    // Remove headers
    for key in &headers_to_remove {
        req.headers_mut().remove(key);
    }

    Ok(())
}

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

pub(crate) async fn http_handler(
    cfg: &AppConfig,
    mut req: Request<Body>,
    remote_addr: SocketAddr,
) -> GenericResult<Response<Body>> {
    let req_uri = req.uri().clone();

    let is_private_ip = is_private_ip(&remote_addr.ip());

    if is_private_ip {
        tracked_log(
            log::Level::Info,
            remote_addr.ip(),
            "**not-available**",
            req.uri(),
            "Request received from the same network. Security middlewares will be by-passed.",
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

    let proxy_route = match req.method() {
        &Method::GET => match cfg.get_proxy_route_by_uri(req.uri_mut()) {
            Some(proxy_route) => proxy_route,
            None => {
                tracked_log(
                    log::Level::Warn,
                    remote_addr.ip(),
                    "**not-available**",
                    req_uri,
                    "Proxy route not found for GET request, returning 404.",
                );

                return response_by_status(StatusCode::NOT_FOUND);
            }
        },
        _ => match cfg.get_proxy_route_by_inbound(req.uri().path()) {
            Some(proxy_route) => proxy_route,
            None => {
                tracked_log(
                    log::Level::Warn,
                    remote_addr.ip(),
                    "**not-available**",
                    req_uri,
                    "Proxy route not found for non-GET request, returning 404.",
                );
                return response_by_status(StatusCode::NOT_FOUND);
            }
        },
    };

    let (req, payload) = match generate_payload_from_req(req, &proxy_route.proxy_type).await {
        Ok(t) => t,
        Err(e) => {
            tracked_log(
                log::Level::Warn,
                remote_addr.ip(),
                "**not-available**",
                req_uri,
                format!("Received invalid http payload: {e}, returning 401."),
            );
            return response_by_status(StatusCode::UNAUTHORIZED);
        }
    };

    tracked_log(
        log::Level::Info,
        remote_addr.ip(),
        &payload.proxy_sign().address,
        &req_uri,
        "Request and payload data received.",
    );

    let x_forwarded_for: HeaderValue = match remote_addr.ip().to_string().parse() {
        Ok(t) => t,
        Err(_) => {
            tracked_log(
                log::Level::Error,
                remote_addr.ip(),
                &payload.proxy_sign().address,
                &req_uri,
                "Error type casting of IpAddr into HeaderValue, returning 500.",
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
