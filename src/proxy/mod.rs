use crate::ctx::{AppConfig, GenericResult, ProxyRoute};
use crate::rpc::RpcPayload;
use hyper::header;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Body, Request, Response, StatusCode, Uri};
use proxy_signature::ProxySign;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub(crate) mod http;
pub(crate) mod websocket;

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
    Cosmos,
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
    /// Cosmos feature requires body payload and Signed Message in X-Auth-Payload header
    Cosmos {
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
            PayloadData::Cosmos { proxy_sign, .. } => proxy_sign,
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
        ProxyType::Cosmos => {
            let (req, payload, proxy_sign) = parse_body_and_auth_header::<RpcPayload>(req).await?;
            let payload_data = PayloadData::Cosmos {
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
        PayloadData::Cosmos {
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
    match payload {
        PayloadData::Quicknode { proxy_sign, .. } => {
            http::post::validation_middleware(cfg, proxy_sign, proxy_route, req_uri, remote_addr)
                .await
        }
        PayloadData::Moralis(proxy_sign) => {
            http::get::validation_middleware(cfg, proxy_sign, proxy_route, req_uri, remote_addr)
                .await
        }
        PayloadData::Cosmos { proxy_sign, .. } => {
            http::post::validation_middleware(cfg, proxy_sign, proxy_route, req_uri, remote_addr)
                .await
        }
    }
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
    println!("HEADER VALUE {:?}", header_value);
    let proxy_sign: ProxySign = serde_json::from_str(header_value)?;
    println!("HEADER VALUE {:?}", header_value);
    let body_bytes = hyper::body::to_bytes(body).await?;
    if body_bytes.is_empty() {
        return Err("Empty body cannot be deserialized into non-optional type T".into());
    }
    let payload: serde_json::Value = serde_json::from_slice(&body_bytes)?;
    println!("AAAAAAAAAAA {:?}", payload);
    let payload: T = serde_json::from_slice(&body_bytes)?;
    println!("AAAAAAAAAAAAAAAAAAAAAAAA");
    let new_req = Request::from_parts(parts, Body::from(body_bytes));
    println!("WOOOOOOOOOOOOOOO");
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
