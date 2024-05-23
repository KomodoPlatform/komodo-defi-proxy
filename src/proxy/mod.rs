use crate::ctx::{AppConfig, GenericResult, ProxyRoute};
use crate::sign::SignedMessage;
use hyper::header;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Body, Request, Response, StatusCode, Uri};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
mod moralis;
use moralis::{proxy_moralis, validation_middleware_moralis};
mod quicknode;
pub(crate) use quicknode::{proxy_quicknode, validation_middleware_quicknode, QuicknodePayload};

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
}

/// Represents the types of payloads that can be processed by the proxy, with each variant tailored to a specific proxy type.
/// This helps in managing the logic for routing and processing requests appropriately within the proxy layer.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PayloadData {
    Quicknode(QuicknodePayload),
    /// Moralis feature requires only Signed Message in X-Auth-Payload header
    Moralis(SignedMessage),
}

impl PayloadData {
    /// Returns a reference to the `SignedMessage` contained within the payload.
    pub(crate) fn signed_message(&self) -> &SignedMessage {
        match self {
            PayloadData::Quicknode(payload) => &payload.signed_message,
            PayloadData::Moralis(payload) => payload,
        }
    }
}

/// Asynchronously generates and organizes payload data from an HTTP request based on the specified proxy type.
/// This function ensures that requests are properly formatted to the correct service,
/// returning a tuple with the modified request and the structured payload.
pub(crate) async fn generate_payload_from_req(
    req: Request<Body>,
    proxy_type: &ProxyType,
) -> GenericResult<(Request<Body>, PayloadData)> {
    match proxy_type {
        ProxyType::Quicknode => {
            let (req, payload) = parse_body_payload::<QuicknodePayload>(req).await?;
            Ok((req, PayloadData::Quicknode(payload)))
        }
        ProxyType::Moralis => {
            let (req, payload) = parse_header_payload::<SignedMessage>(req).await?;
            Ok((req, PayloadData::Moralis(payload)))
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
        PayloadData::Quicknode(payload) => {
            proxy_quicknode(cfg, req, remote_addr, payload, x_forwarded_for, proxy_route).await
        }
        PayloadData::Moralis(payload) => {
            proxy_moralis(cfg, req, remote_addr, payload, x_forwarded_for, proxy_route).await
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
        PayloadData::Quicknode(payload) => {
            validation_middleware_quicknode(cfg, payload, proxy_route, req_uri, remote_addr).await
        }
        PayloadData::Moralis(payload) => {
            validation_middleware_moralis(cfg, payload, proxy_route, req_uri, remote_addr).await
        }
    }
}

/// Asynchronously parses an HTTP request's body into a specified type `T`. If the request method is `GET`,
/// the function modifies the request to have an empty body. For other methods, it retains the original body.
/// The function ensures that the body is not empty before attempting deserialization into the non-optional type `T`.
async fn parse_body_payload<T>(req: Request<Body>) -> GenericResult<(Request<Body>, T)>
where
    T: DeserializeOwned,
{
    let (parts, body) = req.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await?;
    if body_bytes.is_empty() {
        return Err("Empty body cannot be deserialized into non-optional type T".into());
    }
    let payload: T = serde_json::from_slice(&body_bytes)?;
    let new_req = Request::from_parts(parts, Body::from(body_bytes));
    Ok((new_req, payload))
}

async fn parse_header_payload<T>(req: Request<Body>) -> GenericResult<(Request<Body>, T)>
where
    T: DeserializeOwned,
{
    let (parts, body) = req.into_parts();
    let header_value = parts
        .headers
        .get(X_AUTH_PAYLOAD)
        .ok_or("Missing X-Auth-Payload header")?
        .to_str()?;
    let payload: T = serde_json::from_str(header_value)?;
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
    ];

    // Extend with additional headers to remove
    headers_to_remove.extend_from_slice(additional_headers_to_remove);

    // Remove headers
    for key in &headers_to_remove {
        req.headers_mut().remove(key);
    }

    Ok(())
}
