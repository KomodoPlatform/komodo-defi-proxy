use crate::address_status::{AddressStatus, AddressStatusOperations};
use crate::ctx::{AppConfig, ProxyRoute};
use crate::db::Db;
use crate::http::{
    insert_jwt_to_http_header, response_by_status, APPLICATION_JSON, X_FORWARDED_FOR,
};
use crate::proxy::remove_hop_by_hop_headers;
use crate::rate_limiter::RateLimitOperations;
use crate::{log_format, GenericResult};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{header, Body, Request, Response, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use proxy_signature::ProxySign;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Represents a payload for JSON-RPC calls, tailored for the Quicknode API within the proxy.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct QuicknodePayload {
    pub(crate) method: String,
    pub(crate) params: serde_json::value::Value,
    pub(crate) id: usize,
    pub(crate) jsonrpc: String,
}

/// Used for websocket connection.
/// It combines standard JSON RPC method call fields (method, params, id, jsonrpc) with a `SignedMessage`
/// for authentication and validation, facilitating secure and validated interactions with the Quicknode service.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct QuicknodeSocketPayload {
    pub(crate) method: String,
    pub(crate) params: serde_json::value::Value,
    pub(crate) id: usize,
    pub(crate) jsonrpc: String,
    pub(crate) signed_message: ProxySign,
}

impl QuicknodeSocketPayload {
    pub(crate) fn into_parts(self) -> (QuicknodePayload, ProxySign) {
        let payload = QuicknodePayload {
            method: self.method,
            params: self.params,
            id: self.id,
            jsonrpc: self.jsonrpc,
        };
        let signed_message = self.signed_message;
        (payload, signed_message)
    }
}

#[derive(Debug)]
enum ProofOfFundingError {
    InvalidSignedMessage,
    InsufficientBalance,
    ErrorFromRpcCall,
    #[allow(dead_code)]
    RpcCallFailed(String),
}

pub(crate) async fn proxy_quicknode(
    cfg: &AppConfig,
    mut req: Request<Body>,
    remote_addr: &SocketAddr,
    payload: QuicknodePayload,
    signed_message: ProxySign,
    x_forwarded_for: HeaderValue,
    proxy_route: &ProxyRoute,
) -> GenericResult<Response<Body>> {
    // check if requested method allowed
    if !proxy_route.allowed_rpc_methods.contains(&payload.method) {
        log::warn!(
            "{}",
            log_format!(
                remote_addr.ip(),
                signed_message.address,
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
                    signed_message.address,
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
                    signed_message.address,
                    original_req_uri,
                    "Error type casting value of {} into Uri: {}, returning 500.",
                    proxy_route.outbound_route,
                    e
                )
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    remove_hop_by_hop_headers(&mut req, &[])?;

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

pub(crate) async fn validation_middleware_quicknode(
    cfg: &AppConfig,
    signed_message: &ProxySign,
    proxy_route: &ProxyRoute,
    req_uri: &Uri,
    remote_addr: &SocketAddr,
) -> Result<(), StatusCode> {
    let mut db = Db::create_instance(cfg).await;

    match db.read_address_status(&signed_message.address).await {
        AddressStatus::Trusted => Ok(()),
        AddressStatus::Blocked => Err(StatusCode::FORBIDDEN),
        AddressStatus::None => {
            if !signed_message.is_valid_message() {
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
            };

            let rate_limiter_key =
                format!("{}:{}", proxy_route.inbound_route, signed_message.address);

            let rate_limiter = proxy_route
                .rate_limiter
                .as_ref()
                .unwrap_or(&cfg.rate_limiter);
            match db.rate_exceeded(&rate_limiter_key, rate_limiter).await {
                Ok(false) => {}
                _ => {
                    log::warn!(
                        "{}",
                        log_format!(
                            remote_addr.ip(),
                            signed_message.address,
                            req_uri,
                            "Rate exceed for {}, checking balance for {} address.",
                            rate_limiter_key,
                            signed_message.address,
                        )
                    );

                    if !signed_message.is_valid_message() {
                        log::error!(
                            "{}",
                            log_format!(
                                remote_addr.ip(),
                                signed_message.address,
                                req_uri,
                                "Node '{}' sent invalid signed message to inbound '{}', returning 401.",
                                signed_message.address,
                                proxy_route.inbound_route
                            )
                        );

                        return Err(StatusCode::UNAUTHORIZED);
                    }
                }
            };

            if db.rate_address(rate_limiter_key).await.is_err() {
                log::error!(
                    "{}",
                    log_format!(
                        remote_addr.ip(),
                        signed_message.address,
                        req_uri,
                        "Rate incrementing failed."
                    )
                );
            };

            Ok(())
        }
    }
}
