use crate::address_status::{AddressStatus, AddressStatusOperations};
use crate::ctx::{AppConfig, ProxyRoute};
use crate::db::Db;
use crate::http::{
    insert_jwt_to_http_header, response_by_status, APPLICATION_JSON, X_FORWARDED_FOR,
};
use crate::proxy::remove_hop_by_hop_headers;
use crate::rate_limiter::RateLimitOperations;
use crate::rpc::Json;
use crate::{log_format, rpc, GenericResult};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{header, Body, Request, Response, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use proxy_signature::ProxySign;
use serde::{Deserialize, Serialize};
use serde_json::json;
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
            let signed_message_status =
                verify_message_and_balance(cfg, signed_message, proxy_route).await;

            if let Err(ProofOfFundingError::InvalidSignedMessage) = signed_message_status {
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

            let rate_limiter_key = format!("{}:{}", "TICKER_TODO", signed_message.address);

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

                    match verify_message_and_balance(cfg, signed_message, proxy_route).await {
                        Ok(_) => {}
                        Err(ProofOfFundingError::InsufficientBalance) => {
                            log::warn!(
                                "{}",
                                log_format!(
                                    remote_addr.ip(),
                                    signed_message.address,
                                    req_uri,
                                    "Wallet {} has insufficient balance for coin {}, returning 406.",
                                    signed_message.address,
                                    "TICKER_TODO",
                                )
                            );

                            return Err(StatusCode::NOT_ACCEPTABLE);
                        }
                        e => {
                            log::error!(
                                "{}",
                                log_format!(
                                    remote_addr.ip(),
                                    signed_message.address,
                                    req_uri,
                                    "verify_message_and_balance failed in coin {}: {:?}",
                                    "TICKER_TODO",
                                    e
                                )
                            );
                            return Err(StatusCode::INTERNAL_SERVER_ERROR);
                        }
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

// TODO: don't check balance
async fn verify_message_and_balance(
    cfg: &AppConfig,
    signed_message: &ProxySign,
    proxy_route: &ProxyRoute,
) -> Result<(), ProofOfFundingError> {
    if let true = signed_message.is_valid_message() {
        let mut db = Db::create_instance(cfg).await;

        // We don't want to send balance requests everytime when user sends requests.
        if let Ok(true) = db.key_exists(&signed_message.address).await {
            return Ok(());
        }

        let rpc_payload = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [signed_message.address, "latest"]
        });

        let rpc_client =
            // TODO: Use the current transport instead of forcing to use http (even if it's rare, this might not work on certain nodes)
            rpc::RpcClient::new(proxy_route.outbound_route.replace("ws", "http").clone());

        match rpc_client
            .send(cfg, rpc_payload, proxy_route.authorized)
            .await
        {
            Ok(res) if res["result"] != Json::Null && res["result"] != "0x0" => {
                // cache this address for 60 seconds
                let _ = db.insert_cache(&signed_message.address, "", 60).await;

                return Ok(());
            }
            Ok(res) if res["error"] != Json::Null => {
                return Err(ProofOfFundingError::ErrorFromRpcCall);
            }
            Ok(_) => return Err(ProofOfFundingError::InsufficientBalance),
            Err(e) => return Err(ProofOfFundingError::RpcCallFailed(e.to_string())),
        };
    }

    Err(ProofOfFundingError::InvalidSignedMessage)
}
