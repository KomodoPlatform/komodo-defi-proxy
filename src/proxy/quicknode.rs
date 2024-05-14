use crate::address_status::{AddressStatus, AddressStatusOperations};
use crate::ctx::{AppConfig, ProxyRoute};
use crate::db::Db;
use crate::http::{
    insert_jwt_to_http_header, response_by_status, APPLICATION_JSON, X_FORWARDED_FOR,
};
use crate::rate_limiter::RateLimitOperations;
use crate::rpc::Json;
use crate::sign::{SignOps, SignedMessage};
use crate::{log_format, rpc, GenericResult};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{header, Body, Request, Response, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;

/// Represents a payload for JSON-RPC calls, tailored for the Quicknode API within the proxy.
/// This struct combines standard JSON RPC method call fields (method, params, id, jsonrpc) with a `SignedMessage`
/// for authentication and validation, facilitating secure and validated interactions with the Quicknode service.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct QuicknodePayload {
    pub(crate) method: String,
    pub(crate) params: serde_json::value::Value,
    pub(crate) id: usize,
    pub(crate) jsonrpc: String,
    pub(crate) signed_message: SignedMessage,
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

pub(crate) async fn validation_middleware_quicknode(
    cfg: &AppConfig,
    payload: &QuicknodePayload,
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
            let signed_message_status = verify_message_and_balance(cfg, payload, proxy_route).await;

            if let Err(ProofOfFundingError::InvalidSignedMessage) = signed_message_status {
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
            };

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
                _ => {
                    log::warn!(
                        "{}",
                        log_format!(
                            remote_addr.ip(),
                            payload.signed_message.address,
                            req_uri,
                            "Rate exceed for {}, checking balance for {} address.",
                            rate_limiter_key,
                            payload.signed_message.address
                        )
                    );

                    match verify_message_and_balance(cfg, payload, proxy_route).await {
                        Ok(_) => {}
                        Err(ProofOfFundingError::InsufficientBalance) => {
                            log::warn!(
                                "{}",
                                log_format!(
                                    remote_addr.ip(),
                                    payload.signed_message.address,
                                    req_uri,
                                    "Wallet {} has insufficient balance for coin {}, returning 406.",
                                    payload.signed_message.address,
                                    payload.signed_message.coin_ticker,
                                )
                            );

                            return Err(StatusCode::NOT_ACCEPTABLE);
                        }
                        e => {
                            log::error!(
                                "{}",
                                log_format!(
                                    remote_addr.ip(),
                                    payload.signed_message.address,
                                    req_uri,
                                    "verify_message_and_balance failed in coin {}: {:?}",
                                    payload.signed_message.coin_ticker,
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
                        payload.signed_message.address,
                        req_uri,
                        "Rate incrementing failed."
                    )
                );
            };

            Ok(())
        }
    }
}

async fn verify_message_and_balance(
    cfg: &AppConfig,
    payload: &QuicknodePayload,
    proxy_route: &ProxyRoute,
) -> Result<(), ProofOfFundingError> {
    if let Ok(true) = payload.signed_message.verify_message() {
        let mut db = Db::create_instance(cfg).await;

        // We don't want to send balance requests everytime when user sends requests.
        if let Ok(true) = db.key_exists(&payload.signed_message.address).await {
            return Ok(());
        }

        let rpc_payload = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [payload.signed_message.address, "latest"]
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
                let _ = db
                    .insert_cache(&payload.signed_message.address, "", 60)
                    .await;

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

#[test]
fn test_quicknode_payload_serialzation_and_deserialization() {
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

    let actual_payload: QuicknodePayload = serde_json::from_str(&json_payload.to_string()).unwrap();

    let expected_payload = QuicknodePayload {
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

#[tokio::test]
async fn test_parse_quicknode_payload() {
    use super::parse_payload;
    use hyper::Method;

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

    let (mut req, payload): (Request<Body>, QuicknodePayload) =
        parse_payload::<QuicknodePayload>(req, false).await.unwrap();

    let body_bytes = hyper::body::to_bytes(req.body_mut()).await.unwrap();
    assert!(
        !body_bytes.is_empty(),
        "Body should not be empty for non-GET methods"
    );

    let header_value = req.headers().get("dummy-header").unwrap();

    let expected_payload = QuicknodePayload {
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
