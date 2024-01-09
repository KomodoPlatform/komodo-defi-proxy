use crate::server::is_private_ip;

use super::*;

use address_status::{
    get_address_status_list, post_address_status, AddressStatus, AddressStatusOperations,
};
use ctx::{AppConfig, ProxyRoute};
use db::*;
use hyper::header::HeaderName;
use hyper::{
    header::{self, HeaderValue},
    Body, HeaderMap, Method, Request, Response, StatusCode,
};
use hyper_tls::HttpsConnector;
use jwt::{get_cached_token_or_generate_one, JwtClaims};
use proof_of_funding::{verify_message_and_balance, ProofOfFundingError};
use rate_limiter::RateLimitOperations;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sign::SignedMessage;
use std::net::SocketAddr;

async fn get_healthcheck() -> GenericResult<Response<Body>> {
    let json = json!({
        "health": "ok",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        .header(header::CONTENT_TYPE, "application/json")
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

async fn parse_payload(req: Request<Body>) -> GenericResult<(Request<Body>, RpcPayload)> {
    let (parts, body) = req.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await?;

    let payload: RpcPayload = serde_json::from_slice(&body_bytes)?;

    Ok((Request::from_parts(parts, Body::from(body_bytes)), payload))
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct RpcPayload {
    pub(crate) method: String,
    pub(crate) params: serde_json::value::Value,
    pub(crate) id: usize,
    pub(crate) jsonrpc: String,
    pub(crate) signed_message: SignedMessage,
}

async fn proxy(
    cfg: &AppConfig,
    mut req: Request<Body>,
    remote_addr: &SocketAddr,
    payload: RpcPayload,
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

    let original_req_uri = req.uri().clone();
    *req.uri_mut() = match proxy_route.outbound_route.parse() {
        Ok(uri) => uri,
        Err(_) => {
            log::error!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    payload.signed_message.address,
                    original_req_uri,
                    "Error type casting value of {} into Uri, returning 500.",
                    proxy_route.outbound_route
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
        .insert(HeaderName::from_static("x-forwarded-for"), x_forwarded_for);
    req.headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse()?);

    let https = HttpsConnector::new();
    let client = hyper::Client::builder().build(https);

    let target_uri = req.uri().clone();
    let res = match client.request(req).await {
        Ok(t) => t,
        Err(_) => {
            log::warn!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    payload.signed_message.address,
                    original_req_uri,
                    "Couldn't reach {}, returning 503.",
                    target_uri
                )
            );
            return response_by_status(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    Ok(res)
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

    let (req, payload) = match parse_payload(req).await {
        Ok(t) => t,
        Err(_) => {
            log::warn!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    String::from("-"),
                    req_uri,
                    "Recieved invalid http payload, returning 401."
                )
            );
            return response_by_status(StatusCode::UNAUTHORIZED);
        }
    };

    log::info!(
        "{}",
        log_format!(
            remote_addr.ip(),
            payload.signed_message.address,
            req_uri,
            "Request received."
        )
    );

    let x_forwarded_for: HeaderValue = match remote_addr.ip().to_string().parse() {
        Ok(t) => t,
        Err(_) => {
            log::error!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    payload.signed_message.address,
                    req_uri,
                    "Error type casting of IpAddr into HeaderValue, returning 500."
                )
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let proxy_route = match cfg.get_proxy_route_by_inbound(req.uri().to_string()) {
        Some(proxy_route) => proxy_route,
        None => {
            log::warn!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    payload.signed_message.address,
                    req.uri(),
                    "Proxy route not found, returning 404."
                )
            );
            return response_by_status(StatusCode::NOT_FOUND);
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

    let mut db = Db::create_instance(cfg).await;

    match db
        .read_address_status(payload.signed_message.address.clone())
        .await
    {
        AddressStatus::Trusted => {
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
        AddressStatus::Blocked => {
            log::warn!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    payload.signed_message.address,
                    req_uri,
                    "Request blocked."
                )
            );
            response_by_status(StatusCode::FORBIDDEN)
        }
        _ => {
            let signed_message_status =
                verify_message_and_balance(cfg, &payload, proxy_route).await;

            if let Err(ProofOfFundingError::InvalidSignedMessage) = signed_message_status {
                log::warn!(
                    "{}",
                    log_format!(
                        remote_addr.ip(),
                        payload.signed_message.address,
                        req_uri,
                        "Request has invalid signed message, returning 401."
                    )
                );

                return response_by_status(StatusCode::UNAUTHORIZED);
            };

            let rate_limiter_key = format!(
                "{}:{}",
                payload.signed_message.coin_ticker, payload.signed_message.address
            );

            match db
                .rate_exceeded(rate_limiter_key.clone(), &cfg.rate_limiter)
                .await
            {
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

                    match verify_message_and_balance(cfg, &payload, proxy_route).await {
                        Ok(_) => {}
                        Err(ProofOfFundingError::InsufficientBalance) => {
                            log::warn!(
                                "{}",
                                log_format!(
                                    remote_addr.ip(),
                                    payload.signed_message.address,
                                    req_uri,
                                    "Wallet {} has insufficient balance for coin {}, returning 406.",
                                    payload.signed_message.coin_ticker,
                                    payload.signed_message.address
                                )
                            );
                            return response_by_status(StatusCode::NOT_ACCEPTABLE);
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
                            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
                        }
                    }
                }
            }

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
    }
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

    let actual_payload: RpcPayload = serde_json::from_str(&json_payload.to_string()).unwrap();

    let expected_payload = RpcPayload {
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
    let cfg = ctx::get_app_config_test_instance();

    let proxy_route = cfg
        .get_proxy_route_by_inbound(String::from("/test"))
        .unwrap();

    assert_eq!(proxy_route.outbound_route, "https://komodoplatform.com");

    let proxy_route = cfg
        .get_proxy_route_by_inbound(String::from("/test-2"))
        .unwrap();

    assert_eq!(proxy_route.outbound_route, "https://atomicdex.io");
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
async fn test_parse_payload() {
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

    let mut req = Request::new(Body::from(serialized_payload));
    req.headers_mut().insert(
        HeaderName::from_static("dummy-header"),
        "dummy-value".parse().unwrap(),
    );

    let (req, payload) = parse_payload(req).await.unwrap();
    let header_value = req.headers().get("dummy-header").unwrap();

    let expected_payload = RpcPayload {
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
