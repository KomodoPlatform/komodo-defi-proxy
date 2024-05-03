use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode, Uri};

use crate::address_status::AddressStatusOperations;
use crate::ctx::ProxyRoute;
use crate::db::Db;
use crate::http::{http_handler, response_by_status, JsonRpcPayload, PayloadData, X_FORWARDED_FOR};
use crate::log_format;
use crate::proof_of_funding::{verify_message_and_balance, ProofOfFundingError};
use crate::rate_limiter::RateLimitOperations;
use crate::websocket::{should_upgrade_to_socket_conn, socket_handler};
use crate::{ctx::AppConfig, GenericError, GenericResult};

#[macro_export]
macro_rules! log_format {
  ($ip: expr, $address: expr, $path: expr, $format: expr, $($args: tt)+) => {format!(concat!("[Ip: {} | Address: {} | Path: {}] ", $format), $ip, $address, $path, $($args)+)};
  ($ip: expr, $address: expr, $path: expr, $format: expr) => {format!(concat!("[Ip: {} | Pubkey: {} | Address: {}] ", $format), $ip, $address, $path)}
}

pub(crate) fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        // We don't support IPv6s yet
        IpAddr::V6(_) => false,
    }
}

fn get_real_address(req: &Request<Body>, remote_addr: &SocketAddr) -> GenericResult<SocketAddr> {
    if let Some(ip) = req.headers().get(X_FORWARDED_FOR) {
        let addr = IpAddr::from_str(ip.to_str()?)?;

        return Ok(SocketAddr::new(addr, remote_addr.port()));
    }

    Ok(*remote_addr)
}

/// Handles incoming HTTP requests based on their content and whether they need to be upgraded
/// to a socket connection.
///
/// This function first resolves the real client address from the request, considering forwarded headers.
/// It then decides whether to handle the request as a regular HTTP request or upgrade it to a
/// socket-based connection based on its headers and content.
async fn connection_handler(
    cfg: &AppConfig,
    req: Request<Body>,
    remote_addr: SocketAddr,
) -> GenericResult<Response<Body>> {
    let remote_addr = match get_real_address(&req, &remote_addr) {
        Ok(t) => t,
        _ => {
            log::error!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    String::from("-"),
                    req.uri(),
                    "Reading real remote address failed, returning 500."
                )
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if should_upgrade_to_socket_conn(&req) {
        socket_handler(cfg.clone(), req, remote_addr).await
    } else {
        http_handler(cfg, req, remote_addr).await
    }
}

// TODO handle eth and nft features
pub(crate) async fn validation_middleware(
    cfg: &AppConfig,
    payload: &PayloadData,
    proxy_route: &ProxyRoute,
    req_uri: &Uri,
    remote_addr: &SocketAddr,
) -> Result<(), StatusCode> {
    match payload {
        PayloadData::JsonRpc(payload) => {
            validation_middleware_eth(cfg, payload, proxy_route, req_uri, remote_addr).await
        }
        PayloadData::HttpGet(_payload) => {
            // TODO add validation_middleware for nft
            Ok(())
        }
    }
}

pub(crate) async fn validation_middleware_eth(
    cfg: &AppConfig,
    payload: &JsonRpcPayload,
    proxy_route: &ProxyRoute,
    req_uri: &Uri,
    remote_addr: &SocketAddr,
) -> Result<(), StatusCode> {
    let mut db = Db::create_instance(cfg).await;

    match db
        .read_address_status(&payload.signed_message.address)
        .await
    {
        crate::address_status::AddressStatus::Trusted => Ok(()),
        crate::address_status::AddressStatus::Blocked => Err(StatusCode::FORBIDDEN),
        crate::address_status::AddressStatus::None => {
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

            match db.rate_exceeded(&rate_limiter_key, &cfg.rate_limiter).await {
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
                                    payload.signed_message.coin_ticker,
                                    payload.signed_message.address
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

/// Starts serving the proxy API on the configured port. This function sets up the HTTP server,
/// binds it to the specified address, and listens for incoming requests.
pub(crate) async fn serve(cfg: &'static AppConfig) -> GenericResult<()> {
    let addr = format!("0.0.0.0:{}", cfg.port.unwrap_or(5000)).parse()?;

    let handler = make_service_fn(move |c_stream: &AddrStream| {
        let remote_addr = c_stream.remote_addr();
        async move {
            Ok::<_, GenericError>(service_fn(move |req| {
                connection_handler(cfg, req, remote_addr)
            }))
        }
    });

    let server = Server::bind(&addr).serve(handler);

    log::info!("Komodo-DeFi-Proxy API serving on http://{}", addr);

    Ok(server.await?)
}

#[test]
fn test_get_real_address() {
    let mut req = Request::new(Body::from(Vec::new()));

    let addr = IpAddr::from_str("127.0.0.1").unwrap();
    let socket_addr = SocketAddr::new(addr, 80);

    let remote_addr = get_real_address(&req, &socket_addr).unwrap();
    assert_eq!("127.0.0.1", remote_addr.ip().to_string());

    req.headers_mut().insert(
        hyper::header::HeaderName::from_static(X_FORWARDED_FOR),
        "0.0.0.0".parse().unwrap(),
    );

    let remote_addr = get_real_address(&req, &socket_addr).unwrap();
    assert_eq!("0.0.0.0", remote_addr.ip().to_string());
}

#[test]
fn test_is_private_ip_v4() {
    let private_ip = "192.168.1.1".parse().unwrap();
    assert!(is_private_ip(&private_ip));

    let private_ip = "10.0.0.1".parse().unwrap();
    assert!(is_private_ip(&private_ip));

    let private_ip = "172.16.0.1".parse().unwrap();
    assert!(is_private_ip(&private_ip));

    let public_ip = "8.8.8.8".parse().unwrap();
    assert!(!is_private_ip(&public_ip));

    let public_ip = "203.0.113.1".parse().unwrap();
    assert!(!is_private_ip(&public_ip));
}
