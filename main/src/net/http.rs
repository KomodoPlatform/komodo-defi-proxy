use super::*;
use ctx::{AppConfig, ProxyRoute};
use db::*;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{
    header::{self, HeaderValue},
    Body, HeaderMap, Method, Request, Response, Server, StatusCode,
};
use hyper_tls::HttpsConnector;
use ip_status::{get_ip_status_list, post_ip_status, IpStatus, IpStatusOperations};
use jwt::generate_jwt;
use proof_of_funding::{verify_message_and_balance, ProofOfFundingError};
use rate_limiter::RateLimitOperations;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sign::SignedMessage;
use std::net::SocketAddr;

macro_rules! http_log_format {
  ($ip: expr, $path: expr, $format: expr, $($args: tt)+) => {format!(concat!("[{} -> {}] ", $format), $ip, $path, $($args)+)};
  ($ip: expr, $path: expr, $format: expr) => {format!(concat!("[{} -> {}] ", $format), $ip, $path)}
}

impl AppConfig {
    fn get_proxy_route_by_inbound(&self, inbound: String) -> Option<&ProxyRoute> {
        let route_index = self.proxy_routes.iter().position(|r| {
            r.inbound_route == inbound || r.inbound_route.to_owned() + "/" == inbound
        });

        if let Some(index) = route_index {
            return Some(&self.proxy_routes[index]);
        }

        None
    }
}

async fn get_healthcheck() -> GenericResult<Response<Body>> {
    let json = json!({
        "status": "healthy",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json.to_string()))?)
}

pub(crate) fn response_by_status(status: StatusCode) -> GenericResult<Response<Body>> {
    Ok(Response::builder()
        .status(status)
        .body(Body::from(Vec::new()))?)
}

async fn insert_jwt_to_http_header(headers: &mut HeaderMap<HeaderValue>) -> GenericResult<()> {
    let auth_token = generate_jwt().await?;
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

#[derive(Debug, Serialize, Deserialize)]
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
) -> GenericResult<Response<Body>> {
    let proxy_route = cfg.get_proxy_route_by_inbound(req.uri().to_string());

    if let Some(proxy_route) = proxy_route {
        // check if requested method allowed
        if !proxy_route.allowed_methods.contains(&payload.method) {
            log::warn!(
                "{}",
                http_log_format!(
                    remote_addr.ip(),
                    req.uri(),
                    "Method {} not allowed for, returning 403.",
                    payload.method
                )
            );
            return response_by_status(StatusCode::FORBIDDEN);
        }

        // modify outgoing request
        if insert_jwt_to_http_header(req.headers_mut()).await.is_err() {
            log::error!(
                "{}",
                http_log_format!(
                    remote_addr.ip(),
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
                    http_log_format!(
                        remote_addr.ip(),
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

        req.headers_mut().insert(
            header::HeaderName::from_static("x-forwarded-for"),
            x_forwarded_for,
        );

        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build(https);

        let target_uri = req.uri().clone();
        let res = match client.request(req).await {
            Ok(t) => t,
            Err(_) => {
                log::warn!(
                    "{}",
                    http_log_format!(
                        remote_addr.ip(),
                        original_req_uri,
                        "Couldn't reach {}, returning 503.",
                        target_uri
                    )
                );
                return response_by_status(StatusCode::SERVICE_UNAVAILABLE);
            }
        };

        return Ok(res);
    }

    log::warn!(
        "{}",
        http_log_format!(
            remote_addr.ip(),
            req.uri(),
            "Proxy route not found, returning 404."
        )
    );
    response_by_status(StatusCode::NOT_FOUND)
}

async fn router(
    cfg: &AppConfig,
    req: Request<Body>,
    remote_addr: SocketAddr,
) -> GenericResult<Response<Body>> {
    log::info!(
        "{}",
        http_log_format!(remote_addr.ip(), req.uri(), "Request received.")
    );

    if !remote_addr.ip().is_global() {
        log::info!(
            "{}",
            http_log_format!(
                remote_addr.ip(),
                req.uri(),
                "Incoming ip is in the same network. Security middlewares will be by-passed."
            )
        );

        match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => return get_healthcheck().await,
            (&Method::GET, "/ip-status") => return post_ip_status(cfg, req).await,
            (&Method::POST, "/ip-status") => return get_ip_status_list(cfg).await,
            _ => {}
        };
    };

    let req_path = req.uri().clone();
    let (req, payload) = match parse_payload(req).await {
        Ok(t) => t,
        Err(_) => {
            log::warn!(
                "{}",
                http_log_format!(
                    remote_addr.ip(),
                    req_path,
                    "Recieved invalid http payload, returning 401."
                )
            );
            return response_by_status(StatusCode::UNAUTHORIZED);
        }
    };

    let x_forwarded_for: HeaderValue = match remote_addr.ip().to_string().parse() {
        Ok(t) => t,
        Err(_) => {
            log::error!(
                "{}",
                http_log_format!(
                    remote_addr.ip(),
                    req_path,
                    "Error type casting of IpAddr into HeaderValue, returning 500."
                )
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if !remote_addr.ip().is_global() {
        return proxy(cfg, req, &remote_addr, payload, x_forwarded_for).await;
    }

    let mut db = Db::create_instance(cfg).await;

    match db.read_ip_status(remote_addr.ip().to_string()).await {
        IpStatus::Trusted => proxy(cfg, req, &remote_addr, payload, x_forwarded_for).await,
        IpStatus::Blocked => {
            log::warn!(
                "{}",
                http_log_format!(remote_addr.ip(), req_path, "Request blocked.")
            );
            response_by_status(StatusCode::FORBIDDEN)
        }
        _ => {
            match db
                .rate_exceeded(remote_addr.ip().to_string(), &cfg.rate_limiter)
                .await
            {
                Ok(false) => {}
                _ => {
                    log::warn!(
                        "{}",
                        http_log_format!(remote_addr.ip(), req_path, "Rate exceed, returning 429.")
                    );
                    return response_by_status(StatusCode::TOO_MANY_REQUESTS);
                }
            }

            if db.rate_ip(remote_addr.ip().to_string()).await.is_err() {
                log::error!(
                    "{}",
                    http_log_format!(remote_addr.ip(), req_path, "Rate incrementing failed.")
                );
            };

            match verify_message_and_balance(cfg, &payload).await {
                Ok(_) => proxy(cfg, req, &remote_addr, payload, x_forwarded_for).await,
                Err(ProofOfFundingError::InvalidSignedMessage) => {
                    log::warn!(
                        "{}",
                        http_log_format!(
                            remote_addr.ip(),
                            req_path,
                            "Request has invalid signed message, returning 401."
                        )
                    );
                    response_by_status(StatusCode::UNAUTHORIZED)
                }
                Err(ProofOfFundingError::InsufficientBalance) => {
                    log::warn!(
                        "{}",
                        http_log_format!(
                            remote_addr.ip(),
                            req_path,
                            "Wallet {} has insufficient balance, returning 406.",
                            payload.signed_message.address
                        )
                    );
                    response_by_status(StatusCode::NOT_ACCEPTABLE)
                }
                _ => response_by_status(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
    }
}

pub(crate) async fn serve(cfg: &'static AppConfig) -> GenericResult<()> {
    let addr = format!("0.0.0.0:{}", cfg.port.unwrap_or(5000)).parse()?;

    let router = make_service_fn(move |c_stream: &AddrStream| {
        let remote_addr = c_stream.remote_addr();
        async move { Ok::<_, GenericError>(service_fn(move |req| router(cfg, req, remote_addr))) }
    });

    let server = Server::bind(&addr).serve(router);

    log::info!("AtomicDEX Auth API serving on http://{}", addr);

    Ok(server.await?)
}