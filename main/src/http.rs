use super::*;
use ctx::{get_app_config, AppConfig, ProxyRoute};
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
use rate_limiter::RateLimitOperations;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sign::{SignOps, SignedMessage};
use std::net::SocketAddr;

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

async fn parse_payload(req: Request<Body>) -> GenericResult<(Request<Body>, QuickNodePayload)> {
    let (parts, body) = req.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await?;

    let payload: QuickNodePayload = serde_json::from_slice(&body_bytes)?;

    Ok((Request::from_parts(parts, Body::from(body_bytes)), payload))
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct QuickNodePayload {
    pub(crate) method: String,
    pub(crate) params: serde_json::value::Value,
    pub(crate) id: usize,
    pub(crate) jsonrpc: String,
    pub(crate) signed_message: SignedMessage,
}

async fn proxy(
    mut req: Request<Body>,
    payload: QuickNodePayload,
    x_forwarded_for: HeaderValue,
) -> GenericResult<Response<Body>> {
    let config = get_app_config();
    let proxy_route = config.get_proxy_route_by_inbound(req.uri().to_string());

    if let Some(proxy_route) = proxy_route {
        // check if requested method allowed
        if !proxy_route.allowed_methods.contains(&payload.method) {
            return response_by_status(StatusCode::FORBIDDEN);
        }

        // modify outgoing request
        if insert_jwt_to_http_header(req.headers_mut()).await.is_err() {
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }

        *req.uri_mut() = match proxy_route.outbound_route.parse() {
            Ok(uri) => uri,
            Err(_) => {
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

        let res = match client.request(req).await {
            Ok(t) => t,
            Err(_) => {
                return response_by_status(StatusCode::SERVICE_UNAVAILABLE);
            }
        };

        return Ok(res);
    }

    response_by_status(StatusCode::NOT_FOUND)
}

async fn router(req: Request<Body>, remote_addr: SocketAddr) -> GenericResult<Response<Body>> {
    if !remote_addr.ip().is_global() {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => return get_healthcheck().await,
            (&Method::GET, "/ip-status") => return post_ip_status(req).await,
            (&Method::POST, "/ip-status") => return get_ip_status_list().await,
            _ => {}
        };
    };

    let (req, payload) = match parse_payload(req).await {
        Ok(t) => t,
        Err(_) => {
            return response_by_status(StatusCode::UNAUTHORIZED);
        }
    };

    let x_forwarded_for: HeaderValue = match remote_addr.ip().to_string().parse() {
        Ok(t) => t,
        Err(_) => {
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if !remote_addr.ip().is_global() {
        return proxy(req, payload, x_forwarded_for).await;
    }

    let mut db = Db::create_instance().await;

    match db.read_ip_status(remote_addr.ip().to_string()).await {
        IpStatus::Trusted => proxy(req, payload, x_forwarded_for).await,
        IpStatus::Blocked => response_by_status(StatusCode::FORBIDDEN),
        _ => {
            match db.rate_exceeded(remote_addr.ip().to_string()).await {
                Ok(false) => {}
                _ => {
                    return response_by_status(StatusCode::TOO_MANY_REQUESTS);
                }
            }

            if db.rate_ip(remote_addr.ip().to_string()).await.is_err() {
                // TODO
                // log
            };

            // TODO
            // wallet balance validation via app configurations
            match payload.signed_message.verify_message() {
                Ok(true) => {}
                _ => {
                    return response_by_status(StatusCode::UNAUTHORIZED);
                }
            }

            proxy(req, payload, x_forwarded_for).await
        }
    }
}

pub(crate) async fn serve() -> GenericResult<()> {
    let config = get_app_config();

    let addr = format!("0.0.0.0:{}", config.port.unwrap_or(5000)).parse()?;

    let router = make_service_fn(move |c_stream: &AddrStream| {
        let remote_addr = c_stream.remote_addr();
        async move { Ok::<_, GenericError>(service_fn(move |req| router(req, remote_addr))) }
    });

    let server = Server::bind(&addr).serve(router);

    println!("AtomicDEX Auth API serving on http://{}", addr);

    Ok(server.await?)
}
