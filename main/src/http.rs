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
        .body(Body::from(json.to_string()))
        .unwrap())
}

fn response_by_status(status: StatusCode) -> GenericResult<Response<Body>> {
    Ok(Response::builder()
        .status(status)
        .body(Body::from(Vec::new()))
        .unwrap())
}

async fn insert_jwt_to_http_header(headers: &mut HeaderMap<HeaderValue>) -> GenericResult<()> {
    let auth_token = generate_jwt().await?;
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", auth_token).parse().unwrap(),
    );

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuickNodePayload {
    pub method: String,
    pub params: serde_json::value::Value,
    pub id: usize,
    pub jsonrpc: String,
    pub signed_message: SignedMessage,
}

async fn proxy(mut req: Request<Body>, payload: QuickNodePayload) -> GenericResult<Response<Body>> {
    let config = get_app_config();
    let proxy_route = config.get_proxy_route_by_inbound(req.uri().to_string());

    if let Some(proxy_route) = proxy_route {
        // check if requested method allowed
        if !proxy_route.allowed_methods.contains(&payload.method) {
            return response_by_status(StatusCode::FORBIDDEN);
        }

        // modify outgoing request
        insert_jwt_to_http_header(req.headers_mut()).await?;
        *req.uri_mut() = proxy_route.outbound_route.parse().unwrap();

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

        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build(https);

        return Ok(client.request(req).await.unwrap());
    }

    response_by_status(StatusCode::NOT_FOUND)
}

async fn router(req: Request<Body>, remote_addr: SocketAddr) -> GenericResult<Response<Body>> {
    // TODO
    // Will be refactored
    if req.method() == Method::GET && req.uri().path() == "/" {
        return get_healthcheck().await;
    } else if req.method() == Method::POST && req.uri().path() == "/ip-status" {
        if remote_addr.ip().is_global() {
            return response_by_status(StatusCode::FORBIDDEN);
        }

        return post_ip_status(req).await;
    } else if req.method() == Method::GET && req.uri().path() == "/ip-status" {
        if remote_addr.ip().is_global() {
            return response_by_status(StatusCode::FORBIDDEN);
        }

        return get_ip_status_list().await;
    }

    let mut db = Db::create_instance().await;

    if db.rate_exceeded(remote_addr.ip().to_string()).await? {
        return response_by_status(StatusCode::TOO_MANY_REQUESTS);
    }

    if IpStatus::Blocked == db.read_ip_status(remote_addr.ip().to_string()).await?
        && remote_addr.ip().is_global()
    {
        return response_by_status(StatusCode::FORBIDDEN);
    }

    db.rate_ip(remote_addr.ip().to_string()).await?;

    let (parts, body) = req.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await.unwrap();

    let payload: QuickNodePayload = serde_json::from_slice(&body_bytes).unwrap();

    if !payload.signed_message.verify_message() {
        return response_by_status(StatusCode::UNAUTHORIZED);
    }

    let req = Request::from_parts(parts, Body::from(body_bytes));

    proxy(req, payload).await
}

pub async fn serve() -> GenericResult<()> {
    let config = get_app_config();

    let addr = format!("0.0.0.0:{}", config.port.unwrap_or(5000))
        .parse()
        .unwrap();

    let router = make_service_fn(move |c_stream: &AddrStream| {
        let remote_addr = c_stream.remote_addr();
        async move { Ok::<_, GenericError>(service_fn(move |req| router(req, remote_addr))) }
    });

    let server = Server::bind(&addr).serve(router);

    println!("AtomicDEX Auth API serving on http://{}", addr);

    Ok(server.await?)
}
