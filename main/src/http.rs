use super::*;
use crate::jwt::generate_jwt;
use bytes::Buf;
use hyper::{
    header::{self, HeaderValue},
    Body, HeaderMap, Method, Request, Response, Server, StatusCode,
};
use memory_db::*;
use serde_json::json;
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

async fn get_healthcheck() -> Result<Response<Body>> {
    let json = json!({
        "status": "healthy",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json.to_string()))
        .unwrap())
}

#[derive(Debug, Deserialize)]
pub struct IpStatusPayload {
    pub ip: String,
    pub status: i8,
}

async fn post_ip_status(req: Request<Body>) -> Result<Response<Body>> {
    let whole_body = hyper::body::aggregate(req).await?;
    let payload: Vec<IpStatusPayload> = serde_json::from_reader(whole_body.reader())?;

    let mut db = Db::create_instance().await;
    db.bulk_insert_ip_status(payload).await?;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(Vec::new()))
        .unwrap())
}

fn response_by_status(status: StatusCode) -> Result<Response<Body>> {
    Ok(Response::builder()
        .status(status)
        .body(Body::from(Vec::new()))
        .unwrap())
}

async fn insert_jwt_to_http_header(headers: &mut HeaderMap<HeaderValue>) -> Result<()> {
    let auth_token = generate_jwt().await?;
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", auth_token).parse().unwrap(),
    );

    Ok(())
}

async fn proxy(mut req: Request<Body>) -> Result<Response<Body>> {
    let config = get_app_config();
    let proxy_route = config.get_proxy_route_by_inbound(req.uri().to_string());

    if let Some(proxy_route) = proxy_route {
        // Modify outgoing request
        insert_jwt_to_http_header(req.headers_mut()).await?;
        *req.uri_mut() = proxy_route.outbound_route.parse().unwrap();

        let client = hyper::Client::new();
        return Ok(client.request(req).await.unwrap());
    }

    response_by_status(StatusCode::NOT_FOUND)
}

async fn router(req: Request<Body>, remote_addr: SocketAddr) -> Result<Response<Body>> {
    let mut db = Db::create_instance().await;
    // db.insert_ip_status(remote_addr.ip().to_string(), IpStatus::Unrecognized).await?;

    if let IpStatus::Blocked = db.get_ip_status(remote_addr.ip().to_string()).await? {
        return response_by_status(StatusCode::FORBIDDEN);
    }

    // TODO
    // Will be refactored
    if req.method() == Method::GET && req.uri().path() == "/" {
        return get_healthcheck().await;
    } else if req.method() == Method::POST && req.uri().path() == "/ip-status" {
        if remote_addr.ip().is_global() {
            return response_by_status(StatusCode::FORBIDDEN);
        }

        return post_ip_status(req).await;
    }

    proxy(req).await
}

pub async fn serve() -> Result<()> {
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
