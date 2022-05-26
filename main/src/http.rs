use crate::jwt::generate_jwt;

use super::*;
use hyper::{
    header::{self, HeaderName, HeaderValue},
    Body, Method, Request, Response, Server, StatusCode,
};
use redis::aio::MultiplexedConnection;
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

async fn api_healthcheck() -> Result<Response<Body>> {
    let json = json!({
        "status": "healthy",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json.to_string()))
        .unwrap())
}

fn response_by_status(status: StatusCode) -> Result<Response<Body>> {
    Ok(Response::builder()
        .status(status)
        .body(Body::from(Vec::new()))
        .unwrap())
}

async fn proxy(mut req: Request<Body>) -> Result<Response<Body>> {
    let config = get_app_config();

    let proxy_route = config.get_proxy_route_by_inbound(req.uri().to_string());

    if let Some(proxy_route) = proxy_route {
        let client = hyper::Client::new();
        *req.uri_mut() = proxy_route.outbound_route.parse().unwrap();

        let auth_token = generate_jwt().await?;
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {}", auth_token).parse().unwrap(),
        );

        return Ok(client.request(req).await.unwrap());
    }

    response_by_status(StatusCode::NOT_FOUND)
}

async fn router(
    req: Request<Body>,
    _remote_addr: SocketAddr,
    _r_connection: MultiplexedConnection,
) -> Result<Response<Body>> {
    if req.method() == &Method::GET && req.uri().path() == "/" {
        return api_healthcheck().await;
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
        async move {
            let r_connection = get_redis_connection().await;
            Ok::<_, GenericError>(service_fn(move |req| {
                router(req, remote_addr, r_connection.clone())
            }))
        }
    });

    let server = Server::bind(&addr).serve(router);

    println!("AtomicDEX Auth API serving on http://{}", addr);

    Ok(server.await?)
}
