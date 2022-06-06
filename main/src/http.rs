use super::*;
use crate::jwt::generate_jwt;
use bytes::Buf;
use hyper::{
    header::{self, HeaderValue},
    Body, HeaderMap, Method, Request, Response, Server, StatusCode,
};
use hyper_tls::HttpsConnector;
use memory_db::*;
use serde_json::json;
use std::net::SocketAddr;

#[derive(Debug, Deserialize)]
pub struct RateLimiter {
    pub rp_1_min: u16,
    pub rp_5_min: u16,
    pub rp_15_min: u16,
    pub rp_30_min: u16,
    pub rp_60_min: u16,
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

#[derive(Debug, Serialize, Deserialize)]
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

async fn get_ip_status_list() -> Result<Response<Body>> {
    let mut db = Db::create_instance().await;
    let list = db.read_ip_status_list().await?;

    let list: Vec<IpStatusPayload> = list
        .iter()
        .map(|v| IpStatusPayload {
            ip: v.0.clone(),
            status: v.1,
        })
        .collect();
    let serialized = serde_json::to_string(&list).unwrap();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serialized))
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
        ] {
            req.headers_mut().remove(key);
        }

        // keep-alive header is not provided from `header`,
        // so remove it by writing it hard-coded.
        req.headers_mut().remove("keep-alive");

        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build(https);

        return Ok(client.request(req).await.unwrap());
    }

    response_by_status(StatusCode::NOT_FOUND)
}

async fn router(req: Request<Body>, remote_addr: SocketAddr) -> Result<Response<Body>> {
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
