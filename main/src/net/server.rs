use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use crate::http::{http_handler, response_by_status};
use crate::log_format;
use crate::websocket::{should_upgrade_to_socket_conn, socket_handler};
use crate::{ctx::AppConfig, GenericError, GenericResult};

#[macro_export]
macro_rules! log_format {
  ($ip: expr, $address: expr, $path: expr, $format: expr, $($args: tt)+) => {format!(concat!("[Ip: {} | Address: {} | Path: {}] ", $format), $ip, $address, $path, $($args)+)};
  ($ip: expr, $address: expr, $path: expr, $format: expr) => {format!(concat!("[Ip: {} | Pubkey: {} | Address: {}] ", $format), $ip, $address, $path)}
}

fn get_real_address(req: &Request<Body>, remote_addr: &SocketAddr) -> GenericResult<SocketAddr> {
    if let Some(ip) = req.headers().get("x-forwarded-for") {
        let addr = IpAddr::from_str(ip.to_str()?)?;

        return Ok(SocketAddr::new(addr, remote_addr.port()));
    }

    Ok(*remote_addr)
}

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
        socket_handler(cfg, req, remote_addr).await
    } else {
        http_handler(cfg, req, remote_addr).await
    }
}

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

    log::info!("AtomicDEX Auth API serving on http://{}", addr);

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
        hyper::header::HeaderName::from_static("x-forwarded-for"),
        "0.0.0.0".parse().unwrap(),
    );

    let remote_addr = get_real_address(&req, &socket_addr).unwrap();
    assert_eq!("0.0.0.0", remote_addr.ip().to_string());
}
