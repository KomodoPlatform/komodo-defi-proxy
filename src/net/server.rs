use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};

use super::{GenericError, GenericResult};
use crate::ctx::{AppConfig, DEFAULT_PORT};
use crate::logger::tracked_log;
use crate::proxy::websocket::{should_upgrade_to_socket_conn, socket_handler};
use crate::proxy::{http_handler, response_by_status, X_FORWARDED_FOR};

pub(crate) fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        // We don't support IPv6s yet
        IpAddr::V6(_) => false,
    }
}

fn get_real_address(req: &Request<Body>, remote_addr: &SocketAddr) -> GenericResult<SocketAddr> {
    if let Some(ip) = req.headers().get(X_FORWARDED_FOR) {
        // NOTE (Decker): This parses the ENTIRE `X-Forwarded-For` value as a single IP.
        // That is only correct when the value contains exactly one IP. Per RFC 7239 /
        // de-facto convention, XFF is a COMMA-SEPARATED LIST of IPs that grows as the
        // request passes through proxies:
        //
        //     X-Forwarded-For: <original-client>, <proxy-1>, <proxy-2>, ...
        //
        // The leftmost entry is the original client; each hop appends the address it saw.
        //
        // How nginx populates it depends on the directive in front of us:
        //
        //   1) APPEND (default-ish, multi-value):
        //        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        //      nginx takes whatever the client sent and APPENDS the real connecting IP:
        //        client sends "X-Forwarded-For: 127.0.0.1"
        //        -> upstream receives "127.0.0.1, <real-client-ip>"
        //      With the single-IP parse below, `IpAddr::from_str("127.0.0.1, 1.2.3.4")`
        //      FAILS -> `?` returns Err -> caller responds 500. So any client-supplied
        //      XFF turns into a 500 here (fail-closed, but by accident, not by design).
        //
        //   2) REPLACE (single-value, recommended for this setup):
        //        proxy_set_header X-Forwarded-For $remote_addr;
        //      nginx OVERWRITES the header with the real TCP peer IP it sees. The client
        //      cannot influence it:
        //        client sends "X-Forwarded-For: 127.0.0.1"
        //        -> upstream receives "<real-client-ip>"  (single IP, parses fine)
        //      This is what keeps the admin/private branch (is_private_ip) unreachable
        //      from the outside: a spoofed "127.0.0.1" can never reach us.
        //
        //   3) PASS-THROUGH (DANGEROUS, do NOT use):
        //        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
        //      nginx forwards the client value verbatim. Then a client sending
        //      "X-Forwarded-For: 127.0.0.1" is trusted here as a private IP -> full
        //      auth bypass + access to /address-status. This is the critical XFF-trust
        //      vulnerability; never configure nginx this way.
        //
        // SECURITY: trusting XFF unconditionally is unsafe regardless of nginx config.
        // The robust fix is to (a) decide privacy from the real TCP `remote_addr`, and
        // (b) only honor XFF when the TCP peer is in an allowlist of trusted upstreams,
        // parsing it as a list and taking the appropriate entry — not as a single IP.
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
    let t_start = std::time::Instant::now();
    log::debug!(
        "hang-debug: connection_handler started: {} {} from tcp-peer {}",
        req.method(),
        req.uri(),
        remote_addr
    );
    let method = req.method().clone();
    let uri = req.uri().clone();

    let remote_addr = match get_real_address(&req, &remote_addr) {
        Ok(t) => t,
        _ => {
            tracked_log(
                log::Level::Error,
                remote_addr.ip(),
                "**not-available**",
                req.uri(),
                "Reading real remote address failed, returning 500.",
            );

            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let result = if should_upgrade_to_socket_conn(&req) {
        socket_handler(cfg.clone(), req, remote_addr).await
    } else {
        http_handler(cfg, req, remote_addr).await
    };

    match &result {
        Ok(response) => log::debug!(
            "hang-debug: connection_handler finished: {} {} from {} -> status {} in {}ms",
            method,
            uri,
            remote_addr,
            response.status(),
            t_start.elapsed().as_millis()
        ),
        Err(e) => log::debug!(
            "hang-debug: connection_handler finished: {} {} from {} -> error '{}' in {}ms",
            method,
            uri,
            remote_addr,
            e,
            t_start.elapsed().as_millis()
        ),
    }

    result
}

/// Starts serving the proxy API on the configured port. This function sets up the HTTP server,
/// binds it to the specified address, and listens for incoming requests.
pub(crate) async fn serve(cfg: &'static AppConfig) -> GenericResult<()> {
    let addr = format!("0.0.0.0:{}", cfg.port.unwrap_or(DEFAULT_PORT)).parse()?;

    let handler = make_service_fn(move |c_stream: &AddrStream| {
        let remote_addr = c_stream.remote_addr();
        log::debug!(
            "hang-debug: new TCP connection accepted from {}",
            remote_addr
        );
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
