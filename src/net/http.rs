use super::*;
use crate::proxy::{generate_payload_from_req, proxy, validation_middleware};
use crate::server::is_private_ip;
use address_status::{get_address_status_list, post_address_status};
use ctx::AppConfig;
use hyper::{
    header::{self, HeaderValue},
    Body, HeaderMap, Method, Request, Response, StatusCode,
};
use jwt::{get_cached_token_or_generate_one, JwtClaims};
use serde_json::json;
use std::net::SocketAddr;

/// Value
pub(crate) const APPLICATION_JSON: &str = "application/json";
/// Header
pub(crate) const X_FORWARDED_FOR: &str = "x-forwarded-for";
async fn get_healthcheck() -> GenericResult<Response<Body>> {
    let json = json!({
        "health": "ok",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        .header(header::CONTENT_TYPE, APPLICATION_JSON)
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

    // create proxy_route before payload, as we need proxy_type from it for payload generation
    let proxy_route = match cfg.get_proxy_route_by_inbound(req.uri().path().to_string()) {
        Some(proxy_route) => proxy_route,
        None => {
            log::warn!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    String::from("-"),
                    req.uri(),
                    "Proxy route not found, returning 404."
                )
            );
            return response_by_status(StatusCode::NOT_FOUND);
        }
    };

    let (req, payload) = match generate_payload_from_req(req, &proxy_route.proxy_type).await {
        Ok(t) => t,
        Err(_) => {
            log::warn!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    String::from("-"),
                    req_uri,
                    "Received invalid http payload, returning 401."
                )
            );
            return response_by_status(StatusCode::UNAUTHORIZED);
        }
    };

    log::info!(
        "{}",
        log_format!(
            remote_addr.ip(),
            payload.signed_message().address,
            req_uri,
            "Request and payload data received."
        )
    );

    let x_forwarded_for: HeaderValue = match remote_addr.ip().to_string().parse() {
        Ok(t) => t,
        Err(_) => {
            log::error!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    payload.signed_message().address,
                    req_uri,
                    "Error type casting of IpAddr into HeaderValue, returning 500."
                )
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
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

    if let Err(status_code) =
        validation_middleware(cfg, &payload, proxy_route, req.uri(), &remote_addr).await
    {
        return response_by_status(status_code);
    }

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

#[test]
fn test_get_proxy_route_by_inbound() {
    use hyper::Uri;
    use std::str::FromStr;

    let cfg = ctx::get_app_config_test_instance();

    // If we leave this code line `let proxy_route = match cfg.get_proxy_route_by_inbound(req.uri().to_string()) {`
    // inbound_route cant be "/test", as it's not uri. I suppose inbound actually should be a Path.
    // Two options: in `req.uri().to_string()` path() is missing or "/test" in test is wrong and the whole url should be.
    let proxy_route = cfg
        .get_proxy_route_by_inbound(String::from("/test"))
        .unwrap();

    assert_eq!(proxy_route.outbound_route, "https://komodoplatform.com");

    let proxy_route = cfg
        .get_proxy_route_by_inbound(String::from("/test-2"))
        .unwrap();

    assert_eq!(proxy_route.outbound_route, "https://atomicdex.io");

    let url = Uri::from_str("https://komodo.proxy:5535/nft-test").unwrap();
    let path = url.path().to_string();
    let proxy_route = cfg.get_proxy_route_by_inbound(path).unwrap();
    assert_eq!(proxy_route.outbound_route, "https://nft.proxy");
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
