use crate::ctx::{AppConfig, ProxyRoute};
use crate::logger::tracked_log;
use crate::proxy::{
    insert_jwt_to_http_header, remove_hop_by_hop_headers, response_by_status, APPLICATION_JSON,
    X_FORWARDED_FOR,
};
use crate::rpc::RpcPayload;
use crate::GenericResult;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{header, Body, Request, Response, StatusCode};
use hyper_tls::HttpsConnector;
use proxy_signature::ProxySign;
use std::net::SocketAddr;

pub(crate) async fn proxy(
    cfg: &AppConfig,
    mut req: Request<Body>,
    remote_addr: &SocketAddr,
    payload: RpcPayload,
    proxy_sign: ProxySign,
    x_forwarded_for: HeaderValue,
    proxy_route: &ProxyRoute,
) -> GenericResult<Response<Body>> {
    // If `allowed_rpc_methods` has values, only those are allowed then.
    if !proxy_route.allowed_rpc_methods.is_empty()
        && !proxy_route.allowed_rpc_methods.contains(&payload.method)
    {
        tracked_log(
            log::Level::Warn,
            remote_addr.ip(),
            proxy_sign.address,
            req.uri(),
            format!("Method {} not allowed for, returning 403.", payload.method),
        );
        return response_by_status(StatusCode::FORBIDDEN);
    }

    if proxy_route.authorized {
        // modify outgoing request
        if insert_jwt_to_http_header(cfg, req.headers_mut())
            .await
            .is_err()
        {
            tracked_log(
                log::Level::Error,
                remote_addr.ip(),
                proxy_sign.address,
                req.uri(),
                "Error inserting JWT into http header, returning 500.",
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let original_req_uri = req.uri().clone();
    *req.uri_mut() = match proxy_route.outbound_route.parse() {
        Ok(uri) => uri,
        Err(e) => {
            tracked_log(
                log::Level::Error,
                remote_addr.ip(),
                proxy_sign.address,
                original_req_uri,
                format!(
                    "Error type casting value of {} into Uri: {}, returning 500.",
                    proxy_route.outbound_route, e
                ),
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    remove_hop_by_hop_headers(&mut req, &[])?;

    req.headers_mut()
        .insert(HeaderName::from_static(X_FORWARDED_FOR), x_forwarded_for);
    req.headers_mut()
        .insert(header::CONTENT_TYPE, APPLICATION_JSON.parse()?);

    let https = HttpsConnector::new();
    let client = hyper::Client::builder().build(https);

    let target_uri = req.uri().clone();
    let res = match client.request(req).await {
        Ok(t) => t,
        Err(e) => {
            tracked_log(
                log::Level::Warn,
                remote_addr.ip(),
                proxy_sign.address,
                original_req_uri,
                format!("Couldn't reach {}: {}. Returning 503.", target_uri, e),
            );
            return response_by_status(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    Ok(res)
}
