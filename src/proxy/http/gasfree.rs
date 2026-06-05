use crate::ctx::ProxyRoute;
use crate::logger::tracked_log;
use crate::proxy::http::get::modify_request_uri;
use crate::proxy::{
    remove_hop_by_hop_headers, response_by_status, ProxyType, APPLICATION_JSON, X_FORWARDED_FOR,
};
use crate::GenericResult;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{header, Body, Request, Response, StatusCode};
use hyper_tls::HttpsConnector;
use proxy_signature::ProxySign;
use sha2::Sha256;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

const GASFREE_TIMESTAMP_HEADER: &str = "timestamp";

type HmacSha256 = Hmac<Sha256>;

pub(crate) async fn proxy(
    mut req: Request<Body>,
    remote_addr: &SocketAddr,
    signed_message: ProxySign,
    x_forwarded_for: HeaderValue,
    proxy_route: &ProxyRoute,
) -> GenericResult<Response<Body>> {
    let (api_key, api_secret) = match &proxy_route.proxy_type {
        ProxyType::GasFree {
            api_key,
            api_secret,
        } => (api_key.as_str(), api_secret.as_str()),
        _ => {
            tracked_log(
                log::Level::Error,
                remote_addr.ip(),
                signed_message.address,
                req.uri(),
                "GasFree handler received a non-GasFree route, returning 500.",
            );
            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let original_req_uri = req.uri().clone();

    if let Err(e) = modify_request_uri(&mut req, proxy_route) {
        tracked_log(
            log::Level::Error,
            remote_addr.ip(),
            signed_message.address,
            original_req_uri,
            format!("Error modifying request base Uri: {}, returning 500.", e),
        );
        return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if let Err(e) = insert_gasfree_auth_headers(&mut req, api_key, api_secret) {
        tracked_log(
            log::Level::Error,
            remote_addr.ip(),
            signed_message.address,
            req.uri(),
            format!(
                "Error inserting GasFree auth headers: {}, returning 500.",
                e
            ),
        );
        return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    remove_hop_by_hop_headers(&mut req, &[])?;

    req.headers_mut()
        .insert(HeaderName::from_static(X_FORWARDED_FOR), x_forwarded_for);
    req.headers_mut()
        .insert(header::ACCEPT, APPLICATION_JSON.parse()?);
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
                signed_message.address,
                original_req_uri,
                format!("Couldn't reach {}: {}. Returning 503.", target_uri, e),
            );
            return response_by_status(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    Ok(res)
}

pub(crate) fn build_hmac_authorization(
    api_key: &str,
    api_secret: &str,
    method: &str,
    request_path: &str,
    timestamp: u64,
) -> String {
    let string_to_sign = format!("{method}{request_path}{timestamp}");
    let mut mac = HmacSha256::new_from_slice(api_secret.as_bytes())
        .expect("HMAC-SHA256 accepts arbitrary-length keys");
    mac.update(string_to_sign.as_bytes());
    let signature = BASE64_STANDARD.encode(mac.finalize().into_bytes());
    format!("ApiKey {api_key}:{signature}")
}

fn insert_gasfree_auth_headers(
    req: &mut Request<Body>,
    api_key: &str,
    api_secret: &str,
) -> GenericResult<()> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let authorization = build_hmac_authorization(
        api_key,
        api_secret,
        req.method().as_str(),
        req.uri().path(),
        timestamp,
    );

    req.headers_mut().insert(
        HeaderName::from_static(GASFREE_TIMESTAMP_HEADER),
        timestamp.to_string().parse()?,
    );
    req.headers_mut()
        .insert(header::AUTHORIZATION, authorization.parse()?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_hmac_authorization_known_vector() {
        let authorization = build_hmac_authorization(
            "test-key",
            "test-secret",
            "GET",
            "/nile/api/v1/config/token/all",
            1_731_912_286,
        );

        assert_eq!(
            authorization,
            "ApiKey test-key:sYfwaLSnifcL/MTLFDmfORdCVceFLckEPL1mMKEjTHQ="
        );
    }
}
