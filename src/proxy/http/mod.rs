use std::net::SocketAddr;

use hyper::{StatusCode, Uri};
use proxy_signature::ProxySign;

use crate::{
    address_status::{AddressStatus, AddressStatusOperations},
    ctx::{AppConfig, ProxyRoute},
    db::Db,
    log_format,
    rate_limiter::RateLimitOperations,
};

pub(crate) mod get;
pub(crate) mod post;

pub(crate) async fn validation_middleware(
    cfg: &AppConfig,
    signed_message: &ProxySign,
    proxy_route: &ProxyRoute,
    req_uri: &Uri,
    remote_addr: &SocketAddr,
) -> Result<(), StatusCode> {
    let mut db = Db::create_instance(cfg).await;

    match db.read_address_status(&signed_message.address).await {
        AddressStatus::Trusted => Ok(()),
        AddressStatus::Blocked => Err(StatusCode::FORBIDDEN),
        AddressStatus::None => {
            if !signed_message.is_valid_message() {
                log::warn!(
                    "{}",
                    log_format!(
                        remote_addr.ip(),
                        signed_message.address,
                        req_uri,
                        "Request has invalid signed message, returning 401"
                    )
                );

                return Err(StatusCode::UNAUTHORIZED);
            }

            let rate_limiter_key =
                format!("{}:{}", proxy_route.inbound_route, signed_message.address);

            let rate_limiter = proxy_route
                .rate_limiter
                .as_ref()
                .unwrap_or(&cfg.rate_limiter);
            match db.rate_exceeded(&rate_limiter_key, rate_limiter).await {
                Ok(false) => {}
                Ok(true) => {
                    log::warn!(
                        "{}",
                        log_format!(
                            remote_addr.ip(),
                            signed_message.address,
                            req_uri,
                            "Rate exceed for {}, returning 406.",
                            rate_limiter_key,
                        )
                    );
                    return Err(StatusCode::NOT_ACCEPTABLE);
                }
                Err(e) => {
                    log::error!(
                        "{}",
                        log_format!(
                            remote_addr.ip(),
                            signed_message.address,
                            req_uri,
                            "Rate exceeded check failed for node '{}': {}, returning 500.",
                            signed_message.address,
                            e
                        )
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }

            if let Err(e) = db.rate_address(rate_limiter_key).await {
                log::error!(
                    "{}",
                    log_format!(
                        remote_addr.ip(),
                        signed_message.address,
                        req_uri,
                        "Rate incrementing failed for node '{}': {}, returning 500.",
                        signed_message.address,
                        e
                    )
                );
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            };

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use hyper::StatusCode;

    use crate::{ctx, http::response_by_status};

    #[test]
    fn test_get_proxy_route_by_inbound() {
        use hyper::Uri;
        use std::str::FromStr;

        let cfg = ctx::get_app_config_test_instance();

        let proxy_route = cfg.get_proxy_route_by_inbound("/test").unwrap();

        assert_eq!(proxy_route.outbound_route, "https://komodoplatform.com");

        let proxy_route = cfg.get_proxy_route_by_inbound("/test-2").unwrap();

        assert_eq!(proxy_route.outbound_route, "https://atomicdex.io");

        let url = Uri::from_str("https://komodo.proxy:5535/nft-test").unwrap();
        let path = url.path().to_string();
        let proxy_route = cfg.get_proxy_route_by_inbound(&path).unwrap();
        assert_eq!(proxy_route.outbound_route, "https://nft.proxy");
    }

    #[test]
    fn test_get_proxy_route_by_uri_inbound() {
        use hyper::Uri;
        use std::str::FromStr;

        let cfg = ctx::get_app_config_test_instance();

        // test "/nft-test" inbound case
        let mut url = Uri::from_str("https://komodo.proxy:5535/nft-test/nft/api/v2.2/0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326/nft/transfers?chain=eth&format=decimal&order=DESC").unwrap();
        let proxy_route = cfg.get_proxy_route_by_uri(&mut url).unwrap();
        assert_eq!(proxy_route.outbound_route, "https://nft.proxy");

        // test "/nft-test/special" inbound case
        let mut url = Uri::from_str("https://komodo.proxy:3333/nft-test/special/api/v2.2/0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326/nft/transfers?chain=eth&format=decimal&order=DESC").unwrap();
        let proxy_route = cfg.get_proxy_route_by_uri(&mut url).unwrap();
        assert_eq!(proxy_route.outbound_route, "https://nft.special");

        // test "/" inbound case
        let mut url = Uri::from_str("https://komodo.proxy:0333/api/v2.2/0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326/nft/transfers?chain=eth&format=decimal&order=DESC").unwrap();
        let proxy_route = cfg.get_proxy_route_by_uri(&mut url).unwrap();
        assert_eq!(proxy_route.outbound_route, "https://adex.io");
    }

    #[test]
    fn test_respond_by_status() {
        let all_supported_status_codes = [
            100, 101, 102, 200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302, 303,
            304, 305, 307, 308, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412,
            413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 426, 428, 429, 431, 451, 500, 501,
            502, 503, 504, 505, 506, 507, 508, 510, 511,
        ];

        for status_code in all_supported_status_codes {
            let status_type = StatusCode::from_u16(status_code).unwrap();
            let res = response_by_status(status_type).unwrap();
            assert_eq!(res.status(), status_type);
        }
    }
}
