use std::net::SocketAddr;

use hyper::{StatusCode, Uri};
use proxy_signature::ProxySign;

use crate::{
    address_status::{AddressStatus, AddressStatusOperations},
    ctx::{AppConfig, ProxyRoute},
    db::Db, log_format, rate_limiter::RateLimitOperations,
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
