#![feature(ip)]

use crate::{http::serve, memory_db::get_redis_connection};
use http::RateLimiter;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::env;

mod http;
mod jwt;
mod memory_db;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub port: Option<u16>,
    pub redis_connection_string: String,
    pub pubkey_path: String,
    pub privkey_path: String,
    pub token_expiration_time: Option<i64>,
    pub proxy_routes: Vec<ProxyRoute>,
    pub rate_limiter: RateLimiter,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyRoute {
    pub inbound_route: String,
    pub outbound_route: String,
    pub allowed_methods: Vec<String>,
}

impl AppConfig {
    fn from_fs() -> Self {
        let config_path =
            env::var("AUTH_APP_CONFIG_PATH").expect("AUTH_APP_CONFIG_PATH must be defined.");
        let file = std::fs::read_to_string(config_path).unwrap();
        serde_json::from_str(&file).unwrap()
    }
}

static CONFIG: OnceCell<AppConfig> = OnceCell::new();

fn get_app_config() -> &'static AppConfig {
    CONFIG.get_or_init(AppConfig::from_fs)
}

#[tokio::main]
async fn main() -> Result<()> {
    // to panic if redis is not available
    get_redis_connection().await;

    serve().await
}
