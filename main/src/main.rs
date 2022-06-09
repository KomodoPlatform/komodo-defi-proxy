#![feature(ip)]

use crate::{http::serve, memory_db::get_redis_connection};
use core::convert::From;
use http::RateLimiter;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::env;

mod eth_poc;
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
    let x = eth_poc::verify_message("0xcdf11a9c4591fb7334daa4b21494a2590d3f7de41c7d2b333a5b61ca59da9b311b492374cc0ba4fbae53933260fa4b1c18f15d95b694629a7b0620eec77a938600", "test", "0xbAB36286672fbdc7B250804bf6D14Be0dF69fa29");
    println!("eth verification: {:?}", x);

    // to panic if redis is not available
    get_redis_connection().await;

    serve().await
}
