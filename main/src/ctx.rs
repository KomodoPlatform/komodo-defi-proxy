use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::env;

static CONFIG: OnceCell<AppConfig> = OnceCell::new();

pub fn get_app_config() -> &'static AppConfig {
    CONFIG.get_or_init(AppConfig::from_fs)
}

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

#[derive(Debug, Deserialize)]
pub struct RateLimiter {
    pub rp_1_min: u16,
    pub rp_5_min: u16,
    pub rp_15_min: u16,
    pub rp_30_min: u16,
    pub rp_60_min: u16,
}

impl AppConfig {
    fn from_fs() -> Self {
        let config_path =
            env::var("AUTH_APP_CONFIG_PATH").expect("AUTH_APP_CONFIG_PATH must be defined.");
        let file = std::fs::read_to_string(config_path).unwrap();
        serde_json::from_str(&file).unwrap()
    }
}
