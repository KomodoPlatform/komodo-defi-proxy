use super::*;
use once_cell::sync::OnceCell;
use rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::env;

static CONFIG: OnceCell<AppConfig> = OnceCell::new();

pub fn get_app_config() -> &'static AppConfig {
    CONFIG.get_or_init(|| {
        AppConfig::from_fs().expect("Error reading application configuration from fs.")
    })
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
    pub nodes: Vec<Node>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Node {
    pub name: String,
    pub url: String,
}

impl AppConfig {
    fn from_fs() -> GenericResult<Self> {
        let config_path =
            env::var("AUTH_APP_CONFIG_PATH").expect("AUTH_APP_CONFIG_PATH must be defined.");
        let file = std::fs::read_to_string(config_path)?;
        Ok(serde_json::from_str(&file)?)
    }

    pub(crate) fn get_node(&self, ticker: String) -> Option<&Node> {
        (&self.nodes).iter().find(|node| node.name == ticker)
    }

    pub(crate) fn get_rpc_client(&self, ticker: String) -> Option<RpcClient> {
        if let Some(node) = self.get_node(ticker) {
            return Some(RpcClient {
                url: node.url.clone(),
            });
        }

        None
    }
}
