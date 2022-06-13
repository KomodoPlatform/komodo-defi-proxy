use super::*;
use once_cell::sync::OnceCell;
use rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::env;

static CONFIG: OnceCell<AppConfig> = OnceCell::new();

pub(crate) fn get_app_config() -> &'static AppConfig {
    CONFIG.get_or_init(|| {
        AppConfig::from_fs().expect("Error reading application configuration from fs.")
    })
}

#[derive(Deserialize)]
pub(crate) struct AppConfig {
    pub(crate) port: Option<u16>,
    pub(crate) redis_connection_string: String,
    pub(crate) pubkey_path: String,
    pub(crate) privkey_path: String,
    pub(crate) token_expiration_time: Option<i64>,
    pub(crate) proxy_routes: Vec<ProxyRoute>,
    pub(crate) rate_limiter: RateLimiter,
    pub(crate) nodes: Vec<Node>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ProxyRoute {
    pub(crate) inbound_route: String,
    pub(crate) outbound_route: String,
    pub(crate) allowed_methods: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct RateLimiter {
    pub(crate) rp_1_min: u16,
    pub(crate) rp_5_min: u16,
    pub(crate) rp_15_min: u16,
    pub(crate) rp_30_min: u16,
    pub(crate) rp_60_min: u16,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Node {
    pub(crate) name: String,
    pub(crate) url: String,
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
