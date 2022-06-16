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
            return Some(RpcClient::new(node.url.clone()));
        }

        None
    }
}

#[cfg(test)]
pub(crate) fn get_app_config_test_instance() -> AppConfig {
    AppConfig {
        port: Some(5000),
        redis_connection_string: String::from("dummy-value"),
        pubkey_path: String::from("dummy-value"),
        privkey_path: String::from("dummy-value"),
        token_expiration_time: Some(300),
        proxy_routes: Vec::from([
            ProxyRoute {
                inbound_route: String::from("/test"),
                outbound_route: String::from("https://komodoplatform.com"),
                allowed_methods: Vec::default(),
            },
            ProxyRoute {
                inbound_route: String::from("/test-2"),
                outbound_route: String::from("https://atomicdex.io"),
                allowed_methods: Vec::default(),
            },
        ]),
        rate_limiter: ctx::RateLimiter {
            rp_1_min: 555,
            rp_5_min: 555,
            rp_15_min: 555,
            rp_30_min: 555,
            rp_60_min: 555,
        },
        nodes: Vec::from([
            ctx::Node {
                name: String::from("ETH"),
                url: String::from("https://dummy-address"),
            },
            ctx::Node {
                name: String::from("KMD"),
                url: String::from("https://dummy-address2"),
            },
        ]),
    }
}

#[test]
fn test_get_node() {
    let cfg = get_app_config_test_instance();

    let node = cfg.get_node(String::from("ETH")).unwrap();
    assert_eq!(node.name, "ETH");
    assert_eq!(node.url, "https://dummy-address");

    let node = cfg.get_node(String::from("KMD")).unwrap();
    assert_eq!(node.name, "KMD");
    assert_eq!(node.url, "https://dummy-address2");
}

#[test]
fn test_get_rpc_client() {
    let cfg = get_app_config_test_instance();

    let rpc_client = cfg.get_rpc_client(String::from("ETH")).unwrap();
    assert_eq!(rpc_client.url, "https://dummy-address");

    let rpc_client = cfg.get_rpc_client(String::from("KMD")).unwrap();
    assert_eq!(rpc_client.url, "https://dummy-address2");
}
