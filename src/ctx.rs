use std::env;

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

use super::*;

const DEFAULT_TOKEN_EXPIRATION_TIME: i64 = 3600;
static CONFIG: OnceCell<AppConfig> = OnceCell::new();

pub(crate) fn get_app_config() -> &'static AppConfig {
    CONFIG.get_or_init(|| {
        AppConfig::from_fs().expect("Error reading application configuration from fs.")
    })
}

/// Configuration settings for the application, loaded typically from a JSON configuration file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct AppConfig {
    // Optional server port to listen on. If None in config file, then 5000 is default.
    pub(crate) port: Option<u16>,
    // Redis database connection string.
    pub(crate) redis_connection_string: String,
    // File path to the public key used for cryptographic operations.
    pub(crate) pubkey_path: String,
    // File path to the private key used for cryptographic operations.
    pub(crate) privkey_path: String,
    // Optional token expiration time in seconds. If None then 3600 is default.
    pub(crate) token_expiration_time: Option<i64>,
    // Routing configurations for proxying requests.
    pub(crate) proxy_routes: Vec<ProxyRoute>,
    // Rate limiting settings for request handling.
    pub(crate) rate_limiter: RateLimiter,
}

/// Defines a routing rule for proxying requests from an inbound route to an outbound URL
/// based on a specified proxy type and additional authorization and method filtering criteria.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct ProxyRoute {
    // The incoming route pattern.
    pub(crate) inbound_route: String,
    // The target URL to which requests are forwarded.
    pub(crate) outbound_route: String,
    // The type of proxying to perform (e.g., JSON-RPC Call, HTTP GET).
    pub(crate) proxy_type: ProxyType,
    // Whether authorization is required for this route.
    #[serde(default)]
    pub(crate) authorized: bool,
    // Specific HTTP methods allowed for this route.
    #[serde(default)]
    pub(crate) allowed_methods: Vec<String>,
}

/// Enumerates different types of proxy operations supported, such as JSON-RPC Call over HTTP POST and HTTP GET.
/// This helps in applying specific handling logic based on the proxy type.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProxyType {
    JsonRpc, // JSON-RPC call using HTTP POST
    HttpGet, // Standard HTTP GET request
}

/// Configuration for rate limiting to manage the number of requests allowed over specified time intervals.
/// This prevents abuse and ensures fair usage of resources among all clients.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct RateLimiter {
    pub(crate) rp_1_min: u16,
    pub(crate) rp_5_min: u16,
    pub(crate) rp_15_min: u16,
    pub(crate) rp_30_min: u16,
    pub(crate) rp_60_min: u16,
}

impl AppConfig {
    fn from_fs() -> GenericResult<Self> {
        let config_path =
            env::var("AUTH_APP_CONFIG_PATH").expect("AUTH_APP_CONFIG_PATH must be defined.");
        let file = std::fs::read_to_string(config_path)?;
        Ok(serde_json::from_str(&file)?)
    }

    pub(crate) fn token_expiration_time(&self) -> i64 {
        self.token_expiration_time
            .unwrap_or(DEFAULT_TOKEN_EXPIRATION_TIME)
    }

    pub(crate) fn get_proxy_route_by_inbound(&self, inbound: String) -> Option<&ProxyRoute> {
        let route_index = self.proxy_routes.iter().position(|r| {
            r.inbound_route == inbound || r.inbound_route.to_owned() + "/" == inbound
        });

        if let Some(index) = route_index {
            return Some(&self.proxy_routes[index]);
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
                proxy_type: ProxyType::JsonRpc,
                authorized: false,
                allowed_methods: Vec::default(),
            },
            ProxyRoute {
                inbound_route: String::from("/test-2"),
                outbound_route: String::from("https://atomicdex.io"),
                proxy_type: ProxyType::JsonRpc,
                authorized: false,
                allowed_methods: Vec::default(),
            },
            ProxyRoute {
                inbound_route: String::from("/nft-test"),
                outbound_route: String::from("https://nft.proxy"),
                proxy_type: ProxyType::HttpGet,
                authorized: false,
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
    }
}

#[test]
fn test_app_config_serialzation_and_deserialization() {
    let json_config = serde_json::json!({
        "port": 5000,
        "redis_connection_string": "dummy-value",
        "pubkey_path": "dummy-value",
        "privkey_path": "dummy-value",
        "token_expiration_time": 300,
        "proxy_routes": [
            {
                "inbound_route": "/test",
                "outbound_route": "https://komodoplatform.com",
                "proxy_type":"json_rpc",
                "authorized": false,
                "allowed_methods": []
            },
            {
                "inbound_route": "/test-2",
                "outbound_route": "https://atomicdex.io",
                "proxy_type":"json_rpc",
                "authorized": false,
                "allowed_methods": []
            },
            {
                "inbound_route": "/nft-test",
                "outbound_route": "https://nft.proxy",
                "proxy_type":"http_get",
                "authorized": false,
                "allowed_methods": []
            }
        ],
        "rate_limiter": {
            "rp_1_min": 555,
            "rp_5_min": 555,
            "rp_15_min": 555,
            "rp_30_min": 555,
            "rp_60_min": 555
        }
    });

    let actual_config: AppConfig = serde_json::from_str(&json_config.to_string()).unwrap();
    let expected_config = get_app_config_test_instance();

    assert_eq!(actual_config, expected_config);

    // Backwards
    let json = serde_json::to_value(expected_config).unwrap();
    assert_eq!(json_config, json);
    assert_eq!(json_config.to_string(), json.to_string());
}

#[test]
fn test_from_fs() {
    env::set_var("AUTH_APP_CONFIG_PATH", "./assets/.config_test");

    let actual = AppConfig::from_fs().unwrap();
    let expected = get_app_config_test_instance();
    assert_eq!(actual, expected);
}
