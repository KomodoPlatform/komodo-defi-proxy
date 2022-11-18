use super::*;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::env;

const DEFAULT_TOKEN_EXPIRATION_TIME: i64 = 3600;
static CONFIG: OnceCell<AppConfig> = OnceCell::new();

pub(crate) fn get_app_config() -> &'static AppConfig {
    CONFIG.get_or_init(|| {
        AppConfig::from_fs().expect("Error reading application configuration from fs.")
    })
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct AppConfig {
    pub(crate) port: Option<u16>,
    pub(crate) redis_connection_string: String,
    pub(crate) pubkey_path: String,
    pub(crate) privkey_path: String,
    pub(crate) token_expiration_time: Option<i64>,
    pub(crate) proxy_routes: Vec<ProxyRoute>,
    pub(crate) rate_limiter: RateLimiter,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct ProxyRoute {
    pub(crate) inbound_route: String,
    pub(crate) outbound_route: String,
    pub(crate) authorized: bool,
    pub(crate) allowed_methods: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct RateLimiter {
    pub(crate) rp_1_min: u16,
    pub(crate) rp_5_min: u16,
    pub(crate) rp_15_min: u16,
    pub(crate) rp_30_min: u16,
    pub(crate) rp_60_min: u16,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct Node {
    pub(crate) coins: Vec<String>,
    pub(crate) url: String,
    pub(crate) authorized: bool,
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
                authorized: false,
                allowed_methods: Vec::default(),
            },
            ProxyRoute {
                inbound_route: String::from("/test-2"),
                outbound_route: String::from("https://atomicdex.io"),
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
                "authorized": false,
                "allowed_methods": []
            },
            {
                "inbound_route": "/test-2",
                "outbound_route": "https://atomicdex.io",
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
    env::set_var("AUTH_APP_CONFIG_PATH", "../assets/.config_test");

    let actual = AppConfig::from_fs().unwrap();
    let expected = get_app_config_test_instance();
    assert_eq!(actual, expected);
}
