use hyper::Uri;
use once_cell::sync::OnceCell;
use proxy::ProxyType;
use rpc::RpcClient;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::env;

pub(crate) use super::*;

const DEFAULT_TOKEN_EXPIRATION_TIME: i64 = 3600;
pub(crate) const DEFAULT_PORT: u16 = 5000;
static CONFIG: OnceCell<AppConfig> = OnceCell::new();

pub(crate) fn get_app_config() -> &'static AppConfig {
    CONFIG.get_or_init(|| {
        AppConfig::from_fs().expect("Error reading application configuration from fs.")
    })
}

fn deserialize_rpc_client<'de, D>(deserializer: D) -> Result<RpcClient, D::Error>
where
    D: Deserializer<'de>,
{
    let connection_string = String::deserialize(deserializer)?;
    Ok(RpcClient::new(connection_string))
}

fn serialize_rpc_client<S>(v: &RpcClient, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&v.url)
}

/// Configuration settings for the application, loaded typically from a JSON configuration file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct AppConfig {
    /// Optional server port to listen on. If None in config file, then [DEFAULT_PORT] will be used.
    pub(crate) port: Option<u16>,
    /// Redis database connection string.
    pub(crate) redis_connection_string: String,
    /// RPC client for komodo-defi-framework.
    #[serde(
        serialize_with = "serialize_rpc_client",
        deserialize_with = "deserialize_rpc_client"
    )]
    pub(crate) kdf_rpc_client: RpcClient,
    /// `rpc_userpass` which is required for kdf RPCs.
    pub(crate) kdf_rpc_password: String,
    /// File path to the public key used for user verification and authentication.
    pub(crate) pubkey_path: String,
    /// File path to the private key used for user verification and authentication.
    pub(crate) privkey_path: String,
    /// Optional token expiration time in seconds.
    /// If None then the [DEFAULT_TOKEN_EXPIRATION_TIME] will be used.
    pub(crate) token_expiration_time: Option<i64>,
    /// List of proxy routes.
    pub(crate) proxy_routes: Vec<ProxyRoute>,
    /// The default rate limiting rules for maintaining the frequency of incoming traffic for per client.
    pub(crate) rate_limiter: RateLimiter,
}

/// Defines a routing rule for proxying requests from an inbound route to an outbound URL
/// based on a specified proxy type and additional authorization and method filtering criteria.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct ProxyRoute {
    /// The incoming route pattern.
    pub(crate) inbound_route: String,
    /// The target URL to which requests are forwarded.
    pub(crate) outbound_route: String,
    /// The type of proxying to perform, directing requests to the appropriate service or API.
    pub(crate) proxy_type: ProxyType,
    /// Whether authorization is required for this route.
    #[serde(default)]
    pub(crate) authorized: bool,
    /// Specific RPC methods allowed for this route.
    #[serde(default)]
    pub(crate) allowed_rpc_methods: Vec<String>,
    /// Optional custom rate limiter configuration for this route. If provided,
    /// this configuration will be used instead of the default rate limiting settings.
    pub(crate) rate_limiter: Option<RateLimiter>,
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

    pub(crate) fn get_proxy_route_by_inbound(&self, inbound: &str) -> Option<&ProxyRoute> {
        let route_index = self.proxy_routes.iter().position(|r| {
            r.inbound_route == inbound
                || r.inbound_route == "/".to_owned() + inbound
                || r.inbound_route.to_owned() + "/" == inbound
                || "/".to_owned() + &*r.inbound_route == "/".to_owned() + inbound
        });

        route_index.map(|index| &self.proxy_routes[index])
    }

    #[inline(always)]
    /// Finds the best matching proxy route based on the provided URI's.
    pub(crate) fn get_proxy_route_by_uri(&self, uri: &mut Uri) -> Option<&ProxyRoute> {
        self.proxy_routes
            .iter()
            .filter(|proxy_route| uri.path().starts_with(&proxy_route.inbound_route))
            .max_by_key(|proxy_route| proxy_route.inbound_route.len())
    }
}

#[cfg(test)]
pub(crate) fn get_app_config_test_instance() -> AppConfig {
    AppConfig {
        port: Some(6150),
        redis_connection_string: String::from("redis://redis:6379"),
        kdf_rpc_client: RpcClient::new("http://127.0.0.1:7783".into()),
        kdf_rpc_password: String::from("testpass"),
        pubkey_path: String::from("/usr/src/komodo-defi-proxy/assets/.pubkey_test"),
        privkey_path: String::from("/usr/src/komodo-defi-proxy/assets/.privkey_test"),
        token_expiration_time: Some(300),
        proxy_routes: Vec::from([
            ProxyRoute {
                inbound_route: String::from("/test"),
                outbound_route: String::from("https://komodoplatform.com"),
                proxy_type: ProxyType::Quicknode,
                authorized: false,
                allowed_rpc_methods: Vec::default(),
                rate_limiter: None,
            },
            ProxyRoute {
                inbound_route: String::from("/test-2"),
                outbound_route: String::from("https://atomicdex.io"),
                proxy_type: ProxyType::Quicknode,
                authorized: false,
                allowed_rpc_methods: Vec::default(),
                rate_limiter: None,
            },
            ProxyRoute {
                inbound_route: String::from("/nft-test"),
                outbound_route: String::from("https://nft.proxy"),
                proxy_type: ProxyType::Moralis,
                authorized: false,
                allowed_rpc_methods: Vec::default(),
                rate_limiter: Some(RateLimiter {
                    rp_1_min: 60,
                    rp_5_min: 200,
                    rp_15_min: 700,
                    rp_30_min: 1000,
                    rp_60_min: 2000,
                }),
            },
            ProxyRoute {
                inbound_route: String::from("/nft-test/special"),
                outbound_route: String::from("https://nft.special"),
                proxy_type: ProxyType::Moralis,
                authorized: false,
                allowed_rpc_methods: Vec::default(),
                rate_limiter: Some(RateLimiter {
                    rp_1_min: 60,
                    rp_5_min: 200,
                    rp_15_min: 700,
                    rp_30_min: 1000,
                    rp_60_min: 2000,
                }),
            },
            ProxyRoute {
                inbound_route: String::from("/"),
                outbound_route: String::from("https://adex.io"),
                proxy_type: ProxyType::Moralis,
                authorized: false,
                allowed_rpc_methods: Vec::default(),
                rate_limiter: Some(RateLimiter {
                    rp_1_min: 60,
                    rp_5_min: 200,
                    rp_15_min: 700,
                    rp_30_min: 1000,
                    rp_60_min: 2000,
                }),
            },
        ]),
        rate_limiter: RateLimiter {
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
        "port": 6150,
        "redis_connection_string": "redis://redis:6379",
        "kdf_rpc_client": "http://127.0.0.1:7783",
        "kdf_rpc_password": "testpass",
        "pubkey_path": "/usr/src/komodo-defi-proxy/assets/.pubkey_test",
        "privkey_path": "/usr/src/komodo-defi-proxy/assets/.privkey_test",
        "token_expiration_time": 300,
        "proxy_routes": [
            {
                "inbound_route": "/test",
                "outbound_route": "https://komodoplatform.com",
                "proxy_type":"quicknode",
                "authorized": false,
                "allowed_rpc_methods": [],
                "rate_limiter": null
            },
            {
                "inbound_route": "/test-2",
                "outbound_route": "https://atomicdex.io",
                "proxy_type":"quicknode",
                "authorized": false,
                "allowed_rpc_methods": [],
                "rate_limiter": null
            },
            {
                "inbound_route": "/nft-test",
                "outbound_route": "https://nft.proxy",
                "proxy_type":"moralis",
                "authorized": false,
                "allowed_rpc_methods": [],
                "rate_limiter": {
                    "rp_1_min": 60,
                    "rp_5_min": 200,
                    "rp_15_min": 700,
                    "rp_30_min": 1000,
                    "rp_60_min": 2000
                }
            },
            {
                "inbound_route": "/nft-test/special",
                "outbound_route": "https://nft.special",
                "proxy_type":"moralis",
                "authorized": false,
                "allowed_rpc_methods": [],
                "rate_limiter": {
                    "rp_1_min": 60,
                    "rp_5_min": 200,
                    "rp_15_min": 700,
                    "rp_30_min": 1000,
                    "rp_60_min": 2000
                }
            },
            {
                "inbound_route": "/",
                "outbound_route": "https://adex.io",
                "proxy_type":"moralis",
                "authorized": false,
                "allowed_rpc_methods": [],
                "rate_limiter": {
                    "rp_1_min": 60,
                    "rp_5_min": 200,
                    "rp_15_min": 700,
                    "rp_30_min": 1000,
                    "rp_60_min": 2000
                }
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
