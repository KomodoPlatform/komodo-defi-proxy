use hyper::Uri;
use once_cell::sync::OnceCell;
use proxy::ProxyType;
use serde::{Deserialize, Serialize};
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

/// Configuration settings for the application, loaded typically from a JSON configuration file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct AppConfig {
    /// Optional server port to listen on. If None in config file, then [DEFAULT_PORT] will be used.
    pub(crate) port: Option<u16>,
    /// Redis database connection string.
    pub(crate) redis_connection_string: String,
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

    /// Finds the best matching proxy route based on the provided URI's path and updates the URI by
    /// removing the matched path segments while preserving the query parameters.
    pub(crate) fn get_proxy_route_extracting_uri_inbound(
        &self,
        uri: &mut Uri,
    ) -> GenericResult<Option<&ProxyRoute>> {
        let path_segments: Vec<&str> = uri.path().split('/').filter(|s| !s.is_empty()).collect();

        let mut best_match: Option<(&ProxyRoute, usize)> = None;

        for r in &self.proxy_routes {
            let route_segments: Vec<&str> = r
                .inbound_route
                .split('/')
                .filter(|s| !s.is_empty())
                .collect();
            // Count the number of segments that match between the route and the path
            let matched_segments = route_segments
                .iter()
                .zip(&path_segments)
                .take_while(|(route_seg, path_seg)| route_seg == path_seg)
                .count();
            // Update best_match if this route fully matches (all its segments are matched)
            // and best_match is None or has more matched segments than the current best match
            if matched_segments == route_segments.len() // Ensure all segments of the route are matched
                && (best_match.is_none() || matched_segments > best_match.unwrap().1)
            {
                best_match = Some((r, matched_segments));
            }
        }

        if let Some((route, matched_segments)) = best_match {
            // Construct the remaining path by skipping matched segments and accumulating the rest
            let remaining_path: String = path_segments.iter().skip(matched_segments).fold(
                String::new(),
                |mut acc, segment| {
                    acc.push('/');
                    acc.push_str(segment);
                    acc
                },
            );

            // Construct the new path and query
            let new_path_and_query = match uri.query() {
                Some(query) => format!("{}?{}", remaining_path, query),
                None => remaining_path,
            };

            let mut parts = uri.clone().into_parts();
            parts.path_and_query = Some(new_path_and_query.parse()?);
            let new_uri = Uri::from_parts(parts)?;
            *uri = new_uri;

            return Ok(Some(route));
        }

        Ok(None)
    }
}

#[cfg(test)]
pub(crate) fn get_app_config_test_instance() -> AppConfig {
    AppConfig {
        port: Some(6150),
        redis_connection_string: String::from("redis://redis:6379"),
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
