use bytes::Buf;
use ctx::AppConfig;
use hyper::{body::aggregate, header, Body, Request};
use hyper_tls::HttpsConnector;
use proxy_signature::ProxySign;
use serde::{Deserialize, Serialize};
use serde_json::from_reader;
use std::time::{Duration, Instant};

/// Upper bound for a full outbound RPC round trip (connect + request + response body).
/// KDF's own `peer_connection_healthcheck` takes ~10s for disconnected peers, so this
/// must stay comfortably above that; a wedged KDF must yield an error, not a hang.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

use crate::proxy::{insert_jwt_to_http_header, APPLICATION_JSON};

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RpcClient {
    pub(crate) url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub(crate) enum Id {
    String(String),
    Number(usize),
}

/// Payload for JSON-RPC calls
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct RpcPayload {
    pub(crate) method: String,
    pub(crate) params: serde_json::Value,
    pub(crate) id: Id,
    pub(crate) jsonrpc: String,
}

/// Used for websocket connection.
/// It combines standard JSON RPC method call fields (method, params, id, jsonrpc) with a `SignedMessage`
/// for authentication and validation, facilitating secure and validated interactions with the Quicknode service.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct RpcSocketPayload {
    method: String,
    params: serde_json::Value,
    id: Id,
    jsonrpc: String,
    proxy_sign: ProxySign,
}

impl RpcSocketPayload {
    pub(crate) fn into_parts(self) -> (RpcPayload, ProxySign) {
        let payload = RpcPayload {
            method: self.method,
            params: self.params,
            id: self.id,
            jsonrpc: self.jsonrpc,
        };
        let proxy_sign = self.proxy_sign;
        (payload, proxy_sign)
    }
}

impl RpcClient {
    pub(crate) fn new(url: String) -> Self {
        RpcClient { url }
    }

    pub(crate) async fn send(
        &self,
        cfg: &AppConfig,
        payload: serde_json::Value,
        is_authorized: bool,
    ) -> GenericResult<serde_json::Value> {
        // hang-debug: log only the method name, never the payload itself (it contains userpass).
        let rpc_method = payload["method"]
            .as_str()
            .unwrap_or("**unknown**")
            .to_owned();
        let t_start = Instant::now();
        log::debug!(
            "hang-debug: RpcClient::send starting: method '{}' to {} (timeout: {:?})",
            rpc_method,
            self.url,
            RPC_TIMEOUT
        );

        let mut req = Request::post(&self.url).body(Body::from(payload.to_string()))?;
        req.headers_mut()
            .append(header::CONTENT_TYPE, APPLICATION_JSON.parse()?);

        if is_authorized {
            insert_jwt_to_http_header(cfg, req.headers_mut()).await?;
        }

        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build(https);

        let response_result = match tokio::time::timeout(RPC_TIMEOUT, client.request(req)).await {
            Ok(result) => result,
            Err(_) => {
                log::warn!(
                    "hang-debug: RpcClient::send '{}' to {}: TIMED OUT after {:?}",
                    rpc_method,
                    self.url,
                    RPC_TIMEOUT
                );
                return Err(format!(
                    "RPC '{}' to {} timed out after {:?}",
                    rpc_method, self.url, RPC_TIMEOUT
                )
                .into());
            }
        };

        let res = match response_result {
            Ok(res) => {
                log::debug!(
                    "hang-debug: RpcClient::send '{}' to {}: response headers received in {}ms, status {}",
                    rpc_method,
                    self.url,
                    t_start.elapsed().as_millis(),
                    res.status()
                );
                res
            }
            Err(e) => {
                log::debug!(
                    "hang-debug: RpcClient::send '{}' to {}: transport error after {}ms: {}",
                    rpc_method,
                    self.url,
                    t_start.elapsed().as_millis(),
                    e
                );
                return Err(e.into());
            }
        };

        let remaining = RPC_TIMEOUT.saturating_sub(t_start.elapsed());
        let body_result = match tokio::time::timeout(remaining, aggregate(res)).await {
            Ok(result) => result,
            Err(_) => {
                log::warn!(
                    "hang-debug: RpcClient::send '{}' to {}: body read TIMED OUT after {:?} total",
                    rpc_method,
                    self.url,
                    RPC_TIMEOUT
                );
                return Err(format!(
                    "RPC '{}' to {}: body read timed out after {:?} total",
                    rpc_method, self.url, RPC_TIMEOUT
                )
                .into());
            }
        };

        let body = match body_result {
            Ok(body) => body,
            Err(e) => {
                log::debug!(
                    "hang-debug: RpcClient::send '{}' to {}: body read error after {}ms: {}",
                    rpc_method,
                    self.url,
                    t_start.elapsed().as_millis(),
                    e
                );
                return Err(e.into());
            }
        };

        log::debug!(
            "hang-debug: RpcClient::send '{}' to {}: completed in {}ms total",
            rpc_method,
            self.url,
            t_start.elapsed().as_millis()
        );

        Ok(from_reader(Buf::reader(body))?)
    }
}

#[test]
fn test_new() {
    let actual = RpcClient::new(String::from("dummy-value"));
    let expected = RpcClient {
        url: String::from("dummy-value"),
    };

    assert_eq!(actual, expected);
}

#[tokio::test]
async fn test_send() {
    let rpc_client = RpcClient::new(String::from("https://api.mainnet-beta.solana.com"));
    let cfg = ctx::get_app_config_test_instance();

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id":1,
        "method":"getHealth"
    });

    let res = rpc_client.send(&cfg, payload.clone(), false).await.unwrap();

    let expected_res = serde_json::json!({
        "jsonrpc": "2.0",
        "result": "ok",
        "id": 1
    });

    assert_eq!(res, expected_res);

    let res = rpc_client.send(&cfg, payload, false).await.unwrap();

    assert_eq!(res, expected_res);
}

#[test]
fn payload_serialzation_and_deserialization() {
    let json_payload = serde_json::json!({
        "method": "dummy-value",
        "params": [],
        "id": 1,
        "jsonrpc": "2.0"
    });

    let actual_payload: RpcPayload = serde_json::from_str(&json_payload.to_string()).unwrap();

    let expected_payload = RpcPayload {
        method: String::from("dummy-value"),
        params: serde_json::json!([]),
        id: Id::Number(1),
        jsonrpc: String::from("2.0"),
    };

    assert_eq!(actual_payload, expected_payload);

    // Backwards
    let json = serde_json::to_value(expected_payload).unwrap();
    assert_eq!(json_payload, json);
    assert_eq!(json_payload.to_string(), json.to_string());
}

#[test]
fn string_id_serialzation_and_deserialization() {
    let json_payload = serde_json::json!({
        "method": "dummy-value",
        "params": [],
        "id": "string-id-123",
        "jsonrpc": "2.0"
    });

    let deserialized: RpcPayload = serde_json::from_str(&json_payload.to_string()).unwrap();
    let expected_id = Id::String("string-id-123".into());

    assert_eq!(deserialized.id, expected_id);
}
