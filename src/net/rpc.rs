#![allow(dead_code)] // We will need this module for KDF RPCs

use bytes::Buf;
use ctx::AppConfig;
use http::{insert_jwt_to_http_header, APPLICATION_JSON};
use hyper::{body::aggregate, header, Body, Request};
use hyper_tls::HttpsConnector;
use proxy_signature::ProxySign;
use serde::{Deserialize, Serialize};
use serde_json::from_reader;

use super::*;

pub(crate) type Json = serde_json::Value;

#[derive(Debug, PartialEq)]
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
    pub(crate) params: serde_json::value::Value,
    pub(crate) id: Id,
    pub(crate) jsonrpc: String,
}

/// Used for websocket connection.
/// It combines standard JSON RPC method call fields (method, params, id, jsonrpc) with a `SignedMessage`
/// for authentication and validation, facilitating secure and validated interactions with the Quicknode service.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct RpcSocketPayload {
    pub(crate) method: String,
    pub(crate) params: serde_json::value::Value,
    pub(crate) id: Id,
    pub(crate) jsonrpc: String,
    pub(crate) proxy_sign: ProxySign,
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
        payload: Json,
        is_authorized: bool,
    ) -> GenericResult<Json> {
        let mut req = Request::post(&self.url).body(Body::from(payload.to_string()))?;
        req.headers_mut()
            .append(header::CONTENT_TYPE, APPLICATION_JSON.parse()?);

        if is_authorized {
            insert_jwt_to_http_header(cfg, req.headers_mut()).await?;
        }

        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build(https);

        let res = client.request(req).await?;
        let body = aggregate(res).await?;

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
