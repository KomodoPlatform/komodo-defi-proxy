use super::*;

use bytes::Buf;
use ctx::AppConfig;
use http::insert_jwt_to_http_header;
use hyper::{body::aggregate, header, Body, Request};
use hyper_tls::HttpsConnector;
use serde_json::from_reader;

pub(crate) type Json = serde_json::Value;

#[derive(Debug, PartialEq)]
pub(crate) struct RpcClient {
    pub(crate) url: String,
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
            .append(header::CONTENT_TYPE, "application/json".parse()?);

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
