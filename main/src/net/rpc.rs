use super::*;
use bytes::Buf;
use hyper::{body::aggregate, header, Body, Request};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json::from_reader;

pub(crate) type Json = serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RpcClient {
    pub(crate) url: String,
}

impl RpcClient {
    pub(crate) fn new(url: String) -> Self {
        RpcClient { url }
    }

    pub(crate) async fn send(&self, payload: Json) -> GenericResult<Json> {
        let mut req = Request::post(&self.url).body(Body::from(payload.to_string()))?;
        req.headers_mut()
            .append(header::CONTENT_TYPE, "application/json".parse()?);

        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build(https);

        let res = client.request(req).await?;
        let body = aggregate(res).await?;

        Ok(from_reader(Buf::reader(body))?)
    }
}

#[tokio::test]
async fn test_send() {
    let rpc_client = RpcClient::new(String::from("https://api.mainnet-beta.solana.com"));

    let res = rpc_client
        .send(serde_json::json!({
            "jsonrpc": "2.0",
            "id":1,
            "method":"getHealth"
        }))
        .await
        .unwrap();

    let expected_res = serde_json::json!({
        "jsonrpc": "2.0",
        "result": "ok",
        "id": 1
    });

    assert_eq!(res, expected_res);
}
