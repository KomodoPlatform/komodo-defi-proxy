use super::*;
use bytes::Buf;
use hyper::{body::aggregate, Body, Request};
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

    pub(crate) async fn send(&self, method: &str, payload: Json) -> GenericResult<Json> {
        let req = Request::builder()
            .method(method)
            .uri(&self.url)
            .body(Body::from(payload.to_string()))?;
        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build(https);

        let res = client.request(req).await?;
        let body = aggregate(res).await?;

        Ok(from_reader(Buf::reader(body))?)
    }
}

#[tokio::test]
async fn test_send() {
    let rpc_client = RpcClient::new(
        String::from("https://gist.githubusercontent.com/ozkanonur/459b25a35cf3d2c689511fbc565c5ce6/raw/de130316fb12c0dd76685090b8472abbd58fd157/test.json")
    );

    let res = rpc_client.send("GET", serde_json::json!({})).await.unwrap();

    let expected_res = serde_json::json!({
        "key1": "value",
        "key2": 6150,
    });

    assert_eq!(res, expected_res);
}
