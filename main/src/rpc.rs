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

    pub(crate) async fn send(&self, payload: Json) -> GenericResult<Json> {
        let req = Request::post(&self.url).body(Body::from(payload.to_string()))?;
        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build(https);

        let res = client.request(req).await?;
        let body = aggregate(res).await?;

        Ok(from_reader(Buf::reader(body))?)
    }
}
