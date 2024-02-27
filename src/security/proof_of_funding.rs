use ctx::{AppConfig, ProxyRoute};
use db::Db;
use http::RpcPayload;
use rpc::Json;
use serde_json::json;
use sign::SignOps;

use super::*;

#[derive(Debug)]
pub(crate) enum ProofOfFundingError {
    InvalidSignedMessage,
    InsufficientBalance,
    ErrorFromRpcCall,
    #[allow(dead_code)]
    RpcCallFailed(String),
}

pub(crate) async fn verify_message_and_balance(
    cfg: &AppConfig,
    payload: &RpcPayload,
    proxy_route: &ProxyRoute,
) -> Result<(), ProofOfFundingError> {
    if let Ok(true) = payload.signed_message.verify_message() {
        let mut db = Db::create_instance(cfg).await;

        // We don't want to send balance requests everytime when user sends requests.
        if let Ok(true) = db.key_exists(&payload.signed_message.address).await {
            return Ok(());
        }

        let rpc_payload = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [payload.signed_message.address, "latest"]
        });

        let rpc_client =
            // TODO: Use the current transport instead of forcing to use http (even if it's rare, this might not work on certain nodes)
            rpc::RpcClient::new(proxy_route.outbound_route.replace("ws", "http").clone());

        match rpc_client
            .send(cfg, rpc_payload, proxy_route.authorized)
            .await
        {
            Ok(res) if res["result"] != Json::Null && res["result"] != "0x0" => {
                // cache this address for 60 seconds
                let _ = db
                    .insert_cache(&payload.signed_message.address, "", 60)
                    .await;

                return Ok(());
            }
            Ok(res) if res["error"] != Json::Null => {
                return Err(ProofOfFundingError::ErrorFromRpcCall);
            }
            Ok(_) => return Err(ProofOfFundingError::InsufficientBalance),
            Err(e) => return Err(ProofOfFundingError::RpcCallFailed(e.to_string())),
        };
    }

    Err(ProofOfFundingError::InvalidSignedMessage)
}
