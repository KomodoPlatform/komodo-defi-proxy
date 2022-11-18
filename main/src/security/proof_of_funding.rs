use super::*;
use ctx::{AppConfig, ProxyRoute};
use http::RpcPayload;
use rpc::Json;
use serde_json::json;
use sign::SignOps;

#[derive(Debug)]
pub(crate) enum ProofOfFundingError {
    InvalidSignedMessage,
    InsufficientBalance,
    ErrorFromRpcCall,
    RpcCallFailed(String),
}

pub(crate) async fn verify_message_and_balance(
    cfg: &AppConfig,
    payload: &RpcPayload,
    proxy_route: &ProxyRoute,
) -> Result<(), ProofOfFundingError> {
    if let Ok(true) = payload.signed_message.verify_message() {
        let rpc_payload = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [payload.signed_message.address, "latest"]
        });

        let rpc_client = rpc::RpcClient::new(proxy_route.outbound_route.clone());

        match rpc_client
            .send(cfg, rpc_payload, proxy_route.authorized)
            .await
        {
            Ok(res) if res["result"] != Json::Null && res["result"] != "0x0" => return Ok(()),
            Ok(res) if res["error"] != Json::Null => {
                return Err(ProofOfFundingError::ErrorFromRpcCall);
            }
            Ok(_) => return Err(ProofOfFundingError::InsufficientBalance),
            Err(e) => return Err(ProofOfFundingError::RpcCallFailed(e.to_string())),
        };
    }

    Err(ProofOfFundingError::InvalidSignedMessage)
}
