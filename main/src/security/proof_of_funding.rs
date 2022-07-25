use super::*;
use ctx::AppConfig;
use http::RpcPayload;
use rpc::Json;
use serde_json::json;
use sign::SignOps;

#[derive(Debug)]
pub(crate) enum ProofOfFundingError {
    InvalidSignedMessage,
    RpcClientNotFound,
    InsufficientBalance,
    ErrorFromRpcCall,
    RpcCallFailed(String),
}

pub(crate) async fn verify_message_and_balance(
    cfg: &AppConfig,
    payload: &RpcPayload,
) -> Result<(), ProofOfFundingError> {
    if let Ok(true) = payload.signed_message.verify_message() {
        if let Some(node) = cfg.get_node(payload.signed_message.coin_ticker.clone()) {
            let rpc_payload = json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [payload.signed_message.address, "latest"]
            });

            let rpc_client = rpc::RpcClient::new(node.url.clone());

            match rpc_client.send(cfg, rpc_payload, node.authorized).await {
                Ok(res) if res["result"] != Json::Null && res["result"] != "0x0" => return Ok(()),
                Ok(res) if res["error"] != Json::Null => {
                    return Err(ProofOfFundingError::ErrorFromRpcCall);
                }
                Ok(_) => return Err(ProofOfFundingError::InsufficientBalance),
                Err(e) => return Err(ProofOfFundingError::RpcCallFailed(e.to_string())),
            };
        };

        return Err(ProofOfFundingError::RpcClientNotFound);
    }

    Err(ProofOfFundingError::InvalidSignedMessage)
}
