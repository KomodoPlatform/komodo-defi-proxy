use super::*;
use ctx::AppConfig;
use http::RpcPayload;
use rpc::Json;
use serde_json::json;
use sign::SignOps;

pub(crate) enum ProofOfFundingError {
    InvalidSignedMessage,
    RpcClientNotFound,
    InsufficientBalance,
    ErrorFromRpcCall,
    RpcCallFailed,
}

pub(crate) async fn verify_message_and_balance(
    cfg: &AppConfig,
    payload: &RpcPayload,
) -> Result<(), ProofOfFundingError> {
    if let Ok(true) = payload.signed_message.verify_message() {
        if let Some(rpc_client) = cfg.get_rpc_client(String::from("ETH")) {
            let rpc_payload = json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [payload.signed_message.address, "latest"]
            });

            match rpc_client.send(rpc_payload).await {
                Ok(res) if res["result"] != Json::Null && res["result"] != "0x0" => return Ok(()),
                Ok(res) if res["error"] != Json::Null => {
                    return Err(ProofOfFundingError::ErrorFromRpcCall);
                }
                Ok(_) => return Err(ProofOfFundingError::InsufficientBalance),
                Err(_) => return Err(ProofOfFundingError::RpcCallFailed),
            };
        };

        return Err(ProofOfFundingError::RpcClientNotFound);
    }

    Err(ProofOfFundingError::InvalidSignedMessage)
}
