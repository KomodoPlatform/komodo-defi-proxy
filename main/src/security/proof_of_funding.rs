use super::*;
use ctx::AppConfig;
use http::RpcPayload;
use rpc::Json;
use serde_json::json;
use sign::SignOps;
use crate::ctx::Node;

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

#[test]
fn test_proof_of_funding() {
    use crate::ctx::get_app_config_test_instance;
    use crate::sign::SignedMessage;

    let mut cfg = get_app_config_test_instance();
    cfg.nodes = vec![Node {
        name: "ETH".to_string(),
        url: "http://eth1.cipig.net:8555".to_string(),
        authorized: false
    }];

    let mut signed_message = SignedMessage {
        address: String::from("0x0000000000000000000000000000000000000000"),
        timestamp_message: 1974527831,
        signature: String::new(),
        coin_ticker: String::from("ETH"),
    };

    let random_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

    let key_pair = ethkey::KeyPair::from_secret_slice(
        random_key.as_ref(),
    )
        .unwrap();
    
    signed_message.sign_message(key_pair.secret()).unwrap();
    
    let payload = RpcPayload {
        method: "".to_string(),
        params: Default::default(),
        id: 0,
        jsonrpc: "".to_string(),
        signed_message
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(verify_message_and_balance(&cfg, &payload)).unwrap();
}
