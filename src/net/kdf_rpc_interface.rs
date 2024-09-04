use crate::{ctx::AppConfig, GenericResult};

pub(crate) async fn version_rpc(cfg: &AppConfig) -> GenericResult<serde_json::Value> {
    let payload = serde_json::json!({
        "userpass": cfg.kdf_rpc_password,
        "method": "version",
    });

    cfg.kdf_rpc_client.send(cfg, payload, false).await
}

pub(crate) async fn peer_connection_healthcheck_rpc(
    cfg: &AppConfig,
    peer_id: &str,
) -> GenericResult<serde_json::Value> {
    let payload = serde_json::json!({
        "userpass": cfg.kdf_rpc_password,
        "method": "peer_connection_healthcheck",
        "mmrpc": "2.0",
        "params": {
            "peer_id": peer_id
        }
    });

    cfg.kdf_rpc_client.send(cfg, payload, false).await
}
