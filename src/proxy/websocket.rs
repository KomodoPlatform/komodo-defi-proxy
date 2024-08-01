use std::{net::SocketAddr, time::Duration};

use futures_util::{FutureExt, SinkExt, StreamExt};
use hyper::{header::HeaderValue, upgrade, Body, Request, Response, StatusCode};
use tokio::time;
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, handshake, Message},
    WebSocketStream,
};

use crate::{
    ctx::AppConfig, http::response_by_status, log_format, rpc::RpcSocketPayload, GenericResult,
};

pub(crate) fn should_upgrade_to_socket_conn(req: &Request<Body>) -> bool {
    let expected = HeaderValue::from_static("websocket");
    Some(&expected) == req.headers().get("upgrade")
}

pub(crate) async fn socket_handler(
    cfg: AppConfig,
    mut req: Request<Body>,
    remote_addr: SocketAddr,
) -> GenericResult<Response<Body>> {
    let inbound_route = req.uri().path().to_string();
    let proxy_route = match cfg.get_proxy_route_by_inbound(&inbound_route) {
        Some(proxy_route) => proxy_route.clone(),
        None => {
            log::warn!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    String::from("-"),
                    req.uri(),
                    "Proxy route not found for socket, returning 404."
                )
            );
            return response_by_status(StatusCode::NOT_FOUND);
        }
    };

    let mut outbound_req = proxy_route.outbound_route.clone().into_client_request()?;

    if proxy_route.authorized {
        // modify outgoing request
        if crate::http::insert_jwt_to_http_header(&cfg, outbound_req.headers_mut())
            .await
            .is_err()
        {
            log::error!(
                "{}",
                log_format!(
                    remote_addr.ip(),
                    String::from("-"),
                    req.uri(),
                    "Proxy route not found for socket"
                )
            );

            return response_by_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    match handshake::server::create_response_with_body(&req, Body::empty) {
        Ok(response) => {
            tokio::spawn(async move {
                match upgrade::on(&mut req).await {
                    Ok(upgraded) => {
                        let mut inbound_socket = WebSocketStream::from_raw_socket(
                            upgraded,
                            tokio_tungstenite::tungstenite::protocol::Role::Server,
                            None,
                        )
                        .await;

                        match tokio_tungstenite::connect_async(outbound_req).await {
                            Ok((mut outbound_socket, _)) => {
                                let mut keepalive_interval =
                                    time::interval(Duration::from_secs(10));

                                loop {
                                    #[rustfmt::skip]
                                    futures_util::select! {
                                        _ = keepalive_interval.tick().fuse() => {
                                            if let Err(e) = outbound_socket.send(Message::Ping(Vec::new())).await {
                                                log::error!(
                                                    "{}",
                                                    log_format!(
                                                        remote_addr.ip(),
                                                        String::from("-"),
                                                        req.uri(),
                                                        "{:?}",
                                                        e
                                                    )
                                                );
                                            };

                                            if let Err(e) = inbound_socket.send(Message::Ping(Vec::new())).await {
                                                log::error!(
                                                    "{}",
                                                    log_format!(
                                                        remote_addr.ip(),
                                                        String::from("-"),
                                                        req.uri(),
                                                        "{:?}",
                                                        e
                                                    )
                                                );
                                            }
                                        }

                                        msg = outbound_socket.next() => {
                                            match msg {
                                                Some(Ok(msg)) => {
                                                    if let Err(e) = inbound_socket.send(msg).await {
                                                        log::error!(
                                                            "{}",
                                                            log_format!(
                                                                remote_addr.ip(),
                                                                String::from("-"),
                                                                req.uri(),
                                                                "{:?}",
                                                                e
                                                            )
                                                        );
                                                    };
                                                },
                                                _ => break,
                                            };
                                        },

                                        msg = inbound_socket.next() => {
                                            match msg {
                                                Some(Ok(msg)) => {
                                                    if let Message::Text(msg) = msg {
                                                         let socket_payload: RpcSocketPayload = match serde_json::from_str(&msg) {
                                                             Ok(t) => t,
                                                             Err(e) => {
                                                                 if let Err(e) = inbound_socket.send(format!("Invalid payload. {e}").into()).await {
                                                                     log::error!(
                                                                         "{}",
                                                                         log_format!(
                                                                             remote_addr.ip(),
                                                                             String::from("-"),
                                                                             req.uri(),
                                                                             "{:?}",
                                                                             e
                                                                         )
                                                                     );
                                                                 };
                                                                 continue;
                                                             },
                                                         };
                                                        let (payload, signed_message) = socket_payload.into_parts();

                                                        if !proxy_route.allowed_rpc_methods.contains(&payload.method) {
                                                             if let Err(e) = inbound_socket.send("Method not allowed.".into()).await {
                                                                 log::error!(
                                                                     "{}",
                                                                     log_format!(
                                                                         remote_addr.ip(),
                                                                         String::from("-"),
                                                                         req.uri(),
                                                                         "{:?}",
                                                                         e
                                                                     )
                                                                 );
                                                             };
                                                             continue;
                                                        }

                                                        match crate::proxy::http::validation_middleware(
                                                            &cfg,
                                                            &signed_message,
                                                            &proxy_route,
                                                            req.uri(),
                                                            &remote_addr,
                                                        )
                                                        .await
                                                        {
                                                             Ok(_) => {
                                                                 let msg = serde_json::json!({
                                                                     "method": payload.method,
                                                                     "params": payload.params,
                                                                     "id": payload.id,
                                                                     "jsonrpc": payload.jsonrpc
                                                                 })
                                                                 .to_string();

                                                                 if let Err(e) = outbound_socket.send(msg.into()).await {
                                                                     log::error!(
                                                                         "{}",
                                                                         log_format!(
                                                                             remote_addr.ip(),
                                                                             String::from("-"),
                                                                             req.uri(),
                                                                             "{:?}",
                                                                             e
                                                                         )
                                                                     );
                                                                 };

                                                             },
                                                             Err(status_code) => {
                                                                 if let Err(e) = inbound_socket.send(format!("{status_code}").into()).await {
                                                                     log::error!(
                                                                         "{}",
                                                                         log_format!(
                                                                             remote_addr.ip(),
                                                                             String::from("-"),
                                                                             req.uri(),
                                                                             "{:?}",
                                                                             e
                                                                         )
                                                                     );
                                                                 };
                                                             }
                                                        }
                                                    } else if let Err(e) = outbound_socket.send(msg).await {
                                                        log::error!(
                                                            "{}",
                                                            log_format!(
                                                                remote_addr.ip(),
                                                                String::from("-"),
                                                                req.uri(),
                                                                "{:?}",
                                                                e
                                                            )
                                                        );
                                                    }
                                                },
                                                _ => break
                                            };
                                        }
                                    }
                                }
                            }
                            e => {
                                log::error!(
                                    "{}",
                                    log_format!(
                                        remote_addr.ip(),
                                        String::from("-"),
                                        req.uri(),
                                        "{:?}",
                                        e
                                    )
                                );
                            }
                        };
                    }
                    Err(e) => {
                        log::error!(
                            "{}",
                            log_format!(remote_addr.ip(), String::from("-"), req.uri(), "{}", e)
                        );
                    }
                }
            });

            Ok(response)
        }
        Err(e) => {
            log::error!(
                "{}",
                log_format!(remote_addr.ip(), String::from("-"), req.uri(), "{}", e)
            );
            response_by_status(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}
