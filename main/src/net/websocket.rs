use std::{net::SocketAddr, time::Duration};

use futures_util::{FutureExt, SinkExt, StreamExt};
use hyper::{header::HeaderValue, upgrade, Body, Request, Response, StatusCode};
use tokio::time;
use tokio_tungstenite::{
    tungstenite::{handshake, Message},
    WebSocketStream,
};

use crate::{ctx::AppConfig, http::response_by_status, log_format, GenericResult};

pub(crate) fn should_upgrade_to_socket_conn(req: &Request<Body>) -> bool {
    let expected = HeaderValue::from_static("websocket");
    Some(&expected) == req.headers().get("upgrade")
}

pub(crate) async fn socket_handler(
    cfg: &AppConfig,
    mut req: Request<Body>,
    remote_addr: SocketAddr,
) -> GenericResult<Response<Body>> {
    let inbound_route = req.uri().to_string();
    let proxy_route = match cfg.get_proxy_route_by_inbound(inbound_route) {
        Some(proxy_route) => proxy_route,
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

    let outbound_addr = proxy_route.outbound_route.clone();

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

                        match tokio_tungstenite::connect_async(outbound_addr).await {
                            Ok((mut outbound_socket, _)) => {
                                let mut keepalive_interval =
                                    time::interval(Duration::from_secs(10));

                                loop {
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
                                                    if let Err(e) = outbound_socket.send(msg).await {
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
                                                _ => break
                                            };
                                        }
                                    };
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
