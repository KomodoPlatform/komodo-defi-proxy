use std::time::Duration;

use futures_util::{FutureExt, SinkExt, StreamExt};
use hyper::{header::HeaderValue, upgrade, Body, Request, Response};
use log::{error, info};
use tokio::{io, net::TcpListener, sync, time};
use tokio_tungstenite::{
    tungstenite::{handshake, Error, Message},
    WebSocketStream,
};

use crate::GenericResult;

pub(crate) fn is_websocket_req(req: &Request<Body>) -> bool {
    let expected = HeaderValue::from_static("websocket");
    Some(&expected) == req.headers().get("upgrade")
}

// TODO
// Handle routing
// Manage connection pools (clean up memory once disconnected from the client)
// rename this function
pub(crate) async fn spawn_proxy(mut req: Request<Body>) -> GenericResult<Response<Body>> {
    let _inbound_route = req.uri().clone();

    let outbound_addr = "wss://necessary-quaint-road.ethereum-sepolia.quiknode.pro/3173295b7544258f98517fac5bdaa8d02349594a";
    let response = match handshake::server::create_response_with_body(&req, || Body::empty()) {
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
                                            outbound_socket.send(Message::Ping(Vec::new())).await.unwrap();
                                            inbound_socket.send(Message::Ping(Vec::new())).await.unwrap();
                                        }

                                        msg = outbound_socket.next() => {
                                            match msg {
                                                Some(Ok(msg)) => {
                                                    inbound_socket.send(msg).await.unwrap();
                                                },
                                                _ => {
                                                    break;
                                                }
                                            };
                                        },

                                        msg = inbound_socket.next() => {
                                            match msg {
                                                Some(Ok(msg)) => {
                                                    outbound_socket.send(msg).await.unwrap();
                                                },
                                                _ => {
                                                    break;
                                                }
                                            };
                                        }
                                    };
                                }
                            }
                            e => {
                                panic!("{e:?}");
                            }
                        };
                    }
                    Err(e) => println!("TODO"),
                }
            });

            response
        }
        Err(error) => {
            // TODO
            panic!("{error:?}")
        }
    };

    Ok(response)
}
