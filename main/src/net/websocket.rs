use std::time::Duration;

use futures_util::{FutureExt, SinkExt, StreamExt};
use hyper::{header::HeaderValue, Body, Request, upgrade, Response};
use log::{error, info};
use tokio::{io, net::TcpListener, sync, time};
use tokio_tungstenite::{tungstenite::{handshake, Message, Error}, WebSocketStream};

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

    let _outbound_addr = 
        "wss://necessary-quaint-road.ethereum-sepolia.quiknode.pro/3173295b7544258f98517fac5bdaa8d02349594a";
    let response = match handshake::server::create_response_with_body(&req, || Body::empty()) {
        Ok(response) => {
            tokio::spawn(async move {
                match upgrade::on(&mut req).await {
                    Ok(upgraded) => {
                        let ws_stream = WebSocketStream::from_raw_socket(
                            upgraded,
                            tokio_tungstenite::tungstenite::protocol::Role::Server,
                            None,
                        )
                        .await;

                        let (ws_write, ws_read) = ws_stream.split();

                        match ws_read.forward(ws_write).await {
                            Ok(_) => {}
                            Err(Error::ConnectionClosed) => println!("TODO"),
                            Err(e) => println!("TODO"),
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

    // let (tx, _) = sync::broadcast::channel(10);

    // let bind_addr = "127.0.0.1:6678";
    // let downstream_addresses = [
    //     "wss://necessary-quaint-road.ethereum-sepolia.quiknode.pro/3173295b7544258f98517fac5bdaa8d02349594a",
    // ];

    // let server = TcpListener::bind(bind_addr).await?;
    // info!("Listening on {bind_addr}");

    // for addr in downstream_addresses {
    //     let tx = tx.clone();
    //     tokio::spawn(async move {
    //         loop {
    //             match tokio_tungstenite::connect_async(addr).await {
    //                 Ok((mut socket, _)) => {
    //                     info!("Outgoing connection to {addr}");
    //                     time::sleep(Duration::from_secs(1)).await;
    //                     socket.send("{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"eth_subscribe\",\"params\":[\"newPendingTransactions\"]}".into()).await.unwrap();
    //                     socket
    //                         .for_each(|msg| async {
    //                             println!("oooooo {:?}", msg);
    //                             if let Ok(msg) = msg {
    //                                 tx.send(msg).ok();
    //                             }
    //                         })
    //                         .await;
    //                     info!("closed to {addr}");
    //                 }
    //                 e => {
    //                     panic!("{e:?}");
    //                 }
    //             }

    //             time::sleep(Duration::from_secs(1)).await;
    //         }
    //     });
    // }

    // while let Ok((stream, socket)) = server.accept().await {
    //     let mut rx = tx.subscribe();
    //     tokio::spawn(async move {
    //         info!("Open: {socket}");
    //         let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
    //         let mut keepalive_interval = time::interval(Duration::from_secs(30));
    //         loop {
    //             let msg = futures_util::select! {
    //                 _ = keepalive_interval.tick().fuse() => {
    //                     // Ensure that we don't let the WebSocket connection get timed out by
    //                     // sending a periodic ping
    //                     Some(Message::Ping(Vec::new()))
    //                 }
    //                 msg = rx.recv().fuse() => {
    //                     Some(msg.unwrap())
    //                 }
    //                 msg = websocket.next() => {
    //                     println!("msg {:?}", msg);
    //                     if msg.is_none() {
    //                         // Socket was closed
    //                         break;
    //                     }

    //                     websocket.send("{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"eth_subscribe\",\"params\":[\"newPendingTransactions\"]}".into()).await.unwrap();
    //                     None
    //                 }
    //             };

    //             println!("GOT MSG {:?}", msg);
    //             if let Some(msg) = msg {
    //                 if let Err(e) = websocket.send(msg).await {
    //                     error!("Send failed: {:?}", e);
    //                 }
    //             }
    //         }
    //         info!("Closed: {socket}");
    //     });
    // }

    // Ok(())
}
