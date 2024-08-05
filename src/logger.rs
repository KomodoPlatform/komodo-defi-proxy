use std::fmt::Display;

use log::Level;

macro_rules! log_format {
  ($ip: expr, $address: expr, $path: expr, $format: expr, $($args: tt)+) => {format!(concat!("[Ip: {} | Peer: {} | Endpoint: {}] ", $format), $ip, $address, $path, $($args)+)};
  ($ip: expr, $address: expr, $path: expr, $format: expr) => {format!(concat!("[Ip: {} | Peer: {} | Endpoint: {}] ", $format), $ip, $address, $path)}
}

pub(crate) fn tracked_log<Ip, PeerAddress, Endpoint, Message>(
    log_level: Level,
    ip: Ip,
    peer_address: PeerAddress,
    endpoint: Endpoint,
    message: Message,
) where
    Ip: Display,
    PeerAddress: Display,
    Endpoint: Display,
    Message: Display,
{
    log::log!(
        log_level,
        "{}",
        log_format!(ip, peer_address, endpoint, "{}", message)
    );
}
