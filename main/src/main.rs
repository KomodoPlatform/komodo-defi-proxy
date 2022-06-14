#![feature(ip)]

use ctx::get_app_config;
use db::get_redis_connection;
use http::serve;

mod ctx;
mod db;
mod http;
mod ip_status;
mod jwt;
mod proof_of_funding;
mod rate_limiter;
mod rpc;
mod sign;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type GenericResult<T> = std::result::Result<T, GenericError>;

#[tokio::main]
async fn main() -> GenericResult<()> {
    let cfg = get_app_config();
    // to panic if redis is not available
    get_redis_connection(&cfg).await;

    serve(&cfg).await
}
