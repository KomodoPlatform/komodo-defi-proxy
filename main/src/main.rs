#![feature(ip)]

use db::get_redis_connection;
use http::serve;

mod ctx;
mod db;
mod http;
mod ip_status;
mod jwt;
mod rate_limiter;
mod sign;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type GenericResult<T> = std::result::Result<T, GenericError>;

#[tokio::main]
async fn main() -> GenericResult<()> {
    // to panic if redis is not available
    get_redis_connection().await;

    serve().await
}
