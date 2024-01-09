use ctx::get_app_config;
use db::get_redis_connection;
use server::serve;

#[path = "security/address_status.rs"]
mod address_status;
mod ctx;
mod db;
#[path = "net/http.rs"]
mod http;
#[path = "security/jwt.rs"]
mod jwt;
#[path = "security/proof_of_funding.rs"]
mod proof_of_funding;
#[path = "security/rate_limiter.rs"]
mod rate_limiter;
#[path = "net/rpc.rs"]
mod rpc;
#[path = "net/server.rs"]
mod server;
#[path = "security/sign.rs"]
mod sign;
#[path = "net/websocket.rs"]
mod websocket;

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type GenericResult<T> = std::result::Result<T, GenericError>;

#[tokio::main]
async fn main() -> GenericResult<()> {
    simple_logger::SimpleLogger::new().env().init()?;

    let cfg = get_app_config();
    // to panic if redis is not available
    get_redis_connection(cfg).await;

    serve(cfg).await
}
