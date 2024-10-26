use ctx::get_app_config;
use db::get_redis_connection;
use kdf_rpc_interface::version_rpc;
use server::serve;

#[path = "security/address_status.rs"]
mod address_status;
mod ctx;
mod db;
#[path = "security/jwt.rs"]
mod jwt;
#[path = "net/kdf_rpc_interface.rs"]
mod kdf_rpc_interface;
mod logger;
mod proxy;
#[path = "security/rate_limiter.rs"]
mod rate_limiter;
#[path = "net/rpc.rs"]
mod rpc;
#[path = "net/server.rs"]
mod server;

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// A type alias for a generic error, encompassing any error that implements the `Error` trait,
/// along with traits for thread-safe error handling (`Send` and `Sync`).
/// This type is typically used across the application to handle errors uniformly.
pub(crate) type GenericError = Box<dyn std::error::Error + Send + Sync>;
/// A type alias for a generic result, used throughout the application to encapsulate the
/// outcome of operations that might fail with a `GenericError`.
pub(crate) type GenericResult<T> = std::result::Result<T, GenericError>;

#[tokio::main]
async fn main() -> GenericResult<()> {
    simple_logger::SimpleLogger::new().env().init()?;

    let cfg = get_app_config();
    // to panic if redis is not available
    get_redis_connection(cfg).await;

    version_rpc(cfg).await.expect("KDF is not available.");

    serve(cfg).await
}
