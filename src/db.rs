use ctx::AppConfig;
use once_cell::sync::OnceCell;
use redis::aio::MultiplexedConnection;

use super::*;

static REDIS_CLIENT: OnceCell<redis::Client> = OnceCell::new();

pub(crate) fn get_redis_client(cfg: &AppConfig) -> &'static redis::Client {
    let client_closure = || {
        redis::Client::open(cfg.redis_connection_string.clone())
            .expect("Couldn't connect to redis server.")
    };

    REDIS_CLIENT.get_or_init(client_closure)
}

pub(crate) async fn get_redis_connection(cfg: &AppConfig) -> MultiplexedConnection {
    let client = get_redis_client(cfg);

    let t_start = std::time::Instant::now();
    let connection = client
        .get_multiplexed_tokio_connection()
        .await
        .map_err(|e| e.to_string())
        .expect("Couldn't get connection from redis client.");
    log::debug!(
        "hang-debug: redis multiplexed connection obtained in {}ms",
        t_start.elapsed().as_millis()
    );

    connection
}

pub(crate) struct Db {
    pub(crate) connection: MultiplexedConnection,
}

impl Db {
    pub(crate) async fn create_instance(cfg: &AppConfig) -> Self {
        Self {
            connection: get_redis_connection(cfg).await,
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn key_exists(&mut self, key: &str) -> GenericResult<bool> {
        Ok(redis::cmd("EXISTS")
            .arg(key)
            .query_async(&mut self.connection)
            .await?)
    }

    #[allow(dead_code)]
    pub(crate) async fn insert_cache(
        &mut self,
        key: &str,
        value: &str,
        seconds: usize,
    ) -> GenericResult<()> {
        redis::cmd("SETEX")
            .arg(key)
            .arg(seconds)
            .arg(value)
            .query_async::<_, ()>(&mut self.connection)
            .await?;

        Ok(())
    }
}
