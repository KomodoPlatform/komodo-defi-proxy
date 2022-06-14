use super::*;
use ctx::AppConfig;
use once_cell::sync::OnceCell;
use redis::aio::MultiplexedConnection;

static REDIS_CLIENT: OnceCell<redis::Client> = OnceCell::new();

pub(crate) fn get_redis_client(config: &AppConfig) -> &'static redis::Client {
    let client_closure = || {
        redis::Client::open(config.redis_connection_string.clone())
            .expect("Couldn't connect to redis server.")
    };

    REDIS_CLIENT.get_or_init(client_closure)
}

pub(crate) async fn get_redis_connection(config: &AppConfig) -> MultiplexedConnection {
    let client = get_redis_client(config);

    client
        .get_multiplexed_tokio_connection()
        .await
        .expect("Couldn't get connection from redis client.")
}

pub(crate) struct Db {
    pub(crate) connection: MultiplexedConnection,
}

impl Db {
    pub(crate) async fn create_instance(config: &AppConfig) -> Self {
        Self {
            connection: get_redis_connection(config).await,
        }
    }
}

impl Db {
    pub(crate) async fn key_exists(&mut self, key: &str) -> GenericResult<bool> {
        Ok(redis::cmd("EXISTS")
            .arg(key)
            .query_async(&mut self.connection)
            .await?)
    }
}
