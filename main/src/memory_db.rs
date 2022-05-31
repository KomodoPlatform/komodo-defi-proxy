use crate::http::IpStatusPayload;

use super::*;
use async_trait::async_trait;
use redis::{aio::MultiplexedConnection, FromRedisValue};

pub const DB_STATUS_LIST: &str = "status_list";

static REDIS_CLIENT: OnceCell<redis::Client> = OnceCell::new();

pub fn get_redis_client() -> &'static redis::Client {
    let config = get_app_config();

    let client_closure = || {
        redis::Client::open(config.redis_connection_string.clone())
            .expect("Couldn't connect to redis server.")
    };

    REDIS_CLIENT.get_or_init(client_closure)
}

#[derive(Debug, Deserialize, PartialEq)]
pub enum IpStatus {
    /// Follow the normal procedure.
    None = -1,
    /// Means incoming request will be respond as `403 Forbidden`.
    Trusted,
    /// Means incoming request will bypass the security checks on the middleware layer.
    Blocked,
}

impl IpStatus {
    pub fn from_i8(value: i8) -> Self {
        match value {
            0 => Self::Trusted,
            1 => Self::Blocked,
            _ => Self::None,
        }
    }
}

impl FromRedisValue for IpStatus {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let val: i8 = redis::from_redis_value(v)?;

        Ok(IpStatus::from_i8(val))
    }
}

pub async fn get_redis_connection() -> MultiplexedConnection {
    let client = get_redis_client();

    client
        .get_multiplexed_tokio_connection()
        .await
        .expect("Couldn't get connection from redis client.")
}

pub struct Db {
    connection: MultiplexedConnection,
}

impl Db {
    pub async fn create_instance() -> Self {
        Self {
            connection: get_redis_connection().await,
        }
    }
}

#[async_trait]
pub trait IpStatusOperations {
    async fn insert_ip_status(&mut self, ip: String, status: IpStatus) -> Result<()>;
    async fn bulk_insert_ip_status(&mut self, payload: Vec<IpStatusPayload>) -> Result<()>;
    async fn read_ip_status(&mut self, ip: String) -> Result<IpStatus>;
    async fn read_ip_status_list(&mut self) -> Result<Vec<(String, i8)>>;
}

#[async_trait]
impl IpStatusOperations for Db {
    async fn insert_ip_status(&mut self, ip: String, status: IpStatus) -> Result<()> {
        Ok(redis::cmd("HSET")
            .arg(DB_STATUS_LIST)
            .arg(&[ip, format!("{}", status as i8)])
            .query_async(&mut self.connection)
            .await?)
    }

    async fn bulk_insert_ip_status(&mut self, payload: Vec<IpStatusPayload>) -> Result<()> {
        let mut pipe = redis::pipe();
        let formatted: Vec<(String, i8)> =
            payload.iter().map(|v| (v.ip.clone(), v.status)).collect();
        pipe.hset_multiple(DB_STATUS_LIST, &formatted);
        pipe.query_async(&mut self.connection).await?;

        Ok(())
    }

    async fn read_ip_status(&mut self, ip: String) -> Result<IpStatus> {
        match redis::cmd("HGET")
            .arg(DB_STATUS_LIST)
            .arg(ip)
            .query_async(&mut self.connection)
            .await
        {
            Ok(i) => Ok(i),
            Err(_) => Ok(IpStatus::None),
        }
    }

    async fn read_ip_status_list(&mut self) -> Result<Vec<(String, i8)>> {
        match redis::cmd("HGETALL")
            .arg(DB_STATUS_LIST)
            .query_async(&mut self.connection)
            .await
        {
            Ok(i) => Ok(i),
            Err(_) => Ok(Vec::new()),
        }
    }
}
