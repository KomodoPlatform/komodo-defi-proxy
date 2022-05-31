use super::*;
use crate::http::IpStatusPayload;
use async_trait::async_trait;
use redis::{aio::MultiplexedConnection, FromRedisValue, Pipeline};

pub const DB_STATUS_LIST: &str = "status_list";

pub const DB_RP_1_MIN: &str = "rp:1_min";
pub const DB_RP_5_MIN: &str = "rp:5_min";
pub const DB_RP_15_MIN: &str = "rp:15_min";
pub const DB_RP_30_MIN: &str = "rp:30_min";
pub const DB_RP_60_MIN: &str = "rp:60_min";

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

impl Db {
    pub async fn key_exists(&mut self, key: &str) -> Result<bool> {
        Ok(redis::cmd("EXISTS")
            .arg(key)
            .query_async(&mut self.connection)
            .await?)
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
        Ok(redis::cmd("HGET")
            .arg(DB_STATUS_LIST)
            .arg(ip)
            .query_async(&mut self.connection)
            .await
            .unwrap_or(IpStatus::None))
    }

    async fn read_ip_status_list(&mut self) -> Result<Vec<(String, i8)>> {
        Ok(redis::cmd("HGETALL")
            .arg(DB_STATUS_LIST)
            .query_async(&mut self.connection)
            .await
            .unwrap_or_default())
    }
}

#[async_trait]
pub trait RateLimitOperations {
    async fn upsert_ip_rate_in_pipe(
        &mut self,
        pipe: &mut Pipeline,
        db: &str,
        ip: &str,
        expire_time: usize,
    ) -> Result<()>;
    async fn rate_ip(&mut self, ip: String) -> Result<()>;
    async fn did_exceed_in_single_time_frame(
        &mut self,
        db: &str,
        ip: &str,
        rate_limit: u16,
    ) -> Result<bool>;
    async fn rate_exceeded(&mut self, ip: String) -> Result<bool>;
}

#[async_trait]
impl RateLimitOperations for Db {
    async fn upsert_ip_rate_in_pipe(
        &mut self,
        pipe: &mut Pipeline,
        db: &str,
        ip: &str,
        expire_time: usize,
    ) -> Result<()> {
        if !self.key_exists(db).await? {
            pipe.hset(db, ip, "1").expire(db, expire_time);
        } else {
            pipe.cmd("HINCRBY").arg(db).arg(&[ip, "1"]);
        }

        Ok(())
    }

    /// semi-lazy IP rate implementation for 5 different time frames.
    async fn rate_ip(&mut self, ip: String) -> Result<()> {
        let mut pipe = redis::pipe();

        self.upsert_ip_rate_in_pipe(&mut pipe, DB_RP_1_MIN, &ip, 60)
            .await?;
        self.upsert_ip_rate_in_pipe(&mut pipe, DB_RP_5_MIN, &ip, 300)
            .await?;
        self.upsert_ip_rate_in_pipe(&mut pipe, DB_RP_15_MIN, &ip, 900)
            .await?;
        self.upsert_ip_rate_in_pipe(&mut pipe, DB_RP_30_MIN, &ip, 1800)
            .await?;
        self.upsert_ip_rate_in_pipe(&mut pipe, DB_RP_60_MIN, &ip, 3600)
            .await?;

        pipe.query_async(&mut self.connection).await?;

        Ok(())
    }

    async fn did_exceed_in_single_time_frame(
        &mut self,
        db: &str,
        ip: &str,
        rate_limit: u16,
    ) -> Result<bool> {
        let rate: u16 = redis::cmd("HGET")
            .arg(db)
            .arg(&ip)
            .query_async(&mut self.connection)
            .await
            .unwrap_or(0);
        if rate >= rate_limit {
            return Ok(true);
        }

        Ok(false)
    }

    async fn rate_exceeded(&mut self, ip: String) -> Result<bool> {
        let rate_limit_conf = &get_app_config().rate_limiter;

        if self
            .did_exceed_in_single_time_frame(DB_RP_1_MIN, &ip, rate_limit_conf.rp_1_min)
            .await?
        {
            return Ok(true);
        }

        if self
            .did_exceed_in_single_time_frame(DB_RP_5_MIN, &ip, rate_limit_conf.rp_5_min)
            .await?
        {
            return Ok(true);
        }

        if self
            .did_exceed_in_single_time_frame(DB_RP_15_MIN, &ip, rate_limit_conf.rp_15_min)
            .await?
        {
            return Ok(true);
        }

        if self
            .did_exceed_in_single_time_frame(DB_RP_30_MIN, &ip, rate_limit_conf.rp_30_min)
            .await?
        {
            return Ok(true);
        }

        if self
            .did_exceed_in_single_time_frame(DB_RP_60_MIN, &ip, rate_limit_conf.rp_60_min)
            .await?
        {
            return Ok(true);
        }

        Ok(false)
    }
}
