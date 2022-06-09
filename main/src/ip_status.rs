use super::*;
use async_trait::async_trait;
use bytes::Buf;
use db::Db;
use hyper::{header, Body, Request, Response, StatusCode};
use redis::FromRedisValue;
use serde::{Deserialize, Serialize};

pub const DB_STATUS_LIST: &str = "status_list";

#[derive(Debug, Serialize, Deserialize)]
pub struct IpStatusPayload {
    pub ip: String,
    pub status: i8,
}

pub async fn post_ip_status(req: Request<Body>) -> GenericResult<Response<Body>> {
    let whole_body = hyper::body::aggregate(req).await?;
    let payload: Vec<IpStatusPayload> = serde_json::from_reader(whole_body.reader())?;

    let mut db = Db::create_instance().await;
    db.bulk_insert_ip_status(payload).await?;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(Vec::new()))
        .unwrap())
}

pub async fn get_ip_status_list() -> GenericResult<Response<Body>> {
    let mut db = Db::create_instance().await;
    let list = db.read_ip_status_list().await?;

    let list: Vec<IpStatusPayload> = list
        .iter()
        .map(|v| IpStatusPayload {
            ip: v.0.clone(),
            status: v.1,
        })
        .collect();
    let serialized = serde_json::to_string(&list).unwrap();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serialized))
        .unwrap())
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

#[async_trait]
pub trait IpStatusOperations {
    async fn insert_ip_status(&mut self, ip: String, status: IpStatus) -> GenericResult<()>;
    async fn bulk_insert_ip_status(&mut self, payload: Vec<IpStatusPayload>) -> GenericResult<()>;
    async fn read_ip_status(&mut self, ip: String) -> GenericResult<IpStatus>;
    async fn read_ip_status_list(&mut self) -> GenericResult<Vec<(String, i8)>>;
}

#[async_trait]
impl IpStatusOperations for Db {
    async fn insert_ip_status(&mut self, ip: String, status: IpStatus) -> GenericResult<()> {
        Ok(redis::cmd("HSET")
            .arg(DB_STATUS_LIST)
            .arg(&[ip, format!("{}", status as i8)])
            .query_async(&mut self.connection)
            .await?)
    }

    async fn bulk_insert_ip_status(&mut self, payload: Vec<IpStatusPayload>) -> GenericResult<()> {
        let mut pipe = redis::pipe();
        let formatted: Vec<(String, i8)> =
            payload.iter().map(|v| (v.ip.clone(), v.status)).collect();
        pipe.hset_multiple(DB_STATUS_LIST, &formatted);
        pipe.query_async(&mut self.connection).await?;

        Ok(())
    }

    async fn read_ip_status(&mut self, ip: String) -> GenericResult<IpStatus> {
        Ok(redis::cmd("HGET")
            .arg(DB_STATUS_LIST)
            .arg(ip)
            .query_async(&mut self.connection)
            .await
            .unwrap_or(IpStatus::None))
    }

    async fn read_ip_status_list(&mut self) -> GenericResult<Vec<(String, i8)>> {
        Ok(redis::cmd("HGETALL")
            .arg(DB_STATUS_LIST)
            .query_async(&mut self.connection)
            .await
            .unwrap_or_default())
    }
}
