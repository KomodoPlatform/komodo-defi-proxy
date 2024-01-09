use async_trait::async_trait;
use bytes::Buf;
use ctx::AppConfig;
use db::Db;
use hyper::{header, Body, Request, Response, StatusCode};
use redis::FromRedisValue;
use serde::{Deserialize, Serialize};

use super::*;

pub(crate) const DB_STATUS_LIST: &str = "status_list";

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct AddressStatusPayload {
    pub(crate) address: String,
    pub(crate) status: i8,
}

pub(crate) async fn post_address_status(
    cfg: &AppConfig,
    req: Request<Body>,
) -> GenericResult<Response<Body>> {
    let whole_body = hyper::body::aggregate(req).await?;
    let payload: Vec<AddressStatusPayload> = serde_json::from_reader(whole_body.reader())?;

    let mut db = Db::create_instance(cfg).await;
    db.bulk_insert_address_status(payload).await?;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(Vec::new()))?)
}

pub(crate) async fn get_address_status_list(cfg: &AppConfig) -> GenericResult<Response<Body>> {
    let mut db = Db::create_instance(cfg).await;
    let list = db.read_address_status_list().await;

    let list: Vec<AddressStatusPayload> = list
        .iter()
        .map(|v| AddressStatusPayload {
            address: v.0.clone(),
            status: v.1,
        })
        .collect();
    let serialized = serde_json::to_string(&list)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serialized))?)
}

#[derive(Debug, Deserialize, PartialEq)]
pub(crate) enum AddressStatus {
    /// Follow the normal procedure.
    None = -1,
    /// Means incoming request will be respond as `403 Forbidden`.
    Trusted,
    /// Means incoming request will bypass the security checks on the middleware layer.
    Blocked,
}

impl AddressStatus {
    pub(crate) fn from_i8(value: i8) -> Self {
        match value {
            0 => Self::Trusted,
            1 => Self::Blocked,
            _ => Self::None,
        }
    }
}

impl FromRedisValue for AddressStatus {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let val: i8 = redis::from_redis_value(v)?;

        Ok(AddressStatus::from_i8(val))
    }
}

#[async_trait]
pub(crate) trait AddressStatusOperations {
    async fn insert_address_status(
        &mut self,
        address: String,
        status: AddressStatus,
    ) -> GenericResult<()>;
    async fn bulk_insert_address_status(
        &mut self,
        payload: Vec<AddressStatusPayload>,
    ) -> GenericResult<()>;
    async fn read_address_status(&mut self, address: String) -> AddressStatus;
    async fn read_address_status_list(&mut self) -> Vec<(String, i8)>;
}

#[async_trait]
impl AddressStatusOperations for Db {
    async fn insert_address_status(
        &mut self,
        address: String,
        status: AddressStatus,
    ) -> GenericResult<()> {
        Ok(redis::cmd("HSET")
            .arg(DB_STATUS_LIST)
            .arg(&[address, format!("{}", status as i8)])
            .query_async(&mut self.connection)
            .await?)
    }

    async fn bulk_insert_address_status(
        &mut self,
        payload: Vec<AddressStatusPayload>,
    ) -> GenericResult<()> {
        let mut pipe = redis::pipe();
        let formatted: Vec<(String, i8)> = payload
            .iter()
            .map(|v| (v.address.clone(), v.status))
            .collect();
        pipe.hset_multiple(DB_STATUS_LIST, &formatted);
        pipe.query_async(&mut self.connection).await?;

        Ok(())
    }

    async fn read_address_status(&mut self, address: String) -> AddressStatus {
        redis::cmd("HGET")
            .arg(DB_STATUS_LIST)
            .arg(address)
            .query_async(&mut self.connection)
            .await
            .unwrap_or(AddressStatus::None)
    }

    async fn read_address_status_list(&mut self) -> Vec<(String, i8)> {
        redis::cmd("HGETALL")
            .arg(DB_STATUS_LIST)
            .query_async(&mut self.connection)
            .await
            .unwrap_or_default()
    }
}

#[test]
fn test_address_status_constants() {
    assert_eq!(DB_STATUS_LIST, "status_list");
}

#[test]
fn test_address_status_serialzation_and_deserialization() {
    let json_address_status = serde_json::json!({
        "address": "0xbAB36286672fbdc7B250804bf6D14Be0dF69fa29",
        "status": 0
    });

    let actual_address_status: AddressStatusPayload =
        serde_json::from_str(&json_address_status.to_string()).unwrap();

    let expected_address_status = AddressStatusPayload {
        address: String::from("0xbAB36286672fbdc7B250804bf6D14Be0dF69fa29"),
        status: 0,
    };

    assert_eq!(actual_address_status, expected_address_status);

    // Backwards
    let json = serde_json::to_value(expected_address_status).unwrap();
    assert_eq!(json_address_status, json);
    assert_eq!(json_address_status.to_string(), json.to_string());
}

#[test]
fn test_if_address_status_values_same_as_before() {
    assert_eq!(AddressStatus::None, AddressStatus::from_i8(-1));
    assert_eq!(AddressStatus::Trusted, AddressStatus::from_i8(0));
    assert_eq!(AddressStatus::Blocked, AddressStatus::from_i8(1));
}

#[test]
fn test_from_redis_value() {
    let redis_val = redis::Value::Int(-1);
    let val: AddressStatus = redis::from_redis_value(&redis_val).unwrap();
    assert_eq!(val, AddressStatus::None);

    let redis_val = redis::Value::Int(0);
    let val: AddressStatus = redis::from_redis_value(&redis_val).unwrap();
    assert_eq!(val, AddressStatus::Trusted);

    let redis_val = redis::Value::Int(1);
    let val: AddressStatus = redis::from_redis_value(&redis_val).unwrap();
    assert_eq!(val, AddressStatus::Blocked);
}
