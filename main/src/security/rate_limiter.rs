use super::*;

use async_trait::async_trait;
use ctx::RateLimiter;
use db::Db;
use redis::Pipeline;

pub(crate) const DB_RP_1_MIN: &str = "rp:1_min";
pub(crate) const DB_RP_5_MIN: &str = "rp:5_min";
pub(crate) const DB_RP_15_MIN: &str = "rp:15_min";
pub(crate) const DB_RP_30_MIN: &str = "rp:30_min";
pub(crate) const DB_RP_60_MIN: &str = "rp:60_min";

#[async_trait]
pub(crate) trait RateLimitOperations {
    async fn upsert_address_rate_in_pipe(
        &mut self,
        pipe: &mut Pipeline,
        db: &str,
        address: &str,
        expire_time: usize,
    ) -> GenericResult<()>;
    async fn rate_address(&mut self, address: String) -> GenericResult<()>;
    async fn did_exceed_in_single_time_frame(
        &mut self,
        db: &str,
        address: &str,
        rate_limit: u16,
    ) -> GenericResult<bool>;
    async fn rate_exceeded(
        &mut self,
        address: String,
        rate_limiter_conf: &RateLimiter,
    ) -> GenericResult<bool>;
}

#[async_trait]
impl RateLimitOperations for Db {
    async fn upsert_address_rate_in_pipe(
        &mut self,
        pipe: &mut Pipeline,
        db: &str,
        address: &str,
        expire_time: usize,
    ) -> GenericResult<()> {
        if !self.key_exists(db).await? {
            pipe.hset(db, address, "1")
                .cmd("EXPIRE")
                .arg(db)
                .arg(expire_time)
                .arg("XX")
                .query_async(&mut self.connection)
                .await?;
        } else {
            pipe.cmd("HINCRBY")
                .arg(db)
                .arg(&[address, "1"])
                .cmd("EXPIRE")
                .arg(db)
                .arg(expire_time)
                .arg("XX")
                .query_async(&mut self.connection)
                .await?;
        }

        Ok(())
    }

    /// semi-lazy IP rate implementation for 5 different time frames.
    async fn rate_address(&mut self, address: String) -> GenericResult<()> {
        let mut pipe = redis::pipe();

        self.upsert_address_rate_in_pipe(&mut pipe, DB_RP_1_MIN, &address, 60)
            .await?;
        self.upsert_address_rate_in_pipe(&mut pipe, DB_RP_5_MIN, &address, 300)
            .await?;
        self.upsert_address_rate_in_pipe(&mut pipe, DB_RP_15_MIN, &address, 900)
            .await?;
        self.upsert_address_rate_in_pipe(&mut pipe, DB_RP_30_MIN, &address, 1800)
            .await?;
        self.upsert_address_rate_in_pipe(&mut pipe, DB_RP_60_MIN, &address, 3600)
            .await?;

        pipe.query_async(&mut self.connection).await?;

        Ok(())
    }

    async fn did_exceed_in_single_time_frame(
        &mut self,
        db: &str,
        address: &str,
        rate_limit: u16,
    ) -> GenericResult<bool> {
        let rate: u16 = redis::cmd("HGET")
            .arg(db)
            .arg(&address)
            .query_async(&mut self.connection)
            .await
            .unwrap_or(0);
        if rate >= rate_limit {
            return Ok(true);
        }

        Ok(false)
    }

    async fn rate_exceeded(
        &mut self,
        address: String,
        rate_limit_conf: &RateLimiter,
    ) -> GenericResult<bool> {
        if self
            .did_exceed_in_single_time_frame(DB_RP_1_MIN, &address, rate_limit_conf.rp_1_min)
            .await?
        {
            return Ok(true);
        }

        if self
            .did_exceed_in_single_time_frame(DB_RP_5_MIN, &address, rate_limit_conf.rp_5_min)
            .await?
        {
            return Ok(true);
        }

        if self
            .did_exceed_in_single_time_frame(DB_RP_15_MIN, &address, rate_limit_conf.rp_15_min)
            .await?
        {
            return Ok(true);
        }

        if self
            .did_exceed_in_single_time_frame(DB_RP_30_MIN, &address, rate_limit_conf.rp_30_min)
            .await?
        {
            return Ok(true);
        }

        if self
            .did_exceed_in_single_time_frame(DB_RP_60_MIN, &address, rate_limit_conf.rp_60_min)
            .await?
        {
            return Ok(true);
        }

        Ok(false)
    }
}

#[test]
fn test_db_constants() {
    assert_eq!(DB_RP_1_MIN, "rp:1_min");
    assert_eq!(DB_RP_5_MIN, "rp:5_min");
    assert_eq!(DB_RP_15_MIN, "rp:15_min");
    assert_eq!(DB_RP_30_MIN, "rp:30_min");
    assert_eq!(DB_RP_60_MIN, "rp:60_min");
}
