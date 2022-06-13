use super::*;
use async_trait::async_trait;
use ctx::get_app_config;
use db::Db;
use redis::Pipeline;

pub(crate) const DB_RP_1_MIN: &str = "rp:1_min";
pub(crate) const DB_RP_5_MIN: &str = "rp:5_min";
pub(crate) const DB_RP_15_MIN: &str = "rp:15_min";
pub(crate) const DB_RP_30_MIN: &str = "rp:30_min";
pub(crate) const DB_RP_60_MIN: &str = "rp:60_min";

#[async_trait]
pub(crate) trait RateLimitOperations {
    async fn upsert_ip_rate_in_pipe(
        &mut self,
        pipe: &mut Pipeline,
        db: &str,
        ip: &str,
        expire_time: usize,
    ) -> GenericResult<()>;
    async fn rate_ip(&mut self, ip: String) -> GenericResult<()>;
    async fn did_exceed_in_single_time_frame(
        &mut self,
        db: &str,
        ip: &str,
        rate_limit: u16,
    ) -> GenericResult<bool>;
    async fn rate_exceeded(&mut self, ip: String) -> GenericResult<bool>;
}

#[async_trait]
impl RateLimitOperations for Db {
    async fn upsert_ip_rate_in_pipe(
        &mut self,
        pipe: &mut Pipeline,
        db: &str,
        ip: &str,
        expire_time: usize,
    ) -> GenericResult<()> {
        if !self.key_exists(db).await? {
            pipe.hset(db, ip, "1").expire(db, expire_time);
        } else {
            pipe.cmd("HINCRBY").arg(db).arg(&[ip, "1"]);
        }

        Ok(())
    }

    /// semi-lazy IP rate implementation for 5 different time frames.
    async fn rate_ip(&mut self, ip: String) -> GenericResult<()> {
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
    ) -> GenericResult<bool> {
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

    async fn rate_exceeded(&mut self, ip: String) -> GenericResult<bool> {
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
