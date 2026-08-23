use chrono::{DateTime, Duration, Utc};
use lattice_domain::EventPayload;
use lattice_domain::{ByteCount, Coverage, DeviceId};
use lattice_sensor::flow::{
    DestinationCategory, DestinationMetadata, Protocol, Resolution, Rollup, RollupChange, RollupKey,
};
use lattice_sensor::live::{FlowLiveAdapter, LiveConfig, LiveError};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use thiserror::Error;
#[derive(Debug, Error)]
pub enum FlowStoreError {
    #[error("invalid input")]
    Invalid,
    #[error("capacity")]
    Capacity,
    #[error("compaction parent conflicts with existing aggregate")]
    CompactionConflict,
    #[error("integer overflow")]
    Overflow,
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error(transparent)]
    Live(#[from] LiveError),
}

/// D14 integration boundary: durable application is idempotent, then current-second changes are
/// coalesced into an optional replay-safe bandwidth event. Cache retirement never becomes traffic.
pub struct FlowIngestor {
    repository: FlowRepository,
    live: FlowLiveAdapter,
}
impl FlowIngestor {
    pub fn new(
        repository: FlowRepository,
        live: LiveConfig,
        max_live_rows: usize,
    ) -> Result<Self, FlowStoreError> {
        Ok(Self {
            repository,
            live: FlowLiveAdapter::new(live, max_live_rows)?,
        })
    }
    pub async fn apply(
        &mut self,
        changes: &[RollupChange],
        tick_ms: u64,
        now: DateTime<Utc>,
    ) -> Result<Option<EventPayload>, FlowStoreError> {
        let (staged, payload) = self.live.staged_payload(tick_ms, changes, now)?;
        self.repository.apply(changes, now).await?;
        self.live = staged;
        Ok(payload)
    }
    pub fn flush_idle(
        &mut self,
        tick_ms: u64,
        now: DateTime<Utc>,
    ) -> Result<Option<EventPayload>, FlowStoreError> {
        Ok(self.live.flush_payload(tick_ms, now)?)
    }
}
#[derive(Clone, Debug)]
pub struct CompactionPolicy {
    pub seconds: Duration,
    pub minutes: Duration,
    pub hours: Option<Duration>,
    pub max_rows: usize,
}
impl Default for CompactionPolicy {
    fn default() -> Self {
        Self {
            seconds: Duration::hours(24),
            minutes: Duration::days(90),
            hours: None,
            max_rows: 100_000,
        }
    }
}
impl CompactionPolicy {
    pub fn validate(&self) -> Result<(), FlowStoreError> {
        if self.seconds <= Duration::zero()
            || self.minutes < self.seconds
            || self.hours.is_some()
            || self.max_rows == 0
        {
            Err(FlowStoreError::Invalid)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone)]
pub struct FlowRepository {
    pool: SqlitePool,
    max_batch: usize,
}
impl FlowRepository {
    pub(crate) async fn apply_in_transaction(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        changes: &[RollupChange],
        now: DateTime<Utc>,
    ) -> Result<(), FlowStoreError> {
        if changes.len() > self.max_batch {
            return Err(FlowStoreError::Capacity);
        }
        for c in changes {
            match c {
                RollupChange::Upsert(r) | RollupChange::Correction(r) => upsert(tx, r, now).await?,
                RollupChange::Retire(r) if r.cache_only => {}
                _ => return Err(FlowStoreError::Invalid),
            }
        }
        Ok(())
    }
    pub fn new(pool: SqlitePool, max_batch: usize) -> Result<Self, FlowStoreError> {
        if max_batch == 0 {
            return Err(FlowStoreError::Invalid);
        }
        Ok(Self { pool, max_batch })
    }
    pub async fn apply(
        &self,
        changes: &[RollupChange],
        now: DateTime<Utc>,
    ) -> Result<(), FlowStoreError> {
        let mut tx = self.pool.begin().await?;
        self.apply_in_transaction(&mut tx, changes, now).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn range(
        &self,
        res: Resolution,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<Rollup>, FlowStoreError> {
        if start > end || limit == 0 || limit > self.max_batch {
            return Err(FlowStoreError::Invalid);
        }
        let rows=sqlx::query("SELECT bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain,upload,download,coverage FROM flow_rollups WHERE resolution=? AND bucket>=? AND bucket<=? ORDER BY bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain LIMIT ?").bind(res_s(res)).bind(ts(start)).bind(ts(end)).bind(i64::try_from(limit).map_err(|_|FlowStoreError::Overflow)?).fetch_all(&self.pool).await?;
        rows.into_iter().map(|r| decode(res, &r)).collect()
    }
    pub async fn compact(
        &self,
        now: DateTime<Utc>,
        p: &CompactionPolicy,
    ) -> Result<u64, FlowStoreError> {
        p.validate()?;
        let sec = now
            .checked_sub_signed(p.seconds)
            .ok_or(FlowStoreError::Overflow)?;
        let min = now
            .checked_sub_signed(p.minutes)
            .ok_or(FlowStoreError::Overflow)?;
        let mut tx = self.pool.begin().await?;
        let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM flow_rollups WHERE (resolution='second' AND unixepoch(bucket)-((unixepoch(bucket)%60+60)%60)+60<=unixepoch(?)) OR (resolution='minute' AND unixepoch(bucket)-((unixepoch(bucket)%3600+3600)%3600)+3600<=unixepoch(?))").bind(sec.to_rfc3339()).bind(min.to_rfc3339()).fetch_one(&mut *tx).await?;
        if usize::try_from(count).map_err(|_| FlowStoreError::Overflow)? > p.max_rows {
            return Err(FlowStoreError::Capacity);
        };
        aggregate(&mut tx, true, &sec, now).await?;
        aggregate(&mut tx, false, &min, now).await?;
        let a=sqlx::query("DELETE FROM flow_rollups WHERE resolution='second' AND unixepoch(bucket)-((unixepoch(bucket)%60+60)%60)+60<=unixepoch(?)").bind(sec.to_rfc3339()).execute(&mut *tx).await?.rows_affected();
        let b=sqlx::query("DELETE FROM flow_rollups WHERE resolution='minute' AND unixepoch(bucket)-((unixepoch(bucket)%3600+3600)%3600)+3600<=unixepoch(?)").bind(min.to_rfc3339()).execute(&mut *tx).await?.rows_affected();
        tx.commit().await?;
        Ok(a + b)
    }
}
async fn upsert(
    tx: &mut Transaction<'_, Sqlite>,
    r: &Rollup,
    now: DateTime<Utc>,
) -> Result<(), FlowStoreError> {
    if r.key.metadata != r.metadata || r.key.bucket.timestamp_subsec_nanos() != 0 {
        return Err(FlowStoreError::Invalid);
    }
    let width = match r.key.resolution {
        Resolution::Second => 1,
        Resolution::Minute => 60,
        Resolution::Hour => 3600,
    };
    if r.key.bucket.timestamp().rem_euclid(width) != 0 {
        return Err(FlowStoreError::Invalid);
    }
    let up = i64::try_from(r.bytes.upload).map_err(|_| FlowStoreError::Overflow)?;
    let down = i64::try_from(r.bytes.download).map_err(|_| FlowStoreError::Overflow)?;
    let (ip, domain) = r
        .metadata
        .as_ref()
        .map(|m| {
            (
                m.ip.map(|x| x.to_string()).unwrap_or_default(),
                m.domain.clone().unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    validate_meta(&ip, &domain)?;
    if r.key.resolution != Resolution::Hour {
        let width = if r.key.resolution == Resolution::Second {
            60
        } else {
            3600
        };
        let epoch = r
            .key
            .bucket
            .timestamp()
            .div_euclid(width)
            .checked_mul(width)
            .ok_or(FlowStoreError::Overflow)?;
        let parent = DateTime::from_timestamp(epoch, 0)
            .ok_or(FlowStoreError::Invalid)?
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let sealed: Option<i64> = sqlx::query_scalar("SELECT 1 FROM flow_compaction_seals WHERE child_resolution=? AND parent_bucket=? AND device_id=? AND protocol=? AND destination=? AND interface=? AND metadata_ip=? AND metadata_domain=?")
            .bind(res_s(r.key.resolution)).bind(parent).bind(r.key.device_id.to_string()).bind(proto_s(r.key.protocol)).bind(dest_s(r.key.destination)).bind(i64::from(r.key.interface)).bind(&ip).bind(&domain).fetch_optional(&mut **tx).await?;
        if sealed.is_some() {
            return Err(FlowStoreError::Invalid);
        }
    }
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_confirmed) VALUES(?,?,?,0) ON CONFLICT(device_id) DO UPDATE SET last_seen_at=CASE WHEN excluded.last_seen_at>last_seen_at THEN excluded.last_seen_at ELSE last_seen_at END").bind(r.key.device_id.to_string()).bind(ts(r.key.bucket)).bind(ts(r.key.bucket)).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO flow_rollups(resolution,bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain,upload,download,coverage,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(resolution,bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain) DO UPDATE SET upload=excluded.upload,download=excluded.download,coverage=excluded.coverage,updated_at=excluded.updated_at").bind(res_s(r.key.resolution)).bind(ts(r.key.bucket)).bind(r.key.device_id.to_string()).bind(proto_s(r.key.protocol)).bind(dest_s(r.key.destination)).bind(i64::from(r.key.interface)).bind(ip).bind(domain).bind(up).bind(down).bind(cov_s(r.coverage)).bind(ts(now)).execute(&mut **tx).await?;
    Ok(())
}
fn validate_meta(ip: &str, d: &str) -> Result<(), FlowStoreError> {
    if ip.len() > 45
        || d.len() > 253
        || (!ip.is_empty() && ip.parse::<std::net::IpAddr>().is_err())
        || (!d.is_empty()
            && (d.starts_with('.')
                || d.ends_with('.')
                || !d.is_ascii()
                || d.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })))
    {
        Err(FlowStoreError::Invalid)
    } else {
        Ok(())
    }
}
async fn aggregate(
    tx: &mut Transaction<'_, Sqlite>,
    seconds_to_minutes: bool,
    cut: &DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), FlowStoreError> {
    let (child, width, parent) = if seconds_to_minutes {
        ("second", 60, "minute")
    } else {
        ("minute", 3600, "hour")
    };
    let conflict = format!(
        "WITH grouped AS (SELECT strftime('%Y-%m-%dT%H:%M:%SZ',unixepoch(bucket)-((unixepoch(bucket)%{width}+{width})%{width}),'unixepoch') parent_bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain,SUM(upload) upload,SUM(download) download,CASE WHEN MIN(coverage)=MAX(coverage) THEN MIN(coverage) ELSE 'estimated' END coverage FROM flow_rollups WHERE resolution='{child}' AND unixepoch(bucket)-((unixepoch(bucket)%{width}+{width})%{width})+{width}<=unixepoch(?) GROUP BY 1,device_id,protocol,destination,interface,metadata_ip,metadata_domain) SELECT COUNT(*) FROM grouped g JOIN flow_rollups p ON p.resolution='{parent}' AND p.bucket=g.parent_bucket AND p.device_id=g.device_id AND p.protocol=g.protocol AND p.destination=g.destination AND p.interface=g.interface AND p.metadata_ip=g.metadata_ip AND p.metadata_domain=g.metadata_domain WHERE p.upload<>g.upload OR p.download<>g.download OR p.coverage<>g.coverage"
    );
    let conflicts: i64 = sqlx::query_scalar(&conflict)
        .bind(cut.to_rfc3339())
        .fetch_one(&mut **tx)
        .await?;
    if conflicts > 0 {
        return Err(FlowStoreError::CompactionConflict);
    }
    let sql = if seconds_to_minutes {
        "INSERT INTO flow_rollups(resolution,bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain,upload,download,coverage,updated_at) SELECT 'minute',strftime('%Y-%m-%dT%H:%M:%SZ',unixepoch(bucket)-((unixepoch(bucket)%60+60)%60),'unixepoch'),device_id,protocol,destination,interface,metadata_ip,metadata_domain,SUM(upload),SUM(download),CASE WHEN MIN(coverage)=MAX(coverage) THEN MIN(coverage) ELSE 'estimated' END,? FROM flow_rollups WHERE resolution='second' AND unixepoch(bucket)-((unixepoch(bucket)%60+60)%60)+60<=unixepoch(?) GROUP BY 2,device_id,protocol,destination,interface,metadata_ip,metadata_domain ON CONFLICT(resolution,bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain) DO NOTHING"
    } else {
        "INSERT INTO flow_rollups(resolution,bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain,upload,download,coverage,updated_at) SELECT 'hour',strftime('%Y-%m-%dT%H:%M:%SZ',unixepoch(bucket)-((unixepoch(bucket)%3600+3600)%3600),'unixepoch'),device_id,protocol,destination,interface,metadata_ip,metadata_domain,SUM(upload),SUM(download),CASE WHEN MIN(coverage)=MAX(coverage) THEN MIN(coverage) ELSE 'estimated' END,? FROM flow_rollups WHERE resolution='minute' AND unixepoch(bucket)-((unixepoch(bucket)%3600+3600)%3600)+3600<=unixepoch(?) GROUP BY 2,device_id,protocol,destination,interface,metadata_ip,metadata_domain ON CONFLICT(resolution,bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain) DO NOTHING"
    };
    let seal_sql = if seconds_to_minutes {
        "INSERT OR IGNORE INTO flow_compaction_seals(child_resolution,parent_bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain) SELECT 'second',strftime('%Y-%m-%dT%H:%M:%SZ',unixepoch(bucket)-((unixepoch(bucket)%60+60)%60),'unixepoch'),device_id,protocol,destination,interface,metadata_ip,metadata_domain FROM flow_rollups WHERE resolution='second' AND unixepoch(bucket)-((unixepoch(bucket)%60+60)%60)+60<=unixepoch(?) GROUP BY 2,device_id,protocol,destination,interface,metadata_ip,metadata_domain"
    } else {
        "INSERT OR IGNORE INTO flow_compaction_seals(child_resolution,parent_bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain) SELECT 'minute',strftime('%Y-%m-%dT%H:%M:%SZ',unixepoch(bucket)-((unixepoch(bucket)%3600+3600)%3600),'unixepoch'),device_id,protocol,destination,interface,metadata_ip,metadata_domain FROM flow_rollups WHERE resolution='minute' AND unixepoch(bucket)-((unixepoch(bucket)%3600+3600)%3600)+3600<=unixepoch(?) GROUP BY 2,device_id,protocol,destination,interface,metadata_ip,metadata_domain"
    };
    sqlx::query(seal_sql)
        .bind(cut.to_rfc3339())
        .execute(&mut **tx)
        .await?;
    sqlx::query(sql)
        .bind(now.to_rfc3339())
        .bind(cut.to_rfc3339())
        .execute(&mut **tx)
        .await?;
    Ok(())
}
fn decode(res: Resolution, r: &sqlx::sqlite::SqliteRow) -> Result<Rollup, FlowStoreError> {
    let bucket = DateTime::parse_from_rfc3339(r.try_get("bucket")?)
        .map_err(|_| FlowStoreError::Invalid)?
        .with_timezone(&Utc);
    let device_id =
        DeviceId::parse(r.try_get("device_id")?).map_err(|_| FlowStoreError::Invalid)?;
    let p = parse_proto(r.try_get("protocol")?)?;
    let d = parse_dest(r.try_get("destination")?)?;
    let ip: String = r.try_get("metadata_ip")?;
    let domain: String = r.try_get("metadata_domain")?;
    validate_meta(&ip, &domain)?;
    let metadata = if ip.is_empty() && domain.is_empty() {
        None
    } else {
        Some(DestinationMetadata {
            ip: if ip.is_empty() {
                None
            } else {
                Some(ip.parse().map_err(|_| FlowStoreError::Invalid)?)
            },
            domain: if domain.is_empty() {
                None
            } else {
                Some(domain)
            },
        })
    };
    let key = RollupKey {
        resolution: res,
        bucket,
        device_id,
        protocol: p,
        destination: d,
        interface: u32::try_from(r.try_get::<i64, _>("interface")?)
            .map_err(|_| FlowStoreError::Invalid)?,
        metadata: metadata.clone(),
    };
    Ok(Rollup {
        key,
        bytes: ByteCount {
            upload: u64::try_from(r.try_get::<i64, _>("upload")?)
                .map_err(|_| FlowStoreError::Invalid)?,
            download: u64::try_from(r.try_get::<i64, _>("download")?)
                .map_err(|_| FlowStoreError::Invalid)?,
        },
        coverage: parse_cov(r.try_get("coverage")?)?,
        metadata,
    })
}
fn res_s(x: Resolution) -> &'static str {
    match x {
        Resolution::Second => "second",
        Resolution::Minute => "minute",
        Resolution::Hour => "hour",
    }
}
fn proto_s(x: Protocol) -> &'static str {
    match x {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
        Protocol::Other => "other",
    }
}
fn dest_s(x: DestinationCategory) -> &'static str {
    match x {
        DestinationCategory::Local => "local",
        DestinationCategory::Lan => "lan",
        DestinationCategory::Internet => "internet",
        DestinationCategory::Unknown => "unknown",
    }
}
fn cov_s(x: Coverage) -> &'static str {
    match x {
        Coverage::Complete => "complete",
        Coverage::RouterReported => "router-reported",
        Coverage::LocalOnly => "local-only",
        Coverage::Estimated => "estimated",
    }
}
fn parse_proto(x: &str) -> Result<Protocol, FlowStoreError> {
    match x {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "icmp" => Ok(Protocol::Icmp),
        "other" => Ok(Protocol::Other),
        _ => Err(FlowStoreError::Invalid),
    }
}
fn parse_dest(x: &str) -> Result<DestinationCategory, FlowStoreError> {
    match x {
        "local" => Ok(DestinationCategory::Local),
        "lan" => Ok(DestinationCategory::Lan),
        "internet" => Ok(DestinationCategory::Internet),
        "unknown" => Ok(DestinationCategory::Unknown),
        _ => Err(FlowStoreError::Invalid),
    }
}
fn parse_cov(x: &str) -> Result<Coverage, FlowStoreError> {
    match x {
        "complete" => Ok(Coverage::Complete),
        "router-reported" => Ok(Coverage::RouterReported),
        "local-only" => Ok(Coverage::LocalOnly),
        "estimated" => Ok(Coverage::Estimated),
        _ => Err(FlowStoreError::Invalid),
    }
}
fn ts(x: DateTime<Utc>) -> String {
    x.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
