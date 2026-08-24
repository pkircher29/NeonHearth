use chrono::{DateTime, SecondsFormat, Utc};
use lattice_advisory::{
    AdvisoryInput, AdvisoryMatch, AdvisorySource, Confidence, Exploitability, Exposure, Freshness,
    MatchLabel, MatchedField, NormalizedAdvisory, Remediation, RiskDimensions, Severity,
    SourceTrust, VersionConstraint,
};
use lattice_domain::DeviceId;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Row as _, SqlitePool, sqlite::SqliteRow};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

const MAX_ROWS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AdvisoryId(Uuid);
impl AdvisoryId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
    pub fn parse(v: &str) -> Result<Self, uuid::Error> {
        v.parse().map(Self)
    }
}
impl Default for AdvisoryId {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Display for AdvisoryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug)]
pub struct DeviceAdvisory {
    pub advisory_id: AdvisoryId,
    pub advisory: NormalizedAdvisory,
    pub freshness: Freshness,
    pub matching: AdvisoryMatch,
    pub risk: RiskDimensions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedFetch {
    pub source: AdvisorySource,
    pub source_url: String,
    pub http_status: Option<u16>,
    pub retrieved_at: DateTime<Utc>,
    pub cache_expires_at: DateTime<Utc>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub failure_class: Option<FeedFailureClass>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedFailureClass {
    Network,
    Http,
    Parse,
    Validation,
    RateLimited,
}
impl FeedFetch {
    pub fn new(
        source: AdvisorySource,
        source_url: String,
        retrieved_at: DateTime<Utc>,
        cache_expires_at: DateTime<Utc>,
    ) -> Result<Self, AdvisoryStoreError> {
        let value = Self {
            source,
            source_url,
            http_status: None,
            retrieved_at,
            cache_expires_at,
            etag: None,
            last_modified: None,
            failure_class: None,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn with_response_metadata(
        mut self,
        http_status: Option<u16>,
        etag: Option<String>,
        last_modified: Option<String>,
        failure_class: Option<FeedFailureClass>,
    ) -> Result<Self, AdvisoryStoreError> {
        self.http_status = http_status;
        self.etag = etag;
        self.last_modified = last_modified;
        self.failure_class = failure_class;
        self.validate()?;
        Ok(self)
    }
    fn validate(&self) -> Result<(), AdvisoryStoreError> {
        let parsed = url::Url::parse(&self.source_url).map_err(|_| AdvisoryStoreError::Invalid)?;
        let official = match self.source {
            AdvisorySource::Nvd => {
                parsed.host_str() == Some("services.nvd.nist.gov")
                    && parsed.path() == "/rest/json/cves/2.0"
            }
            AdvisorySource::CisaKev => {
                parsed.host_str() == Some("www.cisa.gov")
                    && parsed.path()
                        == "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            }
            AdvisorySource::Vendor => true,
        };
        if self.cache_expires_at < self.retrieved_at
            || parsed.scheme() != "https"
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.host_str().is_none()
            || !official
            || self.source_url.len() > 512
            || self.source_url.chars().any(char::is_control)
            || self
                .http_status
                .is_some_and(|status| !(100..=599).contains(&status))
            || !valid_optional(&self.etag)
            || !valid_optional(&self.last_modified)
        {
            Err(AdvisoryStoreError::Invalid)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
pub struct AdvisoryRepository {
    pool: SqlitePool,
}
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdvisoryStoreError {
    #[error("invalid advisory data")]
    Invalid,
    #[error("advisory data conflicts with existing data")]
    Conflict,
    #[error("advisory relationship is invalid")]
    Constraint,
    #[error("advisory storage capacity exceeded")]
    Capacity,
    #[error("advisory data is corrupt")]
    Corrupt,
    #[error("advisory storage failed")]
    Storage,
}
impl AdvisoryRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
    pub async fn upsert_advisory(
        &self,
        value: &NormalizedAdvisory,
    ) -> Result<AdvisoryId, AdvisoryStoreError> {
        let input = value.input();
        let fields = Fields::from_input(input)?;
        let content = content_revision(input)?;
        let candidate = AdvisoryId::new();
        let actual: String = sqlx::query_scalar("INSERT INTO advisories(advisory_id,source,source_id,content_revision_sha256,provenance_sha256,source_url,title,vendor,model,firmware_kind,firmware_min,firmware_max,published_at,modified_at,retrieved_at,cache_expires_at,provenance_freshness,effective_freshness,source_trust,severity,exploitability,exposure,confidence,remediation) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source,source_id,content_revision_sha256) DO UPDATE SET provenance_sha256=excluded.provenance_sha256,retrieved_at=excluded.retrieved_at,cache_expires_at=excluded.cache_expires_at,provenance_freshness=excluded.provenance_freshness,effective_freshness=excluded.effective_freshness,source_trust=excluded.source_trust RETURNING advisory_id")
            .bind(candidate.to_string()).bind(source(input.source)).bind(&input.source_id).bind(content).bind(value.provenance_sha256())
            .bind(&input.source_url).bind(&input.title).bind(&input.vendor).bind(&input.model).bind(fields.kind).bind(fields.min).bind(fields.max)
            .bind(time(input.published_at)?).bind(time(input.modified_at)?).bind(time(input.retrieved_at)?).bind(time(input.cache_expires_at)?)
            .bind(freshness(input.freshness)).bind(freshness(input.freshness)).bind(trust(input.source_trust)).bind(severity(input.severity)).bind(exploitability(input.exploitability)).bind(exposure(input.exposure)).bind(confidence(input.confidence)).bind(remediation(input.remediation))
            .fetch_one(&self.pool).await.map_err(map_sqlx)?;
        decode_id(&actual)
    }
    pub async fn record_feed_fetch(&self, value: &FeedFetch) -> Result<(), AdvisoryStoreError> {
        value.validate()?;
        sqlx::query("INSERT INTO advisory_source_fetches(fetch_id,source,source_url,http_status,retrieved_at,cache_expires_at,effective_freshness,etag,last_modified,failure_class) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(Uuid::now_v7().to_string()).bind(source(value.source)).bind(&value.source_url).bind(value.http_status.map(i64::from)).bind(time(value.retrieved_at)?).bind(time(value.cache_expires_at)?)
            .bind(freshness(if value.failure_class.is_none() && value.http_status.is_none_or(|status| (200..300).contains(&status) || status == 304) { Freshness::Fresh } else { Freshness::Stale })).bind(&value.etag).bind(&value.last_modified).bind(value.failure_class.map(failure))
            .execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }
    pub async fn record_match(
        &self,
        advisory_id: AdvisoryId,
        device_id: DeviceId,
        matching: &AdvisoryMatch,
        risk: RiskDimensions,
    ) -> Result<(), AdvisoryStoreError> {
        let fields = serde_json::to_string(matching.matched_fields())
            .map_err(|_| AdvisoryStoreError::Invalid)?;
        if fields.len() > 64 {
            return Err(AdvisoryStoreError::Invalid);
        }
        sqlx::query("INSERT INTO advisory_matches(advisory_id,device_id,match_label,matched_fields_json,explanation,match_confidence,severity,exploitability,exposure,confidence,remediation) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(advisory_id,device_id) DO UPDATE SET match_label=excluded.match_label,matched_fields_json=excluded.matched_fields_json,explanation=excluded.explanation,match_confidence=excluded.match_confidence,severity=excluded.severity,exploitability=excluded.exploitability,exposure=excluded.exposure,confidence=excluded.confidence,remediation=excluded.remediation")
            .bind(advisory_id.to_string()).bind(device_id.to_string()).bind(label(matching.label())).bind(fields).bind(matching.explanation()).bind(confidence(matching.confidence()))
            .bind(severity(risk.severity)).bind(exploitability(risk.exploitability)).bind(exposure(risk.exposure)).bind(confidence(risk.confidence)).bind(remediation(risk.remediation))
            .execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }
    pub async fn list_device_advisories(
        &self,
        device_id: DeviceId,
        now: DateTime<Utc>,
    ) -> Result<Vec<DeviceAdvisory>, AdvisoryStoreError> {
        let now = time(now)?;
        let rows: Vec<SqliteRow> = sqlx::query("SELECT a.advisory_id,a.source,a.source_id,a.provenance_sha256,a.source_url,a.title,a.vendor,a.model,a.firmware_kind,a.firmware_min,a.firmware_max,a.published_at,a.modified_at,a.retrieved_at,a.cache_expires_at,a.provenance_freshness,a.source_trust,a.severity,a.exploitability,a.exposure,a.confidence,a.remediation,m.match_label,m.matched_fields_json,m.explanation,m.match_confidence,m.severity,m.exploitability,m.exposure,m.confidence,m.remediation,a.content_revision_sha256,a.effective_freshness FROM advisory_matches m JOIN advisories a ON a.advisory_id=m.advisory_id WHERE m.device_id=? ORDER BY a.modified_at DESC,a.source,a.source_id,a.advisory_id LIMIT ?")
            .bind(device_id.to_string()).bind(i64::try_from(MAX_ROWS + 1).map_err(|_| AdvisoryStoreError::Capacity)?).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        if rows.len() > MAX_ROWS {
            return Err(AdvisoryStoreError::Corrupt);
        }
        rows.into_iter().map(|r| decode_row(r, &now)).collect()
    }
    pub async fn expire_sources(&self, now: DateTime<Utc>) -> Result<u64, AdvisoryStoreError> {
        let now = time(now)?;
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let advisories = sqlx::query("UPDATE advisories SET effective_freshness='stale' WHERE effective_freshness='fresh' AND cache_expires_at < ?")
            .bind(&now).execute(&mut *tx).await.map_err(map_sqlx)?.rows_affected();
        let fetches = sqlx::query("UPDATE advisory_source_fetches SET effective_freshness='stale' WHERE effective_freshness='fresh' AND cache_expires_at < ?")
            .bind(now).execute(&mut *tx).await.map_err(map_sqlx)?.rows_affected();
        tx.commit().await.map_err(map_sqlx)?;
        Ok(advisories + fetches)
    }
}
fn decode_row(r: SqliteRow, now: &str) -> Result<DeviceAdvisory, AdvisoryStoreError> {
    macro_rules! v {
        ($index:expr) => {
            r.try_get($index).map_err(|_| AdvisoryStoreError::Corrupt)?
        };
    }
    let id: String = v!(0);
    let src: String = v!(1);
    let source_id: String = v!(2);
    let hash: String = v!(3);
    let url: String = v!(4);
    let title: String = v!(5);
    let vendor: String = v!(6);
    let model: Option<String> = v!(7);
    let fk: String = v!(8);
    let fmin: Option<String> = v!(9);
    let fmax: Option<String> = v!(10);
    let pub_at: String = v!(11);
    let mod_at: String = v!(12);
    let retrieved: String = v!(13);
    let expires: String = v!(14);
    let pfresh: String = v!(15);
    let trust_v: String = v!(16);
    let sev: String = v!(17);
    let expl: String = v!(18);
    let expo: String = v!(19);
    let conf: String = v!(20);
    let rem: String = v!(21);
    let label_v: String = v!(22);
    let fields: String = v!(23);
    let explanation: String = v!(24);
    let match_conf: String = v!(25);
    let severity_v: String = v!(26);
    let exploit_v: String = v!(27);
    let exposure_v: String = v!(28);
    let confidence_v: String = v!(29);
    let remediation_v: String = v!(30);
    let stored_content: String = v!(31);
    let effective: String = v!(32);
    let input = AdvisoryInput {
        source: decode_source(&src)?,
        source_id,
        source_url: url,
        title,
        vendor,
        model,
        firmware: decode_firmware(&fk, fmin, fmax)?,
        published_at: decode_time(&pub_at)?,
        modified_at: decode_time(&mod_at)?,
        retrieved_at: decode_time(&retrieved)?,
        cache_expires_at: decode_time(&expires)?,
        freshness: decode_freshness(&pfresh)?,
        source_trust: decode_trust(&trust_v)?,
        severity: decode_severity(&sev)?,
        exploitability: decode_exploitability(&expl)?,
        exposure: decode_exposure(&expo)?,
        confidence: decode_confidence(&conf)?,
        remediation: decode_remediation(&rem)?,
    };
    let advisory = NormalizedAdvisory::new(input).map_err(|_| AdvisoryStoreError::Corrupt)?;
    if advisory.provenance_sha256() != hash {
        return Err(AdvisoryStoreError::Corrupt);
    }
    if content_revision(advisory.input())? != stored_content {
        return Err(AdvisoryStoreError::Corrupt);
    }
    let effective = decode_freshness(&effective)?;
    if advisory.input().freshness != Freshness::Fresh && effective == Freshness::Fresh {
        return Err(AdvisoryStoreError::Corrupt);
    }
    let matching = AdvisoryMatch::from_persisted(
        decode_label(&label_v)?,
        serde_json::from_str::<Vec<MatchedField>>(&fields)
            .map_err(|_| AdvisoryStoreError::Corrupt)?,
        explanation,
        decode_confidence(&match_conf)?,
    )
    .map_err(|_| AdvisoryStoreError::Corrupt)?;
    let freshness = if advisory.input().freshness == Freshness::FutureDated {
        Freshness::FutureDated
    } else if advisory.input().freshness == Freshness::Stale || expires.as_str() < now {
        Freshness::Stale
    } else {
        Freshness::Fresh
    };
    Ok(DeviceAdvisory {
        advisory_id: decode_id(&id)?,
        advisory,
        freshness,
        matching,
        risk: RiskDimensions {
            severity: decode_severity(&severity_v)?,
            exploitability: decode_exploitability(&exploit_v)?,
            exposure: decode_exposure(&exposure_v)?,
            confidence: decode_confidence(&confidence_v)?,
            remediation: decode_remediation(&remediation_v)?,
        },
    })
}
#[derive(Serialize)]
struct Content<'a> {
    source: &'a str,
    source_id: &'a str,
    source_url: &'a str,
    title: &'a str,
    vendor: &'a str,
    model: &'a Option<String>,
    firmware: &'a VersionConstraint,
    published_at: String,
    modified_at: String,
    severity: &'a Severity,
    exploitability: &'a Exploitability,
    exposure: &'a Exposure,
    confidence: &'a Confidence,
    remediation: &'a Remediation,
}
fn content_revision(input: &AdvisoryInput) -> Result<String, AdvisoryStoreError> {
    let c = Content {
        source: source(input.source),
        source_id: &input.source_id,
        source_url: &input.source_url,
        title: &input.title,
        vendor: &input.vendor,
        model: &input.model,
        firmware: &input.firmware,
        published_at: time(input.published_at)?,
        modified_at: time(input.modified_at)?,
        severity: &input.severity,
        exploitability: &input.exploitability,
        exposure: &input.exposure,
        confidence: &input.confidence,
        remediation: &input.remediation,
    };
    let bytes = serde_json::to_vec(&c).map_err(|_| AdvisoryStoreError::Invalid)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
struct Fields {
    kind: &'static str,
    min: Option<String>,
    max: Option<String>,
}
impl Fields {
    fn from_input(input: &AdvisoryInput) -> Result<Self, AdvisoryStoreError> {
        Ok(match &input.firmware {
            VersionConstraint::Any => Self {
                kind: "any",
                min: None,
                max: None,
            },
            VersionConstraint::Exact(v) => Self {
                kind: "exact",
                min: Some(v.clone()),
                max: None,
            },
            VersionConstraint::LessThan(v) => Self {
                kind: "less_than",
                min: Some(v.clone()),
                max: None,
            },
            VersionConstraint::Range { min, max } => Self {
                kind: "range",
                min: Some(min.clone()),
                max: Some(max.clone()),
            },
        })
    }
}
fn valid_optional(v: &Option<String>) -> bool {
    v.as_ref()
        .is_none_or(|x| !x.is_empty() && x.len() <= 512 && !x.chars().any(char::is_control))
}
fn time(v: DateTime<Utc>) -> Result<String, AdvisoryStoreError> {
    let s = v.to_rfc3339_opts(SecondsFormat::Nanos, true);
    if s.len() <= 40 {
        Ok(s)
    } else {
        Err(AdvisoryStoreError::Invalid)
    }
}
fn decode_time(v: &str) -> Result<DateTime<Utc>, AdvisoryStoreError> {
    let d = DateTime::parse_from_rfc3339(v)
        .map_err(|_| AdvisoryStoreError::Corrupt)?
        .with_timezone(&Utc);
    if time(d).ok().as_deref() == Some(v) {
        Ok(d)
    } else {
        Err(AdvisoryStoreError::Corrupt)
    }
}
fn decode_id(v: &str) -> Result<AdvisoryId, AdvisoryStoreError> {
    let id = AdvisoryId::parse(v).map_err(|_| AdvisoryStoreError::Corrupt)?;
    if id.to_string() == v {
        Ok(id)
    } else {
        Err(AdvisoryStoreError::Corrupt)
    }
}
fn source(v: AdvisorySource) -> &'static str {
    match v {
        AdvisorySource::Nvd => "nvd",
        AdvisorySource::CisaKev => "cisa_kev",
        AdvisorySource::Vendor => "vendor",
    }
}
fn freshness(v: Freshness) -> &'static str {
    match v {
        Freshness::Fresh => "fresh",
        Freshness::Stale => "stale",
        Freshness::FutureDated => "future_dated",
    }
}
fn trust(v: SourceTrust) -> &'static str {
    match v {
        SourceTrust::OfficialApi => "official_api",
        SourceTrust::VerifiedSignature => "verified_signature",
        SourceTrust::RegisteredHttps => "registered_https",
        SourceTrust::Invalid => "invalid",
    }
}
fn severity(v: Severity) -> &'static str {
    match v {
        Severity::None => "none",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
        Severity::Unknown => "unknown",
    }
}
fn exploitability(v: Exploitability) -> &'static str {
    match v {
        Exploitability::None => "none",
        Exploitability::ProofOfConcept => "proof_of_concept",
        Exploitability::ActiveKnownExploitation => "active_known_exploitation",
        Exploitability::Unknown => "unknown",
    }
}
fn exposure(v: Exposure) -> &'static str {
    match v {
        Exposure::NotExposed => "not_exposed",
        Exposure::PotentiallyExposed => "potentially_exposed",
        Exposure::Exposed => "exposed",
        Exposure::Unknown => "unknown",
    }
}
fn confidence(v: Confidence) -> &'static str {
    match v {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}
fn remediation(v: Remediation) -> &'static str {
    match v {
        Remediation::Upgrade => "upgrade",
        Remediation::Mitigate => "mitigate",
        Remediation::Monitor => "monitor",
        Remediation::None => "none",
        Remediation::Unknown => "unknown",
    }
}
fn label(v: MatchLabel) -> &'static str {
    match v {
        MatchLabel::Exact => "exact",
        MatchLabel::Possible => "possible",
        MatchLabel::Contradicted => "contradicted",
        MatchLabel::Unknown => "unknown",
    }
}
fn failure(v: FeedFailureClass) -> &'static str {
    match v {
        FeedFailureClass::Network => "network",
        FeedFailureClass::Http => "http",
        FeedFailureClass::Parse => "parse",
        FeedFailureClass::Validation => "validation",
        FeedFailureClass::RateLimited => "rate_limited",
    }
}
macro_rules! decoder { ($n:ident,$t:ty,{$($s:literal=>$v:path),+$(,)?})=>{fn $n(v:&str)->Result<$t,AdvisoryStoreError>{match v{$($s=>Ok($v),)+_=>Err(AdvisoryStoreError::Corrupt)}}}; }
decoder!(decode_source,AdvisorySource,{"nvd"=>AdvisorySource::Nvd,"cisa_kev"=>AdvisorySource::CisaKev,"vendor"=>AdvisorySource::Vendor});
decoder!(decode_freshness,Freshness,{"fresh"=>Freshness::Fresh,"stale"=>Freshness::Stale,"future_dated"=>Freshness::FutureDated});
decoder!(decode_trust,SourceTrust,{"official_api"=>SourceTrust::OfficialApi,"verified_signature"=>SourceTrust::VerifiedSignature,"registered_https"=>SourceTrust::RegisteredHttps,"invalid"=>SourceTrust::Invalid});
decoder!(decode_severity,Severity,{"none"=>Severity::None,"low"=>Severity::Low,"medium"=>Severity::Medium,"high"=>Severity::High,"critical"=>Severity::Critical,"unknown"=>Severity::Unknown});
decoder!(decode_exploitability,Exploitability,{"none"=>Exploitability::None,"proof_of_concept"=>Exploitability::ProofOfConcept,"active_known_exploitation"=>Exploitability::ActiveKnownExploitation,"unknown"=>Exploitability::Unknown});
decoder!(decode_exposure,Exposure,{"not_exposed"=>Exposure::NotExposed,"potentially_exposed"=>Exposure::PotentiallyExposed,"exposed"=>Exposure::Exposed,"unknown"=>Exposure::Unknown});
decoder!(decode_confidence,Confidence,{"low"=>Confidence::Low,"medium"=>Confidence::Medium,"high"=>Confidence::High});
decoder!(decode_remediation,Remediation,{"upgrade"=>Remediation::Upgrade,"mitigate"=>Remediation::Mitigate,"monitor"=>Remediation::Monitor,"none"=>Remediation::None,"unknown"=>Remediation::Unknown});
decoder!(decode_label,MatchLabel,{"exact"=>MatchLabel::Exact,"possible"=>MatchLabel::Possible,"contradicted"=>MatchLabel::Contradicted,"unknown"=>MatchLabel::Unknown});
fn decode_firmware(
    kind: &str,
    min: Option<String>,
    max: Option<String>,
) -> Result<VersionConstraint, AdvisoryStoreError> {
    match (kind, min, max) {
        ("any", None, None) => Ok(VersionConstraint::Any),
        ("exact", Some(v), None) => Ok(VersionConstraint::Exact(v)),
        ("less_than", Some(v), None) => Ok(VersionConstraint::LessThan(v)),
        ("range", Some(min), Some(max)) => Ok(VersionConstraint::Range { min, max }),
        _ => Err(AdvisoryStoreError::Corrupt),
    }
}
fn map_sqlx(e: sqlx::Error) -> AdvisoryStoreError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => AdvisoryStoreError::Conflict,
        sqlx::Error::Database(db) if db.is_foreign_key_violation() || db.is_check_violation() => {
            AdvisoryStoreError::Constraint
        }
        _ => AdvisoryStoreError::Storage,
    }
}
