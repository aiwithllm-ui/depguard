//! PostgreSQL-backed, protocol-client implementation of the DepGuard network MVP.
//! It never changes V1 evidence; it verifies and indexes it as supplied.
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use depguard_attestation::{DsseEnvelope, InTotoStatement};
use depguard_evidence::{PublicCommandStatus, PublicCompatibilityEvidenceV1};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use std::{sync::Arc, time::Duration};
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    rate_limit: Arc<dyn RateLimitBoundary>,
}

/// Deployment-owned admission boundary. The MVP defaults to allow-all so it
/// remains usable locally; a reverse proxy or host can inject a real limiter
/// without changing protocol ingestion semantics.
pub trait RateLimitBoundary: Send + Sync + 'static {
    fn allow(&self) -> bool;
}
pub struct AllowAllRateLimit;
impl RateLimitBoundary for AllowAllRateLimit {
    fn allow(&self) -> bool {
        true
    }
}

pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?)
}
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!().run(pool).await?;
    Ok(())
}

pub fn router(pool: PgPool) -> Router {
    router_with_rate_limit(pool, Arc::new(AllowAllRateLimit))
}
pub fn router_with_rate_limit(pool: PgPool, rate_limit: Arc<dyn RateLimitBoundary>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/evidence", post(ingest_evidence))
        .route("/v1/evidence/{id}", get(raw_evidence))
        .route("/v1/attestations/verify", post(verify_attestation))
        .route("/v1/packages/{ecosystem}/{package}", get(package_lookup))
        .route(
            "/v1/packages/{ecosystem}/{package}/versions/{version}",
            get(version_lookup),
        )
        .route(
            "/v1/transitions/{ecosystem}/{package}/{from}/{to}",
            get(transition_lookup),
        )
        .route(
            "/v1/transitions/{ecosystem}/{package}/{from}/{to}/evidence",
            get(transition_evidence),
        )
        .with_state(AppState { pool, rate_limit })
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(TraceLayer::new_for_http())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Status {
    Accepted,
    Rejected,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IngestReply {
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duplicate: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

fn rejected(reason: impl Into<String>) -> (StatusCode, Json<IngestReply>) {
    (
        StatusCode::BAD_REQUEST,
        Json(IngestReply {
            status: Status::Rejected,
            evidence_id: None,
            duplicate: None,
            reason: Some(reason.into()),
        }),
    )
}

/// The evidence ID is sha256 of RFC 8785 canonical JSON of the submitted DSSE
/// envelope. Original bytes are retained separately; replaying formatting changes
/// cannot create a distinct identity.
fn canonical_envelope_id(raw: &Value) -> Result<(String, Value), &'static str> {
    let canonical = serde_json_canonicalizer::to_vec(raw).map_err(|_| "MALFORMED_DSSE")?;
    let id = format!("sha256:{:x}", Sha256::digest(&canonical));
    Ok((
        id,
        serde_json::from_slice(&canonical).map_err(|_| "MALFORMED_DSSE")?,
    ))
}

async fn ingest_evidence(State(state): State<AppState>, bytes: Bytes) -> Response {
    if !state.rate_limit.allow() {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    tracing::info!(operation = "evidence.ingest", size = bytes.len());
    let raw: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return rejected("MALFORMED_DSSE").into_response(),
    };
    let (proposed_id, canonical) = match canonical_envelope_id(&raw) {
        Ok(v) => v,
        Err(e) => return rejected(e).into_response(),
    };
    let envelope: DsseEnvelope = match serde_json::from_value(raw.clone()) {
        Ok(v) => v,
        Err(_) => return rejected("MALFORMED_DSSE").into_response(),
    };
    tracing::info!(operation = "attestation.verify");
    if let Err(error) = depguard_attestation::verify_envelope(&envelope) {
        return rejected(error.code()).into_response();
    }
    let parsed = match parse_verified(&envelope) {
        Ok(v) => v,
        Err(reason) => return rejected(reason).into_response(),
    };
    if let Err(reason) = validate_public_privacy(&parsed.evidence) {
        return rejected(reason).into_response();
    }
    match persist(
        &state.pool,
        &proposed_id,
        canonical,
        bytes.to_vec(),
        envelope,
        parsed,
    )
    .await
    {
        Ok((evidence_id, duplicate)) => (
            StatusCode::OK,
            Json(IngestReply {
                status: Status::Accepted,
                evidence_id: Some(evidence_id),
                duplicate: Some(duplicate),
                reason: None,
            }),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(operation = "evidence.persist", error = %error);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(IngestReply {
                    status: Status::Rejected,
                    evidence_id: None,
                    duplicate: None,
                    reason: Some("PERSISTENCE_ERROR".into()),
                }),
            )
                .into_response()
        }
    }
}

struct Parsed {
    statement: Value,
    predicate: Value,
    evidence: PublicCompatibilityEvidenceV1,
    evidence_digest: String,
    key_id: String,
}
fn parse_verified(envelope: &DsseEnvelope) -> Result<Parsed, &'static str> {
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|_| "MALFORMED_DSSE")?;
    let statement_value: Value =
        serde_json::from_slice(&payload).map_err(|_| "INVALID_STATEMENT")?;
    let statement: InTotoStatement =
        serde_json::from_value(statement_value.clone()).map_err(|_| "INVALID_STATEMENT")?;
    Ok(Parsed {
        predicate: serde_json::to_value(&statement.predicate).map_err(|_| "INVALID_STATEMENT")?,
        evidence_digest: statement.predicate.compatibility_evidence_digest.clone(),
        evidence: statement.predicate.evidence,
        statement: statement_value,
        key_id: envelope.signatures[0].keyid.clone(),
    })
}

/// V1 has a strict, closed schema and therefore cannot carry repository/source or
/// log fields. This defensive check also rejects known sensitive field names if a
/// future malformed payload reaches this boundary.
fn validate_public_privacy(evidence: &PublicCompatibilityEvidenceV1) -> Result<(), &'static str> {
    fn walk(value: &Value) -> bool {
        match value {
            Value::Object(map) => map.iter().any(|(key, value)| {
                let lower = key.to_ascii_lowercase();
                [
                    "privatekey",
                    "secret",
                    "rawlog",
                    "sourcecode",
                    "repository",
                    "gitremote",
                    "databasecontents",
                ]
                .iter()
                .any(|bad| lower.contains(bad))
                    || walk(value)
            }),
            Value::Array(values) => values.iter().any(walk),
            _ => false,
        }
    }
    if walk(&serde_json::to_value(evidence).map_err(|_| "PRIVACY_VIOLATION")?) {
        Err("PRIVACY_VIOLATION")
    } else {
        Ok(())
    }
}

async fn persist(
    pool: &PgPool,
    proposed_id: &str,
    canonical: Value,
    original: Vec<u8>,
    envelope: DsseEnvelope,
    parsed: Parsed,
) -> anyhow::Result<(String, bool)> {
    let mut tx = pool.begin().await?;
    // Serialize competing submissions of the same immutable DSSE envelope.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(proposed_id)
        .execute(&mut *tx)
        .await?;
    if let Some(row) =
        sqlx::query("SELECT a.id, a.evidence_id FROM attestations a WHERE a.evidence_id = $1")
            .bind(proposed_id)
            .fetch_optional(&mut *tx)
            .await?
    {
        let attestation_id: i64 = row.get("id");
        let evidence_id: String = row.get("evidence_id");
        sqlx::query("UPDATE evidence_submissions SET last_seen_at=now(), submission_count=submission_count+1 WHERE attestation_id=$1").bind(attestation_id).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok((evidence_id, true));
    }
    let e = &parsed.evidence;
    let signer_id: i64 = sqlx::query_scalar("INSERT INTO signers(key_id, assurance_tier, public_key_hex) VALUES($1,'LOCAL_DEVELOPMENT_KEY',$1) ON CONFLICT(key_id, assurance_tier) DO UPDATE SET last_seen_at=now() RETURNING id")
        .bind(&parsed.key_id).fetch_one(&mut *tx).await?;
    let package_id: i64 = sqlx::query_scalar("INSERT INTO packages(ecosystem,name) VALUES($1,$2) ON CONFLICT(ecosystem,name) DO UPDATE SET name=EXCLUDED.name RETURNING id")
        .bind(&e.subject.ecosystem).bind(&e.subject.package).fetch_one(&mut *tx).await?;
    let from_id: i64 = sqlx::query_scalar("INSERT INTO package_versions(package_id,version,purl) VALUES($1,$2,$3) ON CONFLICT(package_id,version) DO UPDATE SET purl=EXCLUDED.purl RETURNING id")
        .bind(package_id).bind(&e.subject.baseline.version).bind(&e.subject.baseline.purl).fetch_one(&mut *tx).await?;
    let to_id: i64 = sqlx::query_scalar("INSERT INTO package_versions(package_id,version,purl) VALUES($1,$2,$3) ON CONFLICT(package_id,version) DO UPDATE SET purl=EXCLUDED.purl RETURNING id")
        .bind(package_id).bind(&e.subject.candidate.version).bind(&e.subject.candidate.purl).fetch_one(&mut *tx).await?;
    let transition_id: i64 = sqlx::query_scalar("INSERT INTO version_transitions(package_id,from_version_id,to_version_id) VALUES($1,$2,$3) ON CONFLICT(package_id,from_version_id,to_version_id) DO UPDATE SET package_id=EXCLUDED.package_id RETURNING id")
        .bind(package_id).bind(from_id).bind(to_id).fetch_one(&mut *tx).await?;
    let environment_id: i64 = sqlx::query_scalar("INSERT INTO environments(os,architecture,runtime,runtime_version,package_manager,package_manager_version,sandbox_backend) VALUES($1,$2,$3,NULL,$4,NULL,$5) ON CONFLICT(os,architecture,runtime,runtime_version,package_manager,package_manager_version,sandbox_backend) DO UPDATE SET os=EXCLUDED.os RETURNING id")
        .bind(&e.environment.os).bind(&e.environment.architecture).bind(&e.environment.runtime).bind(&e.environment.package_manager).bind(&e.environment.sandbox_backend).fetch_one(&mut *tx).await?;
    let methodology_id: i64 = sqlx::query_scalar("INSERT INTO methodology_versions(evidence_schema_version,verification_methodology_version,normalization_version,depguard_version,observer_version,sandbox_version) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(evidence_schema_version,verification_methodology_version,normalization_version,depguard_version,observer_version,sandbox_version) DO UPDATE SET depguard_version=EXCLUDED.depguard_version RETURNING id")
        .bind(&e.methodology.evidence_schema_version).bind(&e.methodology.verification_methodology_version).bind(&e.methodology.normalization_version).bind(&e.methodology.depguard_version).bind(&e.methodology.observer_version).bind(&e.methodology.sandbox_version).fetch_one(&mut *tx).await?;
    let signatures = serde_json::to_value(&envelope.signatures)?;
    let attestation_id: i64 = sqlx::query_scalar("INSERT INTO attestations(evidence_id,evidence_digest,canonical_envelope,original_envelope,original_statement,original_predicate,signatures,signer_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id")
        .bind(proposed_id).bind(&parsed.evidence_digest).bind(canonical).bind(original).bind(parsed.statement).bind(parsed.predicate).bind(signatures).bind(signer_id).fetch_one(&mut *tx).await?;
    let outcome = classify_outcome(e);
    let run_id: i64 = sqlx::query_scalar("INSERT INTO verification_runs(attestation_id,transition_id,environment_id,methodology_version_id,outcome,project_fingerprint,process_observation_capability,network_observation_capability) VALUES($1,$2,$3,$4,$5,NULL,$6,$7) RETURNING id")
        .bind(attestation_id).bind(transition_id).bind(environment_id).bind(methodology_id).bind(&outcome).bind(&e.capabilities.process_observation.status).bind(&e.capabilities.network_observation.status).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO evidence_submissions(attestation_id) VALUES($1)")
        .bind(attestation_id)
        .execute(&mut *tx)
        .await?;
    for file in &e.observations.filesystem {
        sqlx::query("INSERT INTO behavior_findings(verification_run_id,kind,value) VALUES($1,'FILESYSTEM_PATH',$2)").bind(run_id).bind(json!({"path":file.path,"kind":file.kind})).execute(&mut *tx).await?;
    }
    for process in &e.observations.processes {
        sqlx::query("INSERT INTO behavior_findings(verification_run_id,kind,value) VALUES($1,'PROCESS_PATTERN',$2)").bind(run_id).bind(serde_json::to_value(process)?).execute(&mut *tx).await?;
    }
    for finding in &e.policy.findings {
        sqlx::query(
            "INSERT INTO policy_findings(verification_run_id,outcome,finding) VALUES($1,$2,$3)",
        )
        .bind(run_id)
        .bind(&e.policy.outcome)
        .bind(finding)
        .execute(&mut *tx)
        .await?;
    }
    for source in &e.external_intelligence {
        for finding in &source.findings {
            sqlx::query("INSERT INTO security_findings(verification_run_id,provider,status,finding) VALUES($1,$2,$3,$4)").bind(run_id).bind(&source.provider).bind(&source.status).bind(finding).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    tracing::info!(operation = "evidence.persist", evidence_id = proposed_id);
    Ok((proposed_id.to_owned(), false))
}

fn classify_outcome(e: &PublicCompatibilityEvidenceV1) -> String {
    let baseline = e.verification.get("baseline").into_iter().flatten();
    if baseline.clone().any(|c| {
        matches!(
            c.status,
            PublicCommandStatus::Failed | PublicCommandStatus::Timeout | PublicCommandStatus::Error
        )
    }) {
        return "BASELINE_INVALID".into();
    }
    if e.policy.outcome == "POLICY_DENIED" {
        return "POLICY_DENIAL".into();
    }
    if e.policy.outcome == "REVIEW_REQUIRED" {
        return "REVIEW_REQUIRED_FINDING".into();
    }
    let mut candidate = e.verification.get("candidate").into_iter().flatten();
    if candidate
        .clone()
        .any(|c| matches!(c.status, PublicCommandStatus::Error))
    {
        return "VERIFICATION_INFRASTRUCTURE_ERROR".into();
    }
    if candidate.clone().any(|c| {
        matches!(
            c.status,
            PublicCommandStatus::Failed | PublicCommandStatus::Timeout
        )
    }) {
        return "CANDIDATE_REGRESSION_OBSERVED".into();
    }
    if candidate.any(|c| matches!(c.status, PublicCommandStatus::Passed)) {
        "CONFIGURED_CHECKS_PASSED".into()
    } else {
        "REVIEW_REQUIRED_FINDING".into()
    }
}

async fn raw_evidence(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT original_envelope FROM attestations WHERE evidence_id=$1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(raw)) => ([(header::CONTENT_TYPE, "application/json")], raw).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
async fn verify_attestation(bytes: Bytes) -> Response {
    let envelope: DsseEnvelope = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return rejected("MALFORMED_DSSE").into_response(),
    };
    match depguard_attestation::verify_envelope(&envelope) {
        Ok(summary) => Json(json!({"status":"VALID","summary":summary})).into_response(),
        Err(e) => rejected(e.code()).into_response(),
    }
}

#[derive(Deserialize)]
struct Page {
    cursor: Option<String>,
    limit: Option<i64>,
}
fn bounded_limit(page: &Page) -> i64 {
    page.limit.unwrap_or(50).clamp(1, 100)
}
async fn package_lookup(
    State(state): State<AppState>,
    Path((ecosystem, package)): Path<(String, String)>,
) -> Response {
    tracing::info!(operation = "api.query", endpoint = "package");
    let rows = match sqlx::query("SELECT v.version, v.purl FROM packages p JOIN package_versions v ON v.package_id=p.id WHERE p.ecosystem=$1 AND p.name=$2 ORDER BY v.version").bind(&ecosystem).bind(&package).fetch_all(&state.pool).await { Ok(r)=>r, Err(_)=>return StatusCode::INTERNAL_SERVER_ERROR.into_response() };
    if rows.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(json!({"ecosystem":ecosystem,"package":package,"versions":rows.into_iter().map(|r|json!({"version":r.get::<String,_>("version"),"purl":r.get::<String,_>("purl")})).collect::<Vec<_>>() })).into_response()
}
async fn version_lookup(
    State(state): State<AppState>,
    Path((ecosystem, package, version)): Path<(String, String, String)>,
) -> Response {
    let rows = match sqlx::query("SELECT fv.version AS \"from\", tv.version AS \"to\" FROM version_transitions t JOIN packages p ON p.id=t.package_id JOIN package_versions fv ON fv.id=t.from_version_id JOIN package_versions tv ON tv.id=t.to_version_id WHERE p.ecosystem=$1 AND p.name=$2 AND (fv.version=$3 OR tv.version=$3) ORDER BY fv.version,tv.version").bind(&ecosystem).bind(&package).bind(&version).fetch_all(&state.pool).await { Ok(r)=>r, Err(_)=>return StatusCode::INTERNAL_SERVER_ERROR.into_response() };
    if rows.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(json!({"ecosystem":ecosystem,"package":package,"version":version,"transitions":rows.into_iter().map(|r|json!({"from":r.get::<String,_>("from"),"to":r.get::<String,_>("to")})).collect::<Vec<_>>() })).into_response()
}

async fn transition_id(
    pool: &PgPool,
    ecosystem: &str,
    package: &str,
    from: &str,
    to: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT t.id FROM version_transitions t JOIN packages p ON p.id=t.package_id JOIN package_versions fv ON fv.id=t.from_version_id JOIN package_versions tv ON tv.id=t.to_version_id WHERE p.ecosystem=$1 AND p.name=$2 AND fv.version=$3 AND tv.version=$4").bind(ecosystem).bind(package).bind(from).bind(to).fetch_optional(pool).await?.ok_or(sqlx::Error::RowNotFound)
}
async fn grouped(pool: &PgPool, sql: &str, transition: i64) -> Result<Value, sqlx::Error> {
    let rows = sqlx::query(sql).bind(transition).fetch_all(pool).await?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|r| json!({"value":r.get::<String,_>("value"),"runs":r.get::<i64,_>("runs")}))
            .collect(),
    ))
}
async fn transition_lookup(
    State(state): State<AppState>,
    Path((ecosystem, package, from, to)): Path<(String, String, String, String)>,
) -> Response {
    tracing::info!(operation = "api.query", endpoint = "transition");
    let id = match transition_id(&state.pool, &ecosystem, &package, &from, &to).await {
        Ok(id) => id,
        Err(sqlx::Error::RowNotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let totals=match sqlx::query("SELECT count(*) AS runs, count(DISTINCT attestation_id) AS evidence, count(DISTINCT signer_id) AS signers FROM verification_runs r JOIN attestations a ON a.id=r.attestation_id WHERE r.transition_id=$1").bind(id).fetch_one(&state.pool).await { Ok(r)=>r, Err(_)=>return StatusCode::INTERNAL_SERVER_ERROR.into_response() };
    let runtime=grouped(&state.pool,"SELECT e.runtime AS value,count(*) AS runs FROM verification_runs r JOIN environments e ON e.id=r.environment_id WHERE r.transition_id=$1 GROUP BY e.runtime",id).await.unwrap_or(Value::Null);
    let os=grouped(&state.pool,"SELECT e.os AS value,count(*) AS runs FROM verification_runs r JOIN environments e ON e.id=r.environment_id WHERE r.transition_id=$1 GROUP BY e.os",id).await.unwrap_or(Value::Null);
    let architecture=grouped(&state.pool,"SELECT e.architecture AS value,count(*) AS runs FROM verification_runs r JOIN environments e ON e.id=r.environment_id WHERE r.transition_id=$1 GROUP BY e.architecture",id).await.unwrap_or(Value::Null);
    let outcome=grouped(&state.pool,"SELECT outcome AS value,count(*) AS runs FROM verification_runs WHERE transition_id=$1 GROUP BY outcome",id).await.unwrap_or(Value::Null);
    let methodology=grouped(&state.pool,"SELECT m.verification_methodology_version AS value,count(*) AS runs FROM verification_runs r JOIN methodology_versions m ON m.id=r.methodology_version_id WHERE r.transition_id=$1 GROUP BY m.verification_methodology_version",id).await.unwrap_or(Value::Null);
    let process=grouped(&state.pool,"SELECT process_observation_capability AS value,count(*) AS runs FROM verification_runs WHERE transition_id=$1 GROUP BY process_observation_capability",id).await.unwrap_or(Value::Null);
    let behavior=grouped(&state.pool,"SELECT kind AS value,count(*) AS runs FROM behavior_findings b JOIN verification_runs r ON r.id=b.verification_run_id WHERE r.transition_id=$1 GROUP BY kind",id).await.unwrap_or(Value::Null);
    let assurance=grouped(&state.pool,"SELECT s.assurance_tier AS value,count(*) AS runs FROM verification_runs r JOIN attestations a ON a.id=r.attestation_id JOIN signers s ON s.id=a.signer_id WHERE r.transition_id=$1 GROUP BY s.assurance_tier",id).await.unwrap_or(Value::Null);
    Json(json!({"transition":{"ecosystem":ecosystem,"package":package,"from":from,"to":to},"evidence":{"verificationRuns":totals.get::<i64,_>("runs"),"uniqueEvidence":totals.get::<i64,_>("evidence"),"uniqueSigners":totals.get::<i64,_>("signers"),"uniqueProjectFingerprints":Value::Null,"projectFingerprintAvailability":"NOT_PRESENT_IN_EVIDENCE_V1"},"environments":{"runtime":runtime,"os":os,"architecture":architecture},"methodologyVersions":methodology,"observationCapabilities":{"process":process,"network":"UNAVAILABLE_IN_EVIDENCE_V1"},"behaviorFindings":behavior,"signerAssurance":assurance,"outcomes":outcome})).into_response()
}
async fn transition_evidence(
    State(state): State<AppState>,
    Path((ecosystem, package, from, to)): Path<(String, String, String, String)>,
    Query(page): Query<Page>,
) -> Response {
    let id = match transition_id(&state.pool, &ecosystem, &package, &from, &to).await {
        Ok(v) => v,
        Err(sqlx::Error::RowNotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let limit = bounded_limit(&page);
    let cursor = page.cursor.unwrap_or_default();
    let mut rows=match sqlx::query("SELECT a.evidence_id,a.evidence_digest,a.accepted_at,r.outcome FROM verification_runs r JOIN attestations a ON a.id=r.attestation_id WHERE r.transition_id=$1 AND a.evidence_id>$2 ORDER BY a.evidence_id LIMIT $3").bind(id).bind(cursor).bind(limit + 1).fetch_all(&state.pool).await {Ok(v)=>v,Err(_)=>return StatusCode::INTERNAL_SERVER_ERROR.into_response()};
    let has_more = rows.len() as i64 > limit;
    if has_more {
        rows.pop();
    }
    let evidence:Vec<Value>=rows.into_iter().map(|r|json!({"evidenceId":r.get::<String,_>("evidence_id"),"evidenceDigest":r.get::<String,_>("evidence_digest"),"acceptedAt":r.get::<chrono::DateTime<chrono::Utc>,_>("accepted_at"),"outcome":r.get::<String,_>("outcome")})).collect();
    let next_cursor = has_more
        .then(|| evidence.last().and_then(|v| v.get("evidenceId")).cloned())
        .flatten();
    Json(json!({"evidence":evidence,"nextCursor":next_cursor})).into_response()
}

/// Current projections are SQL-derived at ingest; this establishes a worker-safe
/// rebuild boundary without another infrastructure dependency.
pub async fn rebuild_aggregates(_pool: &PgPool) -> anyhow::Result<()> {
    tracing::info!(operation = "transition.aggregate");
    Ok(())
}
