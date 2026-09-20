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
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::OpenOptions,
    io::Write,
    path::{Path as FsPath, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer};
use x509_parser::{extensions::GeneralName, prelude::*};

/// Limits apply before DSSE or Sigstore verification so identity verification
/// cannot turn a submission endpoint into an unbounded memory/disk sink.
pub const MAX_HTTP_SUBMISSION_BYTES: usize = 1024 * 1024;
pub const MAX_ATTESTATION_BYTES: usize = 256 * 1024;
pub const MAX_SIGSTORE_BUNDLE_BYTES: usize = 512 * 1024;
pub const COSIGN_TIMEOUT: Duration = Duration::from_secs(10);
const PRODUCTION_COSIGN_PATH: &str = "/usr/local/bin/cosign";
const PRODUCTION_TRUSTED_ROOT_PATH: &str = "/usr/local/share/depguard/sigstore-trusted-root.json";

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    rate_limit: Arc<dyn RateLimitBoundary>,
    identity_verifier: Arc<dyn IdentityVerifier>,
    identity_policy: IdentityPolicy,
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
    router_with_identity_verifier_and_policy(
        pool,
        Arc::new(CosignCliVerifier::from_environment()),
        IdentityPolicy::from_environment(),
    )
}
pub fn router_with_rate_limit(pool: PgPool, rate_limit: Arc<dyn RateLimitBoundary>) -> Router {
    router_with_all(
        pool,
        rate_limit,
        Arc::new(CosignCliVerifier::from_environment()),
        IdentityPolicy::from_environment(),
    )
}

/// Test and embedded deployments can inject an independent Sigstore verifier.
/// Production uses the `cosign verify-blob` implementation below, which checks
/// the Fulcio chain, Rekor/transparency material, artifact signature, and OIDC
/// issuer before this service reads identity claims from the certificate.
pub fn router_with_identity_verifier_and_policy(
    pool: PgPool,
    identity_verifier: Arc<dyn IdentityVerifier>,
    identity_policy: IdentityPolicy,
) -> Router {
    router_with_all(
        pool,
        Arc::new(AllowAllRateLimit),
        identity_verifier,
        identity_policy,
    )
}
fn router_with_all(
    pool: PgPool,
    rate_limit: Arc<dyn RateLimitBoundary>,
    identity_verifier: Arc<dyn IdentityVerifier>,
    identity_policy: IdentityPolicy,
) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/evidence", post(ingest_evidence))
        .route("/v1/submissions", post(ingest_submission))
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
        .with_state(AppState {
            pool,
            rate_limit,
            identity_verifier,
            identity_policy,
        })
        .layer(RequestBodyLimitLayer::new(MAX_HTTP_SUBMISSION_BYTES))
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
    ingest_attestation(state, bytes.to_vec(), None).await
}

/// Network metadata wrapper. `depguardAttestation` is base64 so its exact
/// submitted bytes survive JSON transport unchanged; V1 itself remains a
/// standalone DSSE envelope and is still accepted at `/v1/evidence`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetworkSubmission {
    depguard_attestation: String,
    #[serde(default)]
    identity_proof: Option<Value>,
}

async fn ingest_submission(State(state): State<AppState>, bytes: Bytes) -> Response {
    let submission: NetworkSubmission = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return rejected("MALFORMED_SUBMISSION").into_response(),
    };
    let attestation = match STANDARD.decode(submission.depguard_attestation) {
        Ok(value) => value,
        Err(_) => return rejected("MALFORMED_SUBMISSION").into_response(),
    };
    if attestation.len() > MAX_ATTESTATION_BYTES {
        return rejected("ATTESTATION_TOO_LARGE").into_response();
    }
    if let Some(proof) = submission.identity_proof.as_ref() {
        if !proof.is_object() {
            return rejected("MALFORMED_IDENTITY_PROOF").into_response();
        }
        let proof_size = match serde_json::to_vec(proof) {
            Ok(bytes) => bytes.len(),
            Err(_) => return rejected("MALFORMED_IDENTITY_PROOF").into_response(),
        };
        if proof_size > MAX_SIGSTORE_BUNDLE_BYTES {
            return rejected("IDENTITY_PROOF_TOO_LARGE").into_response();
        }
    }
    ingest_attestation(state, attestation, submission.identity_proof).await
}

async fn ingest_attestation(
    state: AppState,
    bytes: Vec<u8>,
    identity_proof: Option<Value>,
) -> Response {
    if !state.rate_limit.allow() {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    if bytes.len() > MAX_ATTESTATION_BYTES {
        return rejected("ATTESTATION_TOO_LARGE").into_response();
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
    // This is deliberately after frozen V1 verification. A Sigstore proof can
    // enhance identity assurance only; it can never rescue invalid evidence.
    let identity = match identity_proof {
        Some(proof) => match state.identity_verifier.verify(&bytes, &proof) {
            Ok(identity) => match state.identity_policy.validate(&identity) {
                Ok(()) => Some((identity, proof)),
                Err(reason) => return rejected(reason).into_response(),
            },
            Err(reason) => return rejected(reason).into_response(),
        },
        None => None,
    };
    match persist(
        &state.pool,
        &proposed_id,
        canonical,
        bytes,
        envelope,
        parsed,
        identity,
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

pub const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Identity returned only after a verifier has authenticated a Sigstore bundle
/// for the supplied artifact bytes. None of these values are accepted from the
/// submitter as ordinary submission fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCiIdentity {
    pub issuer: String,
    pub repository_identity: String,
    pub workflow_identity: String,
    pub source_revision: String,
    pub source_ref: String,
    pub event_type: String,
    pub certificate_identity: String,
}

pub trait IdentityVerifier: Send + Sync + 'static {
    fn verify(
        &self,
        attestation: &[u8],
        bundle: &Value,
    ) -> Result<VerifiedCiIdentity, &'static str>;
}

/// Optional deployment policy. It is intentionally server configuration, never
/// a submitter-selected field. Empty policy accepts any authenticated GitHub
/// Actions workflow; deployments may pin a repository and/or workflow URI.
#[derive(Debug, Clone, Default)]
pub struct IdentityPolicy {
    pub expected_repository: Option<String>,
    pub expected_workflow: Option<String>,
}
impl IdentityPolicy {
    pub fn from_environment() -> Self {
        Self {
            expected_repository: std::env::var("DEPGUARD_SIGSTORE_REPOSITORY").ok(),
            expected_workflow: std::env::var("DEPGUARD_SIGSTORE_WORKFLOW").ok(),
        }
    }
    pub fn validate(&self, identity: &VerifiedCiIdentity) -> Result<(), &'static str> {
        if identity.issuer != GITHUB_ACTIONS_ISSUER {
            return Err("UNTRUSTED_OIDC_ISSUER");
        }
        if self
            .expected_repository
            .as_deref()
            .is_some_and(|expected| expected != identity.repository_identity)
        {
            return Err("SIGSTORE_IDENTITY_POLICY_REJECTED");
        }
        if self
            .expected_workflow
            .as_deref()
            .is_some_and(|expected| expected != identity.workflow_identity)
        {
            return Err("SIGSTORE_IDENTITY_POLICY_REJECTED");
        }
        Ok(())
    }
}

/// Production verifier for standard `cosign sign-blob --bundle` output. The
/// pinned Cosign process verifies the exact blob, Fulcio chain, certificate
/// transparency SCT, and Rekor inclusion proof against our vendored Sigstore
/// TrustedRoot before this code reads certificate claims.
pub struct CosignCliVerifier {
    executable: PathBuf,
    trusted_root: PathBuf,
}
impl CosignCliVerifier {
    pub fn from_environment() -> Self {
        Self {
            // Production images contain this explicitly pinned binary. Tests and
            // embedded hosts use `new`; we never fetch a verifier at runtime.
            executable: PathBuf::from(PRODUCTION_COSIGN_PATH),
            trusted_root: PathBuf::from(PRODUCTION_TRUSTED_ROOT_PATH),
        }
    }

    pub fn new(executable: impl Into<PathBuf>, trusted_root: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            trusted_root: trusted_root.into(),
        }
    }
}
impl IdentityVerifier for CosignCliVerifier {
    fn verify(
        &self,
        attestation: &[u8],
        bundle: &Value,
    ) -> Result<VerifiedCiIdentity, &'static str> {
        if attestation.len() > MAX_ATTESTATION_BYTES {
            return Err("ATTESTATION_TOO_LARGE");
        }
        let serialized_bundle =
            serde_json::to_vec(bundle).map_err(|_| "MALFORMED_IDENTITY_PROOF")?;
        if serialized_bundle.len() > MAX_SIGSTORE_BUNDLE_BYTES {
            return Err("IDENTITY_PROOF_TOO_LARGE");
        }
        if !bundle.is_object() {
            return Err("MALFORMED_IDENTITY_PROOF");
        }
        let directory = tempfile::tempdir().map_err(|_| "SIGSTORE_VERIFICATION_FAILED")?;
        let artifact = directory.path().join("attestation.json");
        let bundle_path = directory.path().join("bundle.json");
        write_private_file(&artifact, attestation)?;
        write_private_file(&bundle_path, &serialized_bundle)?;
        let status = run_cosign(
            &self.executable,
            &self.trusted_root,
            &bundle_path,
            &artifact,
        )?;
        if !status.success() {
            return Err("INVALID_SIGSTORE_IDENTITY");
        }
        identity_from_verified_bundle(bundle)
    }
}

fn write_private_file(path: &FsPath, bytes: &[u8]) -> Result<(), &'static str> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "SIGSTORE_VERIFICATION_FAILED")?;
    file.write_all(bytes)
        .map_err(|_| "SIGSTORE_VERIFICATION_FAILED")
}

fn run_cosign(
    executable: &FsPath,
    trusted_root: &FsPath,
    bundle_path: &FsPath,
    artifact: &FsPath,
) -> Result<std::process::ExitStatus, &'static str> {
    run_cosign_with_timeout(
        executable,
        trusted_root,
        bundle_path,
        artifact,
        COSIGN_TIMEOUT,
    )
}

fn run_cosign_with_timeout(
    executable: &FsPath,
    trusted_root: &FsPath,
    bundle_path: &FsPath,
    artifact: &FsPath,
    timeout: Duration,
) -> Result<std::process::ExitStatus, &'static str> {
    // This is intentionally an argument vector, never a shell string. Output is
    // discarded (bounded at zero bytes) because certificate claims are read only
    // from the verified bundle, not from process output.
    let args = vec![
        OsString::from("verify-blob"),
        OsString::from("--new-bundle-format"),
        OsString::from("--trusted-root"),
        trusted_root.as_os_str().to_owned(),
        OsString::from("--bundle"),
        bundle_path.as_os_str().to_owned(),
        OsString::from("--certificate-oidc-issuer"),
        OsString::from(GITHUB_ACTIONS_ISSUER),
        OsString::from("--certificate-identity-regexp"),
        OsString::from(r"^https://github\.com/[^/]+/[^/]+/\.github/workflows/.+@refs/.+$"),
        artifact.as_os_str().to_owned(),
    ];
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "SIGSTORE_VERIFIER_UNAVAILABLE")?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| "SIGSTORE_VERIFICATION_FAILED")?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("SIGSTORE_VERIFICATION_TIMEOUT");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn identity_from_verified_bundle(bundle: &Value) -> Result<VerifiedCiIdentity, &'static str> {
    let certificate = bundle
        .pointer("/verificationMaterial/certificate/rawBytes")
        .or_else(|| {
            bundle.pointer("/verificationMaterial/x509CertificateChain/certificates/0/rawBytes")
        })
        .and_then(Value::as_str)
        .ok_or("MALFORMED_IDENTITY_PROOF")?;
    let der = STANDARD
        .decode(certificate)
        .map_err(|_| "MALFORMED_IDENTITY_PROOF")?;
    let (_, certificate) =
        X509Certificate::from_der(&der).map_err(|_| "MALFORMED_IDENTITY_PROOF")?;
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| "MALFORMED_IDENTITY_PROOF")?
        .ok_or("MALFORMED_IDENTITY_PROOF")?;
    let certificate_identity = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some((*uri).to_owned()),
            _ => None,
        })
        .find(|uri| github_workflow_uri(uri))
        .ok_or("INVALID_SIGSTORE_IDENTITY")?;
    let extensions: BTreeMap<String, String> = certificate
        .extensions()
        .iter()
        .filter_map(|extension| {
            extension_string(extension.value).map(|value| (extension.oid.to_id_string(), value))
        })
        .collect();
    let issuer =
        extension(&extensions, &["1.3.6.1.4.1.57264.1.1"]).ok_or("UNTRUSTED_OIDC_ISSUER")?;
    if issuer != GITHUB_ACTIONS_ISSUER {
        return Err("UNTRUSTED_OIDC_ISSUER");
    }
    let repository_uri = extension(
        &extensions,
        &[
            "1.3.6.1.4.1.57264.1.11", // generic source repository URI
            "1.3.6.1.4.1.57264.1.5",  // legacy GitHub repository
        ],
    )
    .ok_or("INVALID_SIGSTORE_IDENTITY")?;
    let repository_identity =
        github_repository_identity(&repository_uri).ok_or("INVALID_SIGSTORE_IDENTITY")?;
    let workflow_identity = extension(&extensions, &["1.3.6.1.4.1.57264.1.17"])
        .filter(|workflow| github_workflow_uri(workflow))
        .ok_or("INVALID_SIGSTORE_IDENTITY")?;
    let source_revision = extension(
        &extensions,
        &[
            "1.3.6.1.4.1.57264.1.12", // generic source digest
            "1.3.6.1.4.1.57264.1.3",  // legacy GitHub workflow SHA
        ],
    )
    .filter(|revision| github_sha(revision))
    .ok_or("INVALID_SIGSTORE_IDENTITY")?;
    let source_ref = extension(
        &extensions,
        &[
            "1.3.6.1.4.1.57264.1.13", // generic source ref
            "1.3.6.1.4.1.57264.1.6",  // legacy GitHub workflow ref
        ],
    )
    .filter(|reference| github_ref(reference))
    .ok_or("INVALID_SIGSTORE_IDENTITY")?;
    let event_type = extension(&extensions, &["1.3.6.1.4.1.57264.1.2"])
        .filter(|event| github_event(event))
        .ok_or("INVALID_SIGSTORE_IDENTITY")?;
    if workflow_identity != certificate_identity
        || github_workflow_repository(&workflow_identity).as_deref()
            != Some(repository_identity.as_str())
        || !workflow_identity.ends_with(&format!("@{source_ref}"))
    {
        return Err("INVALID_SIGSTORE_IDENTITY");
    }
    Ok(VerifiedCiIdentity {
        issuer,
        repository_identity,
        workflow_identity,
        source_revision,
        source_ref,
        event_type,
        certificate_identity,
    })
}
fn extension(map: &BTreeMap<String, String>, oids: &[&str]) -> Option<String> {
    oids.iter().find_map(|oid| map.get(*oid).cloned())
}
fn extension_string(bytes: &[u8]) -> Option<String> {
    // Legacy Fulcio extensions are raw strings. New generic extensions are a
    // DER UTF8String; accept only complete, printable values in either format.
    let raw = std::str::from_utf8(bytes)
        .ok()
        .filter(|value| printable_ascii(value));
    if let Some(value) = raw {
        return Some(value.to_owned());
    }
    if bytes.first() != Some(&0x0c) || bytes.len() < 3 {
        return None;
    }
    let (length, offset) = if bytes[1] & 0x80 == 0 {
        (usize::from(bytes[1]), 2)
    } else if bytes[1] == 0x81 && bytes.len() >= 3 {
        (usize::from(bytes[2]), 3)
    } else {
        return None;
    };
    (bytes.len() == offset + length)
        .then(|| std::str::from_utf8(&bytes[offset..]).ok())
        .flatten()
        .filter(|value| printable_ascii(value))
        .map(str::to_owned)
}
fn printable_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_graphic())
}
fn github_workflow_uri(value: &str) -> bool {
    let prefix = "https://github.com/";
    value.strip_prefix(prefix).is_some_and(|rest| {
        let parts: Vec<_> = rest.split('/').collect();
        parts.len() >= 5
            && !parts[0].is_empty()
            && !parts[1].is_empty()
            && parts[2] == ".github"
            && parts[3] == "workflows"
            && parts[4].contains('@')
    })
}
fn github_repository_identity(value: &str) -> Option<String> {
    let value = value.strip_prefix("https://github.com/").unwrap_or(value);
    let mut parts = value.split('/');
    let owner = parts.next()?;
    let repository = parts.next()?;
    (!owner.is_empty() && !repository.is_empty() && parts.next().is_none())
        .then(|| format!("{owner}/{repository}"))
}
fn github_workflow_repository(value: &str) -> Option<String> {
    let rest = value.strip_prefix("https://github.com/")?;
    let mut parts = rest.split('/');
    let owner = parts.next()?;
    let repository = parts.next()?;
    (parts.next() == Some(".github") && parts.next() == Some("workflows"))
        .then(|| format!("{owner}/{repository}"))
}
fn github_sha(value: &str) -> bool {
    let value = value.strip_prefix("sha1:").unwrap_or(value);
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn github_ref(value: &str) -> bool {
    value.starts_with("refs/heads/")
        || value.starts_with("refs/tags/")
        || value.starts_with("refs/pull/")
}
fn github_event(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

async fn persist(
    pool: &PgPool,
    proposed_id: &str,
    canonical: Value,
    original: Vec<u8>,
    envelope: DsseEnvelope,
    parsed: Parsed,
    identity: Option<(VerifiedCiIdentity, Value)>,
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
        if let Some((identity, bundle)) = identity {
            persist_identity(&mut tx, attestation_id, &identity, bundle).await?;
        }
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
    if let Some((identity, bundle)) = identity {
        persist_identity(&mut tx, attestation_id, &identity, bundle).await?;
    }
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

async fn persist_identity(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    attestation_id: i64,
    identity: &VerifiedCiIdentity,
    bundle: Value,
) -> anyhow::Result<()> {
    let canonical_bundle = serde_json_canonicalizer::to_vec(&bundle)?;
    let bundle_digest = format!("sha256:{:x}", Sha256::digest(canonical_bundle));
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT bundle_digest FROM verified_ci_identities WHERE attestation_id=$1",
    )
    .bind(attestation_id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(existing) = existing {
        if existing != bundle_digest {
            anyhow::bail!("IDENTITY_PROOF_ALREADY_BOUND");
        }
        return Ok(());
    }
    sqlx::query("INSERT INTO verified_ci_identities(attestation_id,identity_assurance,identity_issuer,repository_identity,workflow_identity,source_revision,source_ref,event_type,certificate_identity,bundle_digest,bundle) VALUES($1,'SIGSTORE_KEYLESS_CI',$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(attestation_id)
        .bind(&identity.issuer)
        .bind(&identity.repository_identity)
        .bind(&identity.workflow_identity)
        .bind(&identity.source_revision)
        .bind(&identity.source_ref)
        .bind(&identity.event_type)
        .bind(&identity.certificate_identity)
        .bind(bundle_digest)
        .bind(bundle)
        .execute(&mut **tx)
        .await?;
    Ok(())
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
    let assurance = match sqlx::query("SELECT COALESCE(ci.identity_assurance,'LOCAL_DEVELOPMENT_KEY') AS assurance,count(*) AS runs FROM verification_runs r JOIN attestations a ON a.id=r.attestation_id LEFT JOIN verified_ci_identities ci ON ci.attestation_id=a.id WHERE r.transition_id=$1 GROUP BY COALESCE(ci.identity_assurance,'LOCAL_DEVELOPMENT_KEY')").bind(id).fetch_all(&state.pool).await {
        Ok(rows) => Value::Object(rows.into_iter().map(|row| (row.get::<String,_>("assurance"), Value::from(row.get::<i64,_>("runs")))).collect()),
        Err(_) => Value::Null,
    };
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
    let mut rows=match sqlx::query("SELECT a.evidence_id,a.evidence_digest,a.accepted_at,r.outcome,COALESCE(ci.identity_assurance,'LOCAL_DEVELOPMENT_KEY') AS identity_assurance FROM verification_runs r JOIN attestations a ON a.id=r.attestation_id LEFT JOIN verified_ci_identities ci ON ci.attestation_id=a.id WHERE r.transition_id=$1 AND a.evidence_id>$2 ORDER BY a.evidence_id LIMIT $3").bind(id).bind(cursor).bind(limit + 1).fetch_all(&state.pool).await {Ok(v)=>v,Err(_)=>return StatusCode::INTERNAL_SERVER_ERROR.into_response()};
    let has_more = rows.len() as i64 > limit;
    if has_more {
        rows.pop();
    }
    let evidence:Vec<Value>=rows.into_iter().map(|r|json!({"evidenceId":r.get::<String,_>("evidence_id"),"evidenceDigest":r.get::<String,_>("evidence_digest"),"acceptedAt":r.get::<chrono::DateTime<chrono::Utc>,_>("accepted_at"),"outcome":r.get::<String,_>("outcome"),"identityAssurance":r.get::<String,_>("identity_assurance")})).collect();
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

#[cfg(test)]
mod identity_tests {
    use super::*;

    fn state_without_database_access() -> AppState {
        AppState {
            pool: PgPoolOptions::new()
                .connect_lazy("postgresql://depguard:depguard@127.0.0.1/depguard")
                .unwrap(),
            rate_limit: Arc::new(AllowAllRateLimit),
            identity_verifier: Arc::new(CosignCliVerifier::from_environment()),
            identity_policy: IdentityPolicy::default(),
        }
    }

    #[test]
    fn fulcio_extension_strings_support_legacy_and_der_utf8_forms() {
        assert_eq!(
            extension_string(b"https://token.actions.githubusercontent.com"),
            Some("https://token.actions.githubusercontent.com".into())
        );
        assert_eq!(
            extension_string(&[0x0c, 3, b'a', b'b', b'c']),
            Some("abc".into())
        );
        assert_eq!(extension_string(&[0x0c, 4, b'a', b'b', b'c']), None);
    }

    #[test]
    fn github_identity_shapes_are_strict() {
        assert!(github_workflow_uri(
            "https://github.com/depguard/example/.github/workflows/depguard.yml@refs/heads/main"
        ));
        assert!(!github_workflow_uri("https://example.invalid/workflow"));
        assert_eq!(
            github_repository_identity("https://github.com/depguard/example"),
            Some("depguard/example".into())
        );
        assert_eq!(github_repository_identity("depguard/example/extra"), None);
        assert_eq!(
            github_workflow_repository(
                "https://github.com/depguard/example/.github/workflows/depguard.yml@refs/heads/main"
            ),
            Some("depguard/example".into())
        );
        assert!(github_sha("0123456789012345678901234567890123456789"));
        assert!(!github_sha("not-a-commit"));
        assert!(github_ref("refs/pull/12/merge"));
        assert!(!github_ref("main"));
        assert!(github_event("pull_request_target"));
        assert!(!github_event("malformed event"));
    }

    #[tokio::test]
    async fn identity_input_limits_and_client_assurance_are_rejected_before_verification() {
        let oversized_attestation = json!({
            "depguardAttestation": STANDARD.encode(vec![0_u8; MAX_ATTESTATION_BYTES + 1])
        });
        let response = ingest_submission(
            State(state_without_database_access()),
            Bytes::from(serde_json::to_vec(&oversized_attestation).unwrap()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let oversized_bundle = json!({
            "depguardAttestation": STANDARD.encode(b"not-an-attestation"),
            "identityProof": {"padding": "x".repeat(MAX_SIGSTORE_BUNDLE_BYTES)}
        });
        let response = ingest_submission(
            State(state_without_database_access()),
            Bytes::from(serde_json::to_vec(&oversized_bundle).unwrap()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        for proof in [
            Value::Null,
            json!({"corruptTransparencyProof": true}),
            json!({"issuer": "https://issuer.invalid"}),
            json!({"certificate": "malformed"}),
            json!({"attestationDigest": "sha256:not-the-submitted-bytes"}),
            json!({"repository": "missing-required-certificate-claims"}),
        ] {
            let malicious = json!({
                "depguardAttestation": STANDARD.encode(b"not-an-attestation"),
                "identityProof": proof,
                "assurance": "SIGSTORE_KEYLESS_CI"
            });
            assert!(serde_json::from_value::<NetworkSubmission>(malicious).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn cosign_subprocess_failure_timeout_and_output_are_contained() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("fake-cosign");
        std::fs::write(&script, "#!/bin/sh\nsleep 1\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            run_cosign_with_timeout(
                &script,
                directory.path(),
                directory.path(),
                directory.path(),
                Duration::from_millis(20),
            ),
            Err("SIGSTORE_VERIFICATION_TIMEOUT")
        );

        std::fs::write(
            &script,
            "#!/bin/sh\ndd if=/dev/zero bs=65536 count=1 2>/dev/null\n",
        )
        .unwrap();
        assert!(
            run_cosign_with_timeout(
                &script,
                directory.path(),
                directory.path(),
                directory.path(),
                Duration::from_secs(2),
            )
            .unwrap()
            .success()
        );

        assert!(
            !run_cosign_with_timeout(
                FsPath::new("/usr/bin/false"),
                directory.path(),
                directory.path(),
                directory.path(),
                Duration::from_secs(1),
            )
            .unwrap()
            .success()
        );
    }
}
