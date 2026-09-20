//! The frozen V1 local attestation protocol: DSSE, in-toto, and Ed25519.
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use depguard_evidence::{
    PublicCompatibilityEvidenceV1, SCHEMA_VERSION, VERIFICATION_METHODOLOGY_VERSION,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub const PREDICATE_TYPE: &str = "https://depguard.dev/attestation/compatibility/v1";
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const LOCAL_DEVELOPMENT_KEY: &str = "LOCAL_DEVELOPMENT_KEY";

/// Stable machine-readable verification failures for the public V1 protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Error)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationError {
    #[error("MALFORMED_DSSE")]
    MalformedDsse,
    #[error("INVALID_SIGNATURE")]
    InvalidSignature,
    #[error("UNSUPPORTED_PAYLOAD_TYPE")]
    UnsupportedPayloadType,
    #[error("INVALID_STATEMENT")]
    InvalidStatement,
    #[error("UNSUPPORTED_PREDICATE")]
    UnsupportedPredicate,
    #[error("SCHEMA_VALIDATION_FAILED")]
    SchemaValidationFailed,
    #[error("UNSUPPORTED_SCHEMA")]
    UnsupportedSchema,
    #[error("UNSUPPORTED_METHODOLOGY")]
    UnsupportedMethodology,
    #[error("INVALID_EVIDENCE_DIGEST")]
    InvalidEvidenceDigest,
    #[error("INVALID_SUBJECT")]
    InvalidSubject,
    #[error("INVALID_ARTIFACT_RELATIONSHIP")]
    InvalidArtifactRelationship,
}

impl VerificationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::MalformedDsse => "MALFORMED_DSSE",
            Self::InvalidSignature => "INVALID_SIGNATURE",
            Self::UnsupportedPayloadType => "UNSUPPORTED_PAYLOAD_TYPE",
            Self::InvalidStatement => "INVALID_STATEMENT",
            Self::UnsupportedPredicate => "UNSUPPORTED_PREDICATE",
            Self::SchemaValidationFailed => "SCHEMA_VALIDATION_FAILED",
            Self::UnsupportedSchema => "UNSUPPORTED_SCHEMA",
            Self::UnsupportedMethodology => "UNSUPPORTED_METHODOLOGY",
            Self::InvalidEvidenceDigest => "INVALID_EVIDENCE_DIGEST",
            Self::InvalidSubject => "INVALID_SUBJECT",
            Self::InvalidArtifactRelationship => "INVALID_ARTIFACT_RELATIONSHIP",
        }
    }
    /// Stable CLI grouping: wire/syntax, signature, protocol support, or evidence consistency.
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::MalformedDsse => 41,
            Self::InvalidSignature => 42,
            Self::UnsupportedPayloadType
            | Self::UnsupportedPredicate
            | Self::UnsupportedSchema
            | Self::UnsupportedMethodology => 43,
            Self::InvalidStatement
            | Self::SchemaValidationFailed
            | Self::InvalidEvidenceDigest
            | Self::InvalidSubject
            | Self::InvalidArtifactRelationship => 44,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DsseEnvelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<SignatureEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub keyid: String,
    pub sig: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Predicate,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Predicate {
    pub evidence: PublicCompatibilityEvidenceV1,
    pub compatibility_evidence_digest: String,
    pub signer_assurance: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationSummary {
    pub evidence_schema_version: String,
    pub verification_methodology_version: String,
    pub predicate_type: String,
    pub signer_assurance: String,
}

pub fn ephemeral_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}
pub fn signing_key_from_base64(value: &str) -> Result<SigningKey> {
    let bytes = STANDARD.decode(value.trim())?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 private key"))?;
    Ok(SigningKey::from_bytes(&array))
}
pub fn verifying_key_from_base64(value: &str) -> Result<VerifyingKey> {
    let bytes = STANDARD.decode(value.trim())?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 public key"))?;
    Ok(VerifyingKey::from_bytes(&array)?)
}
/// Derive the V1 Ed25519 public key from the envelope key identifier.  V1 local
/// development attestations use the lowercase hexadecimal public-key encoding.
/// This lets a verifier validate an independently supplied envelope without a
/// side channel while preserving the frozen V1 verification rules.
pub fn verifying_key_from_keyid(
    keyid: &str,
) -> std::result::Result<VerifyingKey, VerificationError> {
    let bytes = hex::decode(keyid).map_err(|_| VerificationError::MalformedDsse)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VerificationError::MalformedDsse)?;
    VerifyingKey::from_bytes(&array).map_err(|_| VerificationError::MalformedDsse)
}

/// Verify a self-describing V1 local-development envelope. This is the same
/// verifier used by the CLI; only public-key discovery is supplied by V1 keyid.
pub fn verify_envelope(
    envelope: &DsseEnvelope,
) -> std::result::Result<VerificationSummary, VerificationError> {
    if envelope.signatures.len() != 1 {
        return Err(VerificationError::MalformedDsse);
    }
    let key = verifying_key_from_keyid(&envelope.signatures[0].keyid)?;
    verify(envelope, &key)
}
pub fn private_key_base64(key: &SigningKey) -> String {
    STANDARD.encode(key.to_bytes())
}
pub fn public_key_base64(key: &VerifyingKey) -> String {
    STANDARD.encode(key.to_bytes())
}

/// DSSE PAE exactly as specified by DSSEv1. Lengths are UTF-8 byte lengths.
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    pae.extend_from_slice(payload);
    pae
}

pub fn sign(evidence: PublicCompatibilityEvidenceV1, key: &SigningKey) -> Result<DsseEnvelope> {
    let digest = evidence.digest()?;
    let mut candidate = BTreeMap::new();
    candidate.insert(
        "sha256".into(),
        evidence
            .artifacts
            .candidate_artifact_digest
            .trim_start_matches("sha256:")
            .into(),
    );
    let statement = InTotoStatement {
        statement_type: STATEMENT_TYPE.into(),
        subject: vec![Subject {
            name: evidence.subject.candidate.purl.clone(),
            digest: candidate,
        }],
        predicate_type: PREDICATE_TYPE.into(),
        predicate: Predicate {
            evidence,
            compatibility_evidence_digest: digest,
            signer_assurance: LOCAL_DEVELOPMENT_KEY.into(),
        },
    };
    let payload = serde_json_canonicalizer::to_vec(&statement)?;
    let signature = key.sign(&dsse_pae(PAYLOAD_TYPE, &payload));
    Ok(DsseEnvelope {
        payload_type: PAYLOAD_TYPE.into(),
        payload: STANDARD.encode(payload),
        signatures: vec![SignatureEntry {
            keyid: hex::encode(key.verifying_key().to_bytes()),
            sig: STANDARD.encode(signature.to_bytes()),
        }],
    })
}

/// Verify a V1 envelope without network access.
pub fn verify(
    envelope: &DsseEnvelope,
    key: &VerifyingKey,
) -> std::result::Result<VerificationSummary, VerificationError> {
    if envelope.payload_type != PAYLOAD_TYPE {
        return Err(VerificationError::UnsupportedPayloadType);
    }
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|_| VerificationError::MalformedDsse)?;
    if envelope.signatures.len() != 1 {
        return Err(VerificationError::MalformedDsse);
    }
    let signature = &envelope.signatures[0];
    let bytes = STANDARD
        .decode(&signature.sig)
        .map_err(|_| VerificationError::MalformedDsse)?;
    let sig = Signature::from_slice(&bytes).map_err(|_| VerificationError::MalformedDsse)?;
    if signature.keyid != hex::encode(key.to_bytes())
        || key.verify(&dsse_pae(PAYLOAD_TYPE, &payload), &sig).is_err()
    {
        return Err(VerificationError::InvalidSignature);
    }
    let raw_statement: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|_| VerificationError::InvalidStatement)?;
    let raw_evidence = raw_statement
        .pointer("/predicate/evidence")
        .ok_or(VerificationError::InvalidStatement)?;
    validate_raw_evidence(raw_evidence)?;
    let statement: InTotoStatement =
        serde_json::from_value(raw_statement).map_err(|_| VerificationError::InvalidStatement)?;
    if statement.statement_type != STATEMENT_TYPE {
        return Err(VerificationError::InvalidStatement);
    }
    if statement.predicate_type != PREDICATE_TYPE {
        return Err(VerificationError::UnsupportedPredicate);
    }
    if statement.predicate.signer_assurance != LOCAL_DEVELOPMENT_KEY {
        return Err(VerificationError::InvalidStatement);
    }
    validate_evidence(&statement.predicate.evidence)?;
    let actual = statement
        .predicate
        .evidence
        .digest()
        .map_err(|_| VerificationError::SchemaValidationFailed)?;
    if actual != statement.predicate.compatibility_evidence_digest {
        return Err(VerificationError::InvalidEvidenceDigest);
    }
    validate_subject(&statement)?;
    Ok(VerificationSummary {
        evidence_schema_version: statement
            .predicate
            .evidence
            .methodology
            .evidence_schema_version,
        verification_methodology_version: statement
            .predicate
            .evidence
            .methodology
            .verification_methodology_version,
        predicate_type: statement.predicate_type,
        signer_assurance: statement.predicate.signer_assurance,
    })
}

fn validate_evidence(
    evidence: &PublicCompatibilityEvidenceV1,
) -> std::result::Result<(), VerificationError> {
    if evidence.schema != SCHEMA_VERSION
        || evidence.methodology.evidence_schema_version != SCHEMA_VERSION
    {
        return Err(VerificationError::UnsupportedSchema);
    }
    if evidence.methodology.verification_methodology_version != VERIFICATION_METHODOLOGY_VERSION {
        return Err(VerificationError::UnsupportedMethodology);
    }
    evidence
        .validate()
        .map_err(|_| VerificationError::SchemaValidationFailed)?;
    let expected_baseline = format!(
        "pkg:{}/{}@{}",
        evidence.subject.ecosystem, evidence.subject.package, evidence.subject.baseline.version
    );
    let expected_candidate = format!(
        "pkg:{}/{}@{}",
        evidence.subject.ecosystem, evidence.subject.package, evidence.subject.candidate.version
    );
    if evidence.subject.baseline.purl != expected_baseline
        || evidence.subject.candidate.purl != expected_candidate
    {
        return Err(VerificationError::InvalidArtifactRelationship);
    }
    Ok(())
}
fn validate_raw_evidence(value: &serde_json::Value) -> std::result::Result<(), VerificationError> {
    if value.get("schema").and_then(serde_json::Value::as_str) != Some(SCHEMA_VERSION)
        || value
            .pointer("/methodology/evidenceSchemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(SCHEMA_VERSION)
    {
        return Err(VerificationError::UnsupportedSchema);
    }
    if value
        .pointer("/methodology/verificationMethodologyVersion")
        .and_then(serde_json::Value::as_str)
        != Some(VERIFICATION_METHODOLOGY_VERSION)
    {
        return Err(VerificationError::UnsupportedMethodology);
    }
    depguard_evidence::validate_json_value(value)
        .map_err(|_| VerificationError::SchemaValidationFailed)
}
fn validate_subject(statement: &InTotoStatement) -> std::result::Result<(), VerificationError> {
    if statement.subject.len() != 1 {
        return Err(VerificationError::InvalidSubject);
    }
    let subject = &statement.subject[0];
    let expected = statement
        .predicate
        .evidence
        .artifacts
        .candidate_artifact_digest
        .trim_start_matches("sha256:");
    if subject.name != statement.predicate.evidence.subject.candidate.purl
        || subject.digest.len() != 1
        || subject.digest.get("sha256").map(String::as_str) != Some(expected)
    {
        return Err(VerificationError::InvalidSubject);
    }
    Ok(())
}
