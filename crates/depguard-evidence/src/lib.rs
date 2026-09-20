//! Public, versioned compatibility evidence. Internal verifier types never form this protocol.
use anyhow::{Context, Result, bail};
use depguard_core::{
    BehaviorObservation, CommandResult, ExternalIntelligence, PackageCoordinate,
    ProvenanceEvidence, sha256_bytes,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "1";
pub const SCHEMA_ID: &str = "https://depguard.dev/schemas/compatibility-evidence/v1.schema.json";
pub const VERIFICATION_METHODOLOGY_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PublicCompatibilityEvidenceV1 {
    pub schema: String,
    pub subject: Subject,
    pub environment: Environment,
    pub artifacts: Artifacts,
    pub verification: BTreeMap<String, Vec<PublicCommand>>,
    pub observations: Observations,
    pub external_intelligence: Vec<PublicIntelligence>,
    pub policy: Policy,
    pub capabilities: Capabilities,
    pub methodology: Methodology,
    pub missing_evidence: Vec<MissingEvidence>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub ecosystem: String,
    pub package: String,
    pub baseline: PackageRef,
    pub candidate: PackageRef,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PackageRef {
    pub version: String,
    pub purl: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub os: String,
    pub architecture: String,
    pub runtime: String,
    pub package_manager: String,
    pub sandbox_backend: String,
    pub container_image_reference: String,
    pub container_image_digest: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Artifacts {
    pub baseline_artifact_digest: String,
    pub candidate_artifact_digest: String,
    pub baseline_registry_integrity: Option<String>,
    pub candidate_registry_integrity: Option<String>,
    pub baseline_lockfile_digest: String,
    pub candidate_lockfile_digest: String,
    pub baseline_dependency_graph_digest: String,
    pub candidate_dependency_graph_digest: String,
    pub behavior_evidence_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicCommandStatus {
    Passed,
    Failed,
    NotConfigured,
    Timeout,
    Error,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PublicCommand {
    pub name: String,
    pub status: PublicCommandStatus,
    pub exit_code: Option<i32>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Observations {
    pub filesystem: Vec<depguard_core::FileObservation>,
    pub processes: Vec<depguard_core::ProcessObservation>,
    pub network_observation_status: String,
    pub sandbox_network_policy: String,
    pub resources: Resources,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub wall_time: Metric,
    pub peak_memory: Metric,
    pub cpu: Metric,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Metric {
    pub status: String,
    pub milliseconds: Option<u128>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PublicIntelligence {
    pub provider: String,
    pub status: String,
    pub source_identifier: Option<String>,
    pub findings: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub outcome: String,
    pub findings: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub status: String,
    pub backend: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub filesystem_observation: Capability,
    pub process_observation: Capability,
    pub network_observation: Capability,
    pub network_sandbox_policy: Capability,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Methodology {
    pub evidence_schema_version: String,
    pub verification_methodology_version: String,
    pub normalization_version: String,
    pub depguard_version: String,
    pub observer_version: String,
    pub sandbox_version: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct MissingEvidence {
    pub kind: String,
    pub reason: String,
}
/// Non-canonical execution metadata. None of these fields contribute to the evidence digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct VerificationRunMetadata {
    pub run_id: String,
    pub raw_wall_duration_ms: u128,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub container_ids: Vec<String>,
    pub temporary_paths: Vec<String>,
}

/// Public verifier output. Canonical compatibility evidence remains a separately digestible
/// object, while this wrapper carries intentionally non-canonical run metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct VerificationRun {
    pub compatibility_evidence: PublicCompatibilityEvidenceV1,
    pub compatibility_evidence_digest: String,
    pub run: VerificationRunMetadata,
}

impl VerificationRun {
    pub fn new(
        compatibility_evidence: PublicCompatibilityEvidenceV1,
        run: VerificationRunMetadata,
    ) -> Result<Self> {
        let compatibility_evidence_digest = compatibility_evidence.digest()?;
        Ok(Self {
            compatibility_evidence,
            compatibility_evidence_digest,
            run,
        })
    }
}

impl PublicCompatibilityEvidenceV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(self)?;
        // RFC 8785 output is still JSON; this catches library/API misuse before signing.
        let _: PublicCompatibilityEvidenceV1 = serde_json::from_slice(&bytes)?;
        Ok(bytes)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(sha256_bytes(&self.canonical_bytes()?))
    }
    pub fn validate(&self) -> Result<()> {
        let value = serde_json::to_value(self)?;
        validate_json_value(&value)?;
        if self.schema != SCHEMA_VERSION
            || self.methodology.evidence_schema_version != SCHEMA_VERSION
            || self.methodology.verification_methodology_version != VERIFICATION_METHODOLOGY_VERSION
            || !self.subject.baseline.purl.starts_with("pkg:")
            || !self.subject.candidate.purl.starts_with("pkg:")
        {
            bail!("INTERNAL_EVIDENCE_ERROR: unsupported schema or invalid PURL");
        }
        Ok(())
    }
}

/// Validate raw public JSON before deserialization, preserving unknown-field rejection.
pub fn validate_json_value(value: &serde_json::Value) -> Result<()> {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/compatibility-evidence/v1.schema.json"
    ))?;
    let validator = jsonschema::validator_for(&schema).context("compile public evidence schema")?;
    validator
        .validate(value)
        .map_err(|e| anyhow::anyhow!("INTERNAL_EVIDENCE_ERROR: {e}"))
}
#[allow(clippy::too_many_arguments)]
pub fn project(
    ecosystem: &str,
    package: &str,
    baseline: &PackageCoordinate,
    candidate: &PackageCoordinate,
    artifacts: Artifacts,
    commands: BTreeMap<String, Vec<CommandResult>>,
    base: &BehaviorObservation,
    candidate_behavior: &BehaviorObservation,
    intelligence: Vec<ExternalIntelligence>,
    provenance: ProvenanceEvidence,
    policy: Policy,
    image: String,
) -> PublicCompatibilityEvidenceV1 {
    let mut missing = vec![MissingEvidence {
        kind: "network-observation".into(),
        reason: "observer-not-implemented".into(),
    }];
    if provenance.status != "verified" {
        missing.push(MissingEvidence {
            kind: "npm-provenance".into(),
            reason: provenance.status,
        });
    }
    let map = commands
        .into_iter()
        .map(|(world, rs)| {
            (
                world,
                rs.into_iter()
                    .map(|r| PublicCommand {
                        name: r.name,
                        status: match r.status {
                            depguard_core::CommandStatus::Passed => PublicCommandStatus::Passed,
                            depguard_core::CommandStatus::Failed => PublicCommandStatus::Failed,
                            depguard_core::CommandStatus::NotConfigured => {
                                PublicCommandStatus::NotConfigured
                            }
                            depguard_core::CommandStatus::TimedOut => PublicCommandStatus::Timeout,
                            depguard_core::CommandStatus::InfrastructureFailure => {
                                PublicCommandStatus::Error
                            }
                        },
                        exit_code: r.exit_code,
                    })
                    .collect(),
            )
        })
        .collect();
    PublicCompatibilityEvidenceV1 {
        schema: SCHEMA_VERSION.into(),
        subject: Subject {
            ecosystem: ecosystem.into(),
            package: package.into(),
            baseline: PackageRef {
                version: baseline.version.clone(),
                purl: baseline.purl(),
            },
            candidate: PackageRef {
                version: candidate.version.clone(),
                purl: candidate.purl(),
            },
        },
        environment: Environment {
            os: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            runtime: "node".into(),
            package_manager: "npm".into(),
            sandbox_backend: "docker".into(),
            container_image_reference: image,
            container_image_digest: None,
        },
        artifacts,
        verification: map,
        observations: Observations {
            filesystem: candidate_behavior.filesystem.clone(),
            processes: candidate_behavior.processes.clone(),
            network_observation_status: "UNAVAILABLE".into(),
            sandbox_network_policy: "DENY".into(),
            resources: Resources {
                wall_time: Metric {
                    status: "OBSERVED".into(),
                    milliseconds: Some(base.wall_duration_ms + candidate_behavior.wall_duration_ms),
                },
                peak_memory: Metric {
                    status: "UNAVAILABLE".into(),
                    milliseconds: None,
                },
                cpu: Metric {
                    status: "UNAVAILABLE".into(),
                    milliseconds: None,
                },
            },
        },
        external_intelligence: intelligence
            .into_iter()
            .map(|x| PublicIntelligence {
                provider: x.provider,
                status: x.status,
                source_identifier: x.source_id,
                findings: x.findings,
            })
            .collect(),
        policy,
        capabilities: Capabilities {
            filesystem_observation: Capability {
                status: "SUPPORTED".into(),
                backend: Some("snapshot-diff".into()),
            },
            process_observation: Capability {
                status: "PARTIAL".into(),
                backend: Some("docker-process-polling".into()),
            },
            network_observation: Capability {
                status: "UNAVAILABLE".into(),
                backend: None,
            },
            network_sandbox_policy: Capability {
                status: "ENFORCED".into(),
                backend: Some("docker-network-none".into()),
            },
        },
        methodology: Methodology {
            evidence_schema_version: SCHEMA_VERSION.into(),
            verification_methodology_version: "1".into(),
            normalization_version: "1".into(),
            depguard_version: env!("CARGO_PKG_VERSION").into(),
            observer_version: "docker-process-polling-v1".into(),
            sandbox_version: "docker-v1".into(),
        },
        missing_evidence: missing,
    }
}

#[cfg(test)]
mod canonical_tests {
    #[test]
    fn rfc8785_orders_keys_and_roundtrips() {
        let a: serde_json::Value =
            serde_json::from_str(r#"{"z":1,"a":2,"nested":{"b":1,"a":0}}"#).unwrap();
        let b: serde_json::Value =
            serde_json::from_str(r#"{"nested":{"a":0,"b":1},"a":2,"z":1}"#).unwrap();
        let canonical_a = serde_json_canonicalizer::to_vec(&a).unwrap();
        let canonical_b = serde_json_canonicalizer::to_vec(&b).unwrap();
        assert_eq!(canonical_a, br#"{"a":2,"nested":{"a":0,"b":1},"z":1}"#);
        assert_eq!(canonical_a, canonical_b);
        let _: serde_json::Value = serde_json::from_slice(&canonical_a).unwrap();
    }
}
