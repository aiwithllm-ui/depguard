//! Stable domain objects shared by the local verifier and future evidence services.
//! No ecosystem-specific parsing belongs in this crate.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const EVIDENCE_SCHEMA_VERSION: &str = "2";
pub const NORMALIZATION_VERSION: &str = "1";
pub const METHODOLOGY_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct PackageCoordinate {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

impl PackageCoordinate {
    pub fn purl(&self) -> String {
        format!("pkg:{}/{}@{}", self.ecosystem, self.name, self.version)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub coordinate: PackageCoordinate,
    pub source_url: String,
    pub integrity: Option<String>,
    pub sha256: String,
    pub cache_path: PathBuf,
    pub size_bytes: u64,
    pub integrity_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageMetadata {
    pub coordinate: PackageCoordinate,
    pub published_at: Option<String>,
    pub maintainers: Vec<String>,
    pub repository: Option<String>,
    pub license: Option<String>,
    pub engines: BTreeMap<String, String>,
    pub dependencies: BTreeMap<String, String>,
    pub optional_dependencies: BTreeMap<String, String>,
    pub peer_dependencies: BTreeMap<String, String>,
    pub scripts: BTreeMap<String, String>,
    pub dist_integrity: Option<String>,
    pub tarball_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DependencyGraph {
    pub nodes: BTreeMap<String, String>,
    pub edges: BTreeMap<String, Vec<String>>,
}

impl DependencyGraph {
    pub fn digest(&self) -> String {
        sha256_json(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedWorld {
    pub root: PathBuf,
    pub package: PackageCoordinate,
    pub artifact: Artifact,
    pub lockfile_digest: String,
    pub graph: DependencyGraph,
    pub graph_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommandStatus {
    Passed,
    Failed,
    NotConfigured,
    TimedOut,
    InfrastructureFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub name: String,
    pub status: CommandStatus,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub cpu_ms: Option<u64>,
    pub peak_memory_bytes: Option<u64>,
    pub stdout_digest: String,
    pub stderr_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcessObservation {
    pub executable: String,
    pub arguments: Vec<String>,
    pub parent_executable: Option<String>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileObservation {
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkObservation {
    pub destination: String,
    pub port: u16,
    pub protocol: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehaviorObservation {
    pub measurement_method: String,
    pub processes: Vec<ProcessObservation>,
    pub filesystem: Vec<FileObservation>,
    pub network: Vec<NetworkObservation>,
    pub wall_duration_ms: u128,
    pub cpu_ms: Option<u64>,
    pub peak_memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExternalIntelligence {
    pub provider: String,
    pub retrieved_at: Option<String>,
    pub source_id: Option<String>,
    pub status: String,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProvenanceEvidence {
    pub status: String,
    pub source_repository: Option<String>,
    pub source_revision: Option<String>,
    pub build_identity: Option<String>,
    pub certificate_identity: Option<String>,
    pub transparency_log: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEvidence {
    pub schema_version: String,
    pub normalization_version: String,
    pub methodology_version: String,
    pub package_purl: String,
    pub from_version: String,
    pub to_version: String,
    pub baseline_artifact_sha256: String,
    pub candidate_artifact_sha256: String,
    pub baseline_lockfile_digest: String,
    pub candidate_lockfile_digest: String,
    pub baseline_graph_digest: String,
    pub candidate_graph_digest: String,
    pub command_results: BTreeMap<String, Vec<CommandResult>>,
    pub behavior_digests: BTreeMap<String, String>,
    pub policy_outcome: String,
    pub external_intelligence: Vec<ExternalIntelligence>,
    pub provenance: ProvenanceEvidence,
}

impl CanonicalEvidence {
    pub fn digest(&self) -> String {
        // Run timing and provider retrieval timestamps are audit metadata, not compatibility
        // facts. Excluding them keeps equivalent normalized runs content-addressable.
        let mut normalized = self.clone();
        for results in normalized.command_results.values_mut() {
            for result in results {
                result.duration_ms = 0;
                // Command frameworks commonly include timing and generated IDs in logs.
                // Raw-log digests stay in run metadata; canonical compatibility records
                // only the normalized command outcome.
                result.stdout_digest.clear();
                result.stderr_digest.clear();
            }
        }
        for intelligence in &mut normalized.external_intelligence {
            intelligence.retrieved_at = None;
        }
        sha256_json(&normalized)
    }
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("sha256:{}", hex::encode(digest.finalize()))
}

pub fn sha256_json<T: Serialize>(value: &T) -> String {
    // All domain collections are BTree-based. serde_json therefore serializes them in a
    // deterministic order; callers must keep timestamps and run IDs out of this identity.
    sha256_bytes(&serde_json::to_vec(value).expect("serializable domain value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_purl_and_graph_digest_are_deterministic() {
        let package = PackageCoordinate {
            ecosystem: "npm".into(),
            name: "@scope/pkg".into(),
            version: "1.2.3".into(),
        };
        assert_eq!(package.purl(), "pkg:npm/@scope/pkg@1.2.3");
        let mut graph = DependencyGraph::default();
        graph.nodes.insert("node_modules/a".into(), "1.0.0".into());
        assert_eq!(graph.digest(), graph.digest());
    }

    #[test]
    fn evidence_digest_excludes_run_timing_and_retrieval_time() {
        let mut evidence = CanonicalEvidence {
            schema_version: "2".into(),
            normalization_version: "1".into(),
            methodology_version: "1".into(),
            package_purl: "pkg:npm/a@2".into(),
            from_version: "1".into(),
            to_version: "2".into(),
            baseline_artifact_sha256: "sha256:a".into(),
            candidate_artifact_sha256: "sha256:b".into(),
            baseline_lockfile_digest: "sha256:c".into(),
            candidate_lockfile_digest: "sha256:d".into(),
            baseline_graph_digest: "sha256:e".into(),
            candidate_graph_digest: "sha256:f".into(),
            command_results: BTreeMap::from([(
                "baseline".into(),
                vec![CommandResult {
                    name: "test".into(),
                    status: CommandStatus::Passed,
                    exit_code: Some(0),
                    duration_ms: 10,
                    cpu_ms: None,
                    peak_memory_bytes: None,
                    stdout_digest: "sha256:a".into(),
                    stderr_digest: "sha256:a".into(),
                }],
            )]),
            behavior_digests: BTreeMap::new(),
            policy_outcome: "NO_POLICY_FINDING".into(),
            external_intelligence: vec![ExternalIntelligence {
                retrieved_at: Some("now".into()),
                ..Default::default()
            }],
            provenance: ProvenanceEvidence::default(),
        };
        let digest = evidence.digest();
        evidence.command_results.get_mut("baseline").unwrap()[0].duration_ms = 999;
        evidence.command_results.get_mut("baseline").unwrap()[0].stdout_digest =
            "sha256:changed".into();
        evidence.external_intelligence[0].retrieved_at = Some("later".into());
        assert_eq!(digest, evidence.digest());
    }
}
