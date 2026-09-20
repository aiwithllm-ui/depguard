use depguard_core::{PackageMetadata, ProvenanceEvidence};
pub fn inspect_npm(metadata: &PackageMetadata) -> ProvenanceEvidence {
    ProvenanceEvidence {
        status: "unavailable".into(),
        source_repository: metadata.repository.clone(),
        source_revision: None,
        build_identity: None,
        certificate_identity: None,
        transparency_log: None,
    }
}
