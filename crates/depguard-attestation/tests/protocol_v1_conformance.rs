use base64::{Engine, engine::general_purpose::STANDARD};
use depguard_attestation::{
    DsseEnvelope, SignatureEntry, VerificationError, dsse_pae, ephemeral_signing_key, sign, verify,
};
use depguard_evidence::{
    PublicCompatibilityEvidenceV1, VerificationRun, VerificationRunMetadata, validate_json_value,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

const EVIDENCE: &str = include_str!("../../../fixtures/protocol/evidence-v1/evidence.json");
const CANONICAL: &[u8] = include_bytes!("../../../fixtures/protocol/evidence-v1/canonical.json");
const DIGEST: &str = include_str!("../../../fixtures/protocol/evidence-v1/canonical.sha256");
type Mutation = (&'static str, Box<dyn Fn(&mut Value)>);

fn evidence() -> PublicCompatibilityEvidenceV1 {
    let raw: Value = serde_json::from_str(EVIDENCE).unwrap();
    validate_json_value(&raw).unwrap();
    serde_json::from_value(raw).unwrap()
}

fn value_from(envelope: &DsseEnvelope) -> Value {
    serde_json::from_slice(&STANDARD.decode(&envelope.payload).unwrap()).unwrap()
}

fn signed_value(value: Value, key: &SigningKey) -> DsseEnvelope {
    let payload = serde_json_canonicalizer::to_vec(&value).unwrap();
    let signature = key.sign(&dsse_pae(depguard_attestation::PAYLOAD_TYPE, &payload));
    DsseEnvelope {
        payload_type: depguard_attestation::PAYLOAD_TYPE.into(),
        payload: STANDARD.encode(payload),
        signatures: vec![SignatureEntry {
            keyid: hex::encode(key.verifying_key().to_bytes()),
            sig: STANDARD.encode(signature.to_bytes()),
        }],
    }
}

fn assert_error(envelope: &DsseEnvelope, key: &SigningKey, expected: VerificationError) {
    assert_eq!(verify(envelope, &key.verifying_key()), Err(expected));
}

#[test]
fn protocol_v1_conformance_golden_schema_canonicalization_digest_and_pae() {
    let raw: Value = serde_json::from_str(EVIDENCE).unwrap();
    validate_json_value(&raw).unwrap();
    let public = evidence();
    // The fixture is a text file; its optional terminal line ending is not protocol data.
    let canonical = CANONICAL.strip_suffix(b"\n").unwrap_or(CANONICAL);
    assert_eq!(public.canonical_bytes().unwrap(), canonical);
    assert_eq!(public.digest().unwrap(), DIGEST.trim());

    let reordered: Value = serde_json::from_str(
        r#"{"verification":{"candidate":[{"status":"FAILED","exitCode":1,"name":"test"}],"baseline":[{"name":"test","status":"PASSED","exitCode":0}]},"schema":"1","subject":{"candidate":{"purl":"pkg:npm/example-package@2.0.0","version":"2.0.0"},"baseline":{"version":"1.0.0","purl":"pkg:npm/example-package@1.0.0"},"package":"example-package","ecosystem":"npm"},"environment":{"sandboxBackend":"docker","runtime":"node","os":"linux","containerImageReference":"node:20-alpine","containerImageDigest":null,"packageManager":"npm","architecture":"x86_64"},"artifacts":{"candidateArtifactDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","baselineArtifactDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","baselineRegistryIntegrity":"sha512-baseline","candidateRegistryIntegrity":"sha512-candidate","baselineLockfileDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","candidateLockfileDigest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","baselineDependencyGraphDigest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","candidateDependencyGraphDigest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","behaviorEvidenceDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"observations":{"processes":[{"exit_code":1,"parent_executable":"npm","arguments":["test"],"executable":"node"}],"filesystem":[{"size":7,"sha256":"sha256:2222222222222222222222222222222222222222222222222222222222222222","path":"candidate-marker.txt","kind":"file","executable":false}],"resources":{"cpu":{"milliseconds":null,"status":"UNAVAILABLE"},"wallTime":{"status":"OBSERVED","milliseconds":321},"peakMemory":{"status":"UNAVAILABLE","milliseconds":null}},"sandboxNetworkPolicy":"DENY","networkObservationStatus":"UNAVAILABLE"},"externalIntelligence":[{"status":"unavailable","sourceIdentifier":null,"findings":[],"provider":"osv"}],"policy":{"findings":["candidate test failed"],"outcome":"REVIEW_REQUIRED"},"capabilities":{"networkSandboxPolicy":{"backend":"docker-network-none","status":"ENFORCED"},"networkObservation":{"status":"UNAVAILABLE","backend":null},"processObservation":{"backend":"docker-process-polling","status":"PARTIAL"},"filesystemObservation":{"status":"SUPPORTED","backend":"snapshot-diff"}},"methodology":{"sandboxVersion":"docker-v1","observerVersion":"docker-process-polling-v1","depguardVersion":"0.2.0","normalizationVersion":"1","verificationMethodologyVersion":"1","evidenceSchemaVersion":"1"},"missingEvidence":[{"reason":"observer-not-implemented","kind":"network-observation"}]}"#,
    ).unwrap();
    let reordered: PublicCompatibilityEvidenceV1 = serde_json::from_value(reordered).unwrap();
    assert_eq!(reordered.canonical_bytes().unwrap(), canonical);
    assert_eq!(reordered.digest().unwrap(), DIGEST.trim());
    assert_eq!(dsse_pae("a", b"bc"), b"DSSEv1 1 a 2 bc");
}

#[test]
fn protocol_v1_conformance_signature_statement_versions_and_subject() {
    let key = ephemeral_signing_key();
    let envelope = sign(evidence(), &key).unwrap();
    let summary = verify(&envelope, &key.verifying_key()).unwrap();
    assert_eq!(summary.evidence_schema_version, "1");
    assert_eq!(summary.verification_methodology_version, "1");
    assert_eq!(summary.predicate_type, depguard_attestation::PREDICATE_TYPE);
    assert_eq!(summary.signer_assurance, "LOCAL_DEVELOPMENT_KEY");

    let mut statement = value_from(&envelope);
    statement["predicateType"] = json!("https://example.invalid/predicate");
    assert_error(
        &signed_value(statement, &key),
        &key,
        VerificationError::UnsupportedPredicate,
    );

    let mut statement = value_from(&envelope);
    statement["_type"] = json!("https://example.invalid/Statement/v1");
    assert_error(
        &signed_value(statement, &key),
        &key,
        VerificationError::InvalidStatement,
    );

    let mut statement = value_from(&envelope);
    statement["predicate"]["evidence"]["schema"] = json!("9");
    assert_error(
        &signed_value(statement, &key),
        &key,
        VerificationError::UnsupportedSchema,
    );

    let mut statement = value_from(&envelope);
    statement["predicate"]["evidence"]["methodology"]["verificationMethodologyVersion"] =
        json!("9");
    assert_error(
        &signed_value(statement, &key),
        &key,
        VerificationError::UnsupportedMethodology,
    );

    let mut statement = value_from(&envelope);
    statement["predicate"]["compatibilityEvidenceDigest"] =
        json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    assert_error(
        &signed_value(statement, &key),
        &key,
        VerificationError::InvalidEvidenceDigest,
    );

    let mut statement = value_from(&envelope);
    statement["subject"][0]["name"] = json!("pkg:npm/other@2.0.0");
    assert_error(
        &signed_value(statement, &key),
        &key,
        VerificationError::InvalidSubject,
    );

    let mut statement = value_from(&envelope);
    statement["subject"][0]["digest"]["sha256"] =
        json!("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    assert_error(
        &signed_value(statement, &key),
        &key,
        VerificationError::InvalidSubject,
    );

    let mut statement = value_from(&envelope);
    statement["predicate"]["evidence"]["subject"]["candidate"]["purl"] =
        json!("pkg:npm/example-package@9.9.9");
    assert_error(
        &signed_value(statement, &key),
        &key,
        VerificationError::InvalidArtifactRelationship,
    );

    let mut statement = value_from(&envelope);
    statement["predicate"]["evidence"]
        .as_object_mut()
        .unwrap()
        .insert("unknownV1Field".into(), json!(true));
    assert_error(
        &signed_value(statement, &key),
        &key,
        VerificationError::SchemaValidationFailed,
    );
}

#[test]
fn protocol_v1_conformance_dsse_tamper_errors() {
    let key = ephemeral_signing_key();
    let envelope = sign(evidence(), &key).unwrap();
    let mut modified_signature = envelope.clone();
    let replacement = if &modified_signature.signatures[0].sig[1..2] == "A" {
        "B"
    } else {
        "A"
    };
    modified_signature.signatures[0]
        .sig
        .replace_range(1..2, replacement);
    assert_error(
        &modified_signature,
        &key,
        VerificationError::InvalidSignature,
    );
    let other = ephemeral_signing_key();
    assert_eq!(
        verify(&envelope, &other.verifying_key()),
        Err(VerificationError::InvalidSignature)
    );
    let mut modified_payload = envelope.clone();
    let mut payload = STANDARD.decode(&modified_payload.payload).unwrap();
    payload[0] ^= 1;
    modified_payload.payload = STANDARD.encode(payload);
    assert_error(&modified_payload, &key, VerificationError::InvalidSignature);
    let mut wrong_payload_type = envelope.clone();
    wrong_payload_type.payload_type = "application/json".into();
    assert_error(
        &wrong_payload_type,
        &key,
        VerificationError::UnsupportedPayloadType,
    );
    let mut malformed_payload = envelope.clone();
    malformed_payload.payload = "%%%".into();
    assert_error(&malformed_payload, &key, VerificationError::MalformedDsse);
    let mut malformed_signature = envelope.clone();
    malformed_signature.signatures[0].sig = "%%%".into();
    assert_error(&malformed_signature, &key, VerificationError::MalformedDsse);
}

#[test]
fn every_canonical_evidence_field_tamper_breaks_signature() {
    let key = ephemeral_signing_key();
    let envelope = sign(evidence(), &key).unwrap();
    let mutations: Vec<Mutation> = vec![
        (
            "candidate version",
            Box::new(|v| {
                v["predicate"]["evidence"]["subject"]["candidate"]["version"] = json!("2.0.1")
            }),
        ),
        (
            "candidate PURL",
            Box::new(|v| {
                v["predicate"]["evidence"]["subject"]["candidate"]["purl"] =
                    json!("pkg:npm/example-package@2.0.1")
            }),
        ),
        (
            "candidate artifact digest",
            Box::new(|v| {
                v["predicate"]["evidence"]["artifacts"]["candidateArtifactDigest"] =
                    json!("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            }),
        ),
        (
            "baseline artifact digest",
            Box::new(|v| {
                v["predicate"]["evidence"]["artifacts"]["baselineArtifactDigest"] =
                    json!("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            }),
        ),
        (
            "candidate lockfile digest",
            Box::new(|v| {
                v["predicate"]["evidence"]["artifacts"]["candidateLockfileDigest"] =
                    json!("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            }),
        ),
        (
            "candidate graph digest",
            Box::new(|v| {
                v["predicate"]["evidence"]["artifacts"]["candidateDependencyGraphDigest"] =
                    json!("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            }),
        ),
        (
            "behavior evidence digest",
            Box::new(|v| {
                v["predicate"]["evidence"]["artifacts"]["behaviorEvidenceDigest"] =
                    json!("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            }),
        ),
        (
            "test result",
            Box::new(|v| {
                v["predicate"]["evidence"]["verification"]["candidate"][0]["status"] =
                    json!("PASSED")
            }),
        ),
        (
            "filesystem observation",
            Box::new(|v| {
                v["predicate"]["evidence"]["observations"]["filesystem"][0]["path"] =
                    json!("tampered.txt")
            }),
        ),
        (
            "process observation",
            Box::new(|v| {
                v["predicate"]["evidence"]["capabilities"]["processObservation"]["status"] =
                    json!("SUPPORTED")
            }),
        ),
        (
            "policy outcome",
            Box::new(|v| v["predicate"]["evidence"]["policy"]["outcome"] = json!("POLICY_DENIED")),
        ),
        (
            "capability declaration",
            Box::new(|v| {
                v["predicate"]["evidence"]["capabilities"]["filesystemObservation"]["backend"] =
                    json!("other")
            }),
        ),
    ];
    for (name, mutate) in mutations {
        let mut value = value_from(&envelope);
        mutate(&mut value);
        let mut tampered = envelope.clone();
        tampered.payload = STANDARD.encode(serde_json::to_vec(&value).unwrap());
        assert_eq!(
            verify(&tampered, &key.verifying_key()),
            Err(VerificationError::InvalidSignature),
            "{name}"
        );
    }
}

#[test]
fn verification_run_metadata_never_changes_evidence_digest() {
    let public = evidence();
    let a = VerificationRun::new(
        public.clone(),
        VerificationRunMetadata {
            run_id: "first".into(),
            raw_wall_duration_ms: 1,
            started_at: Some("2026-01-01T00:00:00Z".into()),
            completed_at: None,
            container_ids: vec!["container-a".into()],
            temporary_paths: vec!["/tmp/a".into()],
        },
    )
    .unwrap();
    let b = VerificationRun::new(
        public,
        VerificationRunMetadata {
            run_id: "second".into(),
            raw_wall_duration_ms: 9_999,
            started_at: None,
            completed_at: Some("2026-01-01T01:00:00Z".into()),
            container_ids: vec!["container-b".into()],
            temporary_paths: vec!["/tmp/b".into()],
        },
    )
    .unwrap();
    assert_eq!(
        a.compatibility_evidence_digest,
        b.compatibility_evidence_digest
    );
}

#[test]
fn verification_error_exit_codes_are_stable() {
    assert_eq!(VerificationError::MalformedDsse.exit_code(), 41);
    assert_eq!(VerificationError::InvalidSignature.exit_code(), 42);
    assert_eq!(VerificationError::UnsupportedPredicate.exit_code(), 43);
    assert_eq!(VerificationError::InvalidEvidenceDigest.exit_code(), 44);
}
