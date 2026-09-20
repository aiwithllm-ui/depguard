//! End-to-end contract test. It is opt-in because it intentionally requires a
//! real PostgreSQL service; docker-compose.yml supplies one for local runs.
use base64::{Engine, engine::general_purpose::STANDARD};
use depguard_attestation::{
    DsseEnvelope, SignatureEntry, VerificationError, dsse_pae, ephemeral_signing_key, sign, verify,
    verify_envelope,
};
use depguard_evidence::PublicCompatibilityEvidenceV1;
use depguard_server::{IdentityPolicy, IdentityVerifier, VerifiedCiIdentity};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{future::IntoFuture, sync::Arc};

fn fixture(package: &str, os: &str, candidate_failed: bool) -> PublicCompatibilityEvidenceV1 {
    let bytes = std::fs::read(format!(
        "{}/../../fixtures/protocol/evidence-v1/evidence.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["subject"]["package"] = json!(package);
    value["subject"]["baseline"]["purl"] = json!(format!("pkg:npm/{package}@1.0.0"));
    value["subject"]["candidate"]["purl"] = json!(format!("pkg:npm/{package}@2.0.0"));
    value["environment"]["os"] = json!(os);
    value["verification"]["baseline"][0]["status"] = json!("PASSED");
    value["verification"]["candidate"][0]["status"] =
        json!(if candidate_failed { "FAILED" } else { "PASSED" });
    // Keep policy clear so the outcome is specifically a candidate regression.
    value["policy"]["outcome"] = json!("NO_POLICY_FINDING");
    value["policy"]["findings"] = json!(Vec::<String>::new());
    serde_json::from_value(value).unwrap()
}

fn statement_value(envelope: &DsseEnvelope) -> Value {
    serde_json::from_slice(&STANDARD.decode(&envelope.payload).unwrap()).unwrap()
}

fn signed_statement(value: Value, key: &SigningKey) -> DsseEnvelope {
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

fn envelope_id(bytes: &[u8]) -> String {
    let raw: Value = serde_json::from_slice(bytes).unwrap();
    let canonical = serde_json_canonicalizer::to_vec(&raw).unwrap();
    format!("sha256:{:x}", Sha256::digest(canonical))
}

async fn post_bytes(client: &reqwest::Client, url: &str, bytes: &[u8]) -> Value {
    client
        .post(format!("{url}/v1/evidence"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn post(client: &reqwest::Client, url: &str, envelope: &DsseEnvelope) -> Value {
    post_bytes(client, url, &serde_json::to_vec(envelope).unwrap()).await
}

async fn post_submission(
    client: &reqwest::Client,
    url: &str,
    attestation: &[u8],
    proof: Value,
) -> Value {
    client
        .post(format!("{url}/v1/submissions"))
        .json(&json!({
            "depguardAttestation": STANDARD.encode(attestation),
            "identityProof": proof,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Deterministic stand-in for production Cosign/Fulcio verification. The nested
/// `verifiedCertificateClaims` is the fixture's authenticated certificate view;
/// top-level client metadata is deliberately ignored.
struct FixtureSigstoreVerifier;
impl IdentityVerifier for FixtureSigstoreVerifier {
    fn verify(
        &self,
        attestation: &[u8],
        bundle: &Value,
    ) -> Result<VerifiedCiIdentity, &'static str> {
        if bundle["corruptTransparencyProof"] == true
            || bundle.pointer("/transparencyLog/verified") != Some(&Value::Bool(true))
        {
            return Err("INVALID_SIGSTORE_IDENTITY");
        }
        let expected = format!("sha256:{:x}", Sha256::digest(attestation));
        if bundle["attestationDigest"] != expected {
            return Err("SIGSTORE_ATTESTATION_BINDING_FAILED");
        }
        let claims = bundle
            .get("verifiedCertificateClaims")
            .and_then(Value::as_object)
            .ok_or("INVALID_SIGSTORE_IDENTITY")?;
        let issuer = claims
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or("UNTRUSTED_OIDC_ISSUER")?;
        if issuer != depguard_server::GITHUB_ACTIONS_ISSUER {
            return Err("UNTRUSTED_OIDC_ISSUER");
        }
        let repository_identity = claims
            .get("repository")
            .and_then(Value::as_str)
            .ok_or("INVALID_SIGSTORE_IDENTITY")?;
        let workflow_identity = claims
            .get("workflow")
            .and_then(Value::as_str)
            .ok_or("INVALID_SIGSTORE_IDENTITY")?;
        let source_revision = claims
            .get("sha")
            .and_then(Value::as_str)
            .ok_or("INVALID_SIGSTORE_IDENTITY")?;
        let source_ref = claims
            .get("ref")
            .and_then(Value::as_str)
            .ok_or("INVALID_SIGSTORE_IDENTITY")?;
        let event_type = claims
            .get("event")
            .and_then(Value::as_str)
            .ok_or("INVALID_SIGSTORE_IDENTITY")?;
        let certificate_identity = claims
            .get("certificateIdentity")
            .and_then(Value::as_str)
            .ok_or("INVALID_SIGSTORE_IDENTITY")?;
        Ok(VerifiedCiIdentity {
            issuer: issuer.into(),
            repository_identity: repository_identity.into(),
            workflow_identity: workflow_identity.into(),
            source_revision: source_revision.into(),
            source_ref: source_ref.into(),
            event_type: event_type.into(),
            certificate_identity: certificate_identity.into(),
        })
    }
}

fn fixture_proof(attestation: &[u8]) -> Value {
    json!({
        "attestationDigest": format!("sha256:{:x}", Sha256::digest(attestation)),
        "transparencyLog": {"verified": true},
        "verifiedCertificateClaims": {
            "issuer": depguard_server::GITHUB_ACTIONS_ISSUER,
            "repository": "depguard/example",
            "workflow": "https://github.com/depguard/example/.github/workflows/depguard.yml@refs/heads/main",
            "sha": "0123456789012345678901234567890123456789",
            "ref": "refs/heads/main",
            "event": "push",
            "certificateIdentity": "https://github.com/depguard/example/.github/workflows/depguard.yml@refs/heads/main"
        }
    })
}

async fn counts(pool: &sqlx::PgPool) -> (i64, i64, i64, i64) {
    let row = sqlx::query(
        "SELECT (SELECT count(*) FROM attestations) AS attestations, \
                (SELECT count(*) FROM verification_runs) AS runs, \
                (SELECT count(*) FROM signers) AS signers, \
                (SELECT count(*) FROM version_transitions) AS transitions",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    (
        row.get("attestations"),
        row.get("runs"),
        row.get("signers"),
        row.get("transitions"),
    )
}

#[tokio::test]
#[ignore = "requires DATABASE_URL Postgres (see docs/network-mvp.md)"]
async fn postgres_network_trust_boundary_contract() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
    let pool = depguard_server::connect(&database_url).await.unwrap();
    depguard_server::migrate(&pool).await.unwrap();
    let query_pool = pool.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(
        axum::serve(
            listener,
            depguard_server::router_with_identity_verifier_and_policy(
                pool,
                Arc::new(FixtureSigstoreVerifier),
                IdentityPolicy::default(),
            ),
        )
        .into_future(),
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let name = format!(
        "network-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    // `keyid` deterministically transports the 32-byte Ed25519 public key.
    let key = ephemeral_signing_key();
    let passing = sign(fixture(&name, "linux", false), &key).unwrap();
    assert!(verify_envelope(&passing).is_ok());
    let wrong_key = ephemeral_signing_key();
    assert_eq!(
        verify(&passing, &wrong_key.verifying_key()),
        Err(VerificationError::InvalidSignature)
    );
    let mut forged_identity = passing.clone();
    forged_identity.signatures[0].keyid = hex::encode(wrong_key.verifying_key().to_bytes());
    assert_eq!(
        verify_envelope(&forged_identity),
        Err(VerificationError::InvalidSignature)
    );

    // Send deliberately non-canonical JSON and demand exact byte recovery.
    let original = serde_json::to_vec_pretty(&passing).unwrap();
    let accepted = post_bytes(&client, &url, &original).await;
    assert_eq!(accepted["status"], "ACCEPTED");
    assert_eq!(accepted["duplicate"], false);
    let evidence_id = accepted["evidenceId"].as_str().unwrap().to_owned();
    assert_eq!(evidence_id, envelope_id(&original));
    let raw = client
        .get(format!("{url}/v1/evidence/{evidence_id}"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(raw.as_ref(), original.as_slice());
    let verified: Value = client
        .post(format!("{url}/v1/attestations/verify"))
        .body(raw.to_vec())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verified["status"], "VALID");

    // An identical envelope is a replay, not another evidence/run/signer row.
    let after_initial = counts(&query_pool).await;
    let duplicate = post_bytes(&client, &url, &original).await;
    assert_eq!(duplicate["evidenceId"], evidence_id);
    assert_eq!(duplicate["duplicate"], true);
    assert_eq!(counts(&query_pool).await, after_initial);
    let submission_count: i64 = sqlx::query_scalar(
        "SELECT s.submission_count FROM evidence_submissions s \
         JOIN attestations a ON a.id=s.attestation_id WHERE a.evidence_id=$1",
    )
    .bind(&evidence_id)
    .fetch_one(&query_pool)
    .await
    .unwrap();
    assert_eq!(submission_count, 2);

    // Every rejected case has no accepted row, transition, or signer side effect.
    let before_invalid = counts(&query_pool).await;
    let mut invalid_signature = passing.clone();
    invalid_signature.signatures[0].sig = STANDARD.encode([0_u8; 64]);
    let mut invalid_digest = statement_value(&passing);
    invalid_digest["predicate"]["compatibilityEvidenceDigest"] =
        json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    let mut invalid_subject = statement_value(&passing);
    invalid_subject["subject"][0]["name"] = json!("pkg:npm/not-the-candidate@2.0.0");
    let mut unsupported_methodology = statement_value(&passing);
    unsupported_methodology["predicate"]["evidence"]["methodology"]["verificationMethodologyVersion"] =
        json!("99");
    for (body, reason) in [
        (
            serde_json::to_vec(&invalid_signature).unwrap(),
            "INVALID_SIGNATURE",
        ),
        (
            serde_json::to_vec(&signed_statement(invalid_digest, &key)).unwrap(),
            "INVALID_EVIDENCE_DIGEST",
        ),
        (
            serde_json::to_vec(&signed_statement(invalid_subject, &key)).unwrap(),
            "INVALID_SUBJECT",
        ),
        (
            serde_json::to_vec(&signed_statement(unsupported_methodology, &key)).unwrap(),
            "UNSUPPORTED_METHODOLOGY",
        ),
        (b"{malformed".to_vec(), "MALFORMED_DSSE"),
        (
            serde_json::to_vec(&forged_identity).unwrap(),
            "INVALID_SIGNATURE",
        ),
    ] {
        let rejected = post_bytes(&client, &url, &body).await;
        assert_eq!(rejected["status"], "REJECTED");
        assert_eq!(rejected["reason"], reason);
        assert_eq!(counts(&query_pool).await, before_invalid);
    }

    // Re-signing is distinct signed evidence, because its envelope hash differs.
    let resigned = sign(fixture(&name, "linux", false), &ephemeral_signing_key()).unwrap();
    let resigned_reply = post(&client, &url, &resigned).await;
    assert_eq!(resigned_reply["status"], "ACCEPTED");
    assert_eq!(resigned_reply["duplicate"], false);
    assert_ne!(resigned_reply["evidenceId"], evidence_id);

    // CI identity is verified independently and binds to this exact immutable
    // attestation. It upgrades only this evidence's network metadata.
    let resigned_bytes = serde_json::to_vec(&resigned).unwrap();
    let ci = post_submission(
        &client,
        &url,
        &resigned_bytes,
        fixture_proof(&resigned_bytes),
    )
    .await;
    assert_eq!(ci["status"], "ACCEPTED");
    assert_eq!(ci["duplicate"], true);
    let stored_ci: (String, String, String, String, String) = sqlx::query_as(
        "SELECT identity_issuer,repository_identity,workflow_identity,source_revision,event_type \
         FROM verified_ci_identities",
    )
    .fetch_one(&query_pool)
    .await
    .unwrap();
    assert_eq!(stored_ci.0, depguard_server::GITHUB_ACTIONS_ISSUER);
    assert_eq!(stored_ci.1, "depguard/example");
    assert!(stored_ci.2.contains(".github/workflows/depguard.yml"));
    assert_eq!(stored_ci.3, "0123456789012345678901234567890123456789");
    assert_eq!(stored_ci.4, "push");

    // The same valid proof cannot endorse different V1 bytes; neither a changed
    // bundle nor a foreign issuer can create CI identity metadata.
    let other = original.clone();
    let mismatched = post_submission(&client, &url, &other, fixture_proof(&resigned_bytes)).await;
    assert_eq!(mismatched["reason"], "SIGSTORE_ATTESTATION_BINDING_FAILED");
    let mut tampered = fixture_proof(&other);
    tampered["corruptTransparencyProof"] = json!(true);
    assert_eq!(
        post_submission(&client, &url, &other, tampered).await["reason"],
        "INVALID_SIGSTORE_IDENTITY"
    );
    let mut bad_issuer = fixture_proof(&other);
    bad_issuer["verifiedCertificateClaims"]["issuer"] = json!("https://issuer.invalid");
    assert_eq!(
        post_submission(&client, &url, &other, bad_issuer).await["reason"],
        "UNTRUSTED_OIDC_ISSUER"
    );

    // Required certificate claims fail closed; no invented repository, workflow,
    // ref, revision, event, or certificate identity can reach CI assurance.
    for claim in [
        "repository",
        "workflow",
        "sha",
        "ref",
        "event",
        "certificateIdentity",
    ] {
        let mut missing = fixture_proof(&other);
        missing["verifiedCertificateClaims"]
            .as_object_mut()
            .unwrap()
            .remove(claim);
        assert_eq!(
            post_submission(&client, &url, &other, missing).await["reason"],
            "INVALID_SIGSTORE_IDENTITY"
        );
    }

    // A cryptographically valid foreign identity remains foreign even when
    // client metadata lies about the desired repository.
    let mut foreign = fixture_proof(&other);
    foreign["verifiedCertificateClaims"]["repository"] = json!("other-org/project-x");
    foreign["verifiedCertificateClaims"]["workflow"] =
        json!("https://github.com/other-org/project-x/.github/workflows/ci.yml@refs/heads/main");
    foreign["verifiedCertificateClaims"]["certificateIdentity"] =
        foreign["verifiedCertificateClaims"]["workflow"].clone();
    foreign["clientMetadata"] = json!({"repository": "trusted-org/project-y"});
    let foreign_reply = post_submission(&client, &url, &other, foreign).await;
    assert_eq!(foreign_reply["status"], "ACCEPTED");
    let stored_foreign: String = sqlx::query_scalar(
        "SELECT repository_identity FROM verified_ci_identities WHERE repository_identity='other-org/project-x'",
    )
    .fetch_one(&query_pool)
    .await
    .unwrap();
    assert_eq!(stored_foreign, "other-org/project-x");

    // Assurance is derived, never accepted from client JSON.
    for proof in [
        Value::Null,
        json!({"corruptTransparencyProof": true}),
        json!({"verifiedCertificateClaims": {"issuer": "https://issuer.invalid"}}),
        json!({"verificationMaterial": {"certificate": {"rawBytes": "not-a-certificate"}}}),
        fixture_proof(&resigned_bytes),
    ] {
        let forged_assurance = client
            .post(format!("{url}/v1/submissions"))
            .json(&json!({
                "depguardAttestation": STANDARD.encode(&other),
                "identityProof": proof,
                "assurance": "SIGSTORE_KEYLESS_CI"
            }))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(forged_assurance["reason"], "MALFORMED_SUBMISSION");
    }

    let wrong_identity = VerifiedCiIdentity {
        issuer: depguard_server::GITHUB_ACTIONS_ISSUER.into(),
        repository_identity: "attacker/repository".into(),
        workflow_identity:
            "https://github.com/attacker/repository/.github/workflows/a.yml@refs/heads/main".into(),
        source_revision: "0123456789012345678901234567890123456789".into(),
        source_ref: "refs/heads/main".into(),
        event_type: "push".into(),
        certificate_identity:
            "https://github.com/attacker/repository/.github/workflows/a.yml@refs/heads/main".into(),
    };
    assert_eq!(
        IdentityPolicy {
            expected_repository: Some("depguard/example".into()),
            expected_workflow: None,
        }
        .validate(&wrong_identity),
        Err("SIGSTORE_IDENTITY_POLICY_REJECTED")
    );

    // Contradictory independent evidence survives and appears in both populations.
    let failing = sign(fixture(&name, "darwin", true), &ephemeral_signing_key()).unwrap();
    let failing_reply = post(&client, &url, &failing).await;
    assert_eq!(failing_reply["status"], "ACCEPTED");
    let aggregate: Value = client
        .get(format!("{url}/v1/transitions/npm/{name}/1.0.0/2.0.0"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(aggregate["evidence"]["uniqueEvidence"], 3);
    assert_eq!(
        aggregate["evidence"]["uniqueProjectFingerprints"],
        Value::Null
    );
    assert_eq!(
        aggregate["evidence"]["projectFingerprintAvailability"],
        "NOT_PRESENT_IN_EVIDENCE_V1"
    );
    let outcomes = aggregate["outcomes"].as_array().unwrap();
    assert!(
        outcomes
            .iter()
            .any(|v| v["value"] == "CONFIGURED_CHECKS_PASSED")
    );
    assert_eq!(aggregate["signerAssurance"]["LOCAL_DEVELOPMENT_KEY"], 1);
    assert_eq!(aggregate["signerAssurance"]["SIGSTORE_KEYLESS_CI"], 2);
    assert!(
        outcomes
            .iter()
            .any(|v| v["value"] == "CANDIDATE_REGRESSION_OBSERVED")
    );

    // Package, version, transition, and paginated transition-evidence are live.
    for route in [
        format!("/v1/packages/npm/{name}"),
        format!("/v1/packages/npm/{name}/versions/1.0.0"),
    ] {
        assert!(
            client
                .get(format!("{url}{route}"))
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
    }
    let first_page: Value = client
        .get(format!(
            "{url}/v1/transitions/npm/{name}/1.0.0/2.0.0/evidence?limit=1"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first_page["evidence"].as_array().unwrap().len(), 1);
    let cursor = first_page["nextCursor"].as_str().unwrap();
    let second_page: Value = client
        .get(format!(
            "{url}/v1/transitions/npm/{name}/1.0.0/2.0.0/evidence?limit=100&cursor={cursor}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(second_page["evidence"].as_array().unwrap().len(), 2);
    assert_eq!(second_page["nextCursor"], Value::Null);
    server.abort();
}
