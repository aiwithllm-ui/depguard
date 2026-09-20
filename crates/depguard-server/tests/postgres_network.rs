//! End-to-end contract test. It is opt-in because it intentionally requires a
//! real PostgreSQL service; docker-compose.yml supplies one for local runs.
use base64::{Engine, engine::general_purpose::STANDARD};
use depguard_attestation::{
    DsseEnvelope, SignatureEntry, VerificationError, dsse_pae, ephemeral_signing_key, sign, verify,
    verify_envelope,
};
use depguard_evidence::PublicCompatibilityEvidenceV1;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::future::IntoFuture;

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
    let server = tokio::spawn(axum::serve(listener, depguard_server::router(pool)).into_future());
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
