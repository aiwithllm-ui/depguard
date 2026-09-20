use base64::{Engine, engine::general_purpose::STANDARD};
use std::{fs, process::Command};

const EVIDENCE: &str = include_str!("../../../fixtures/protocol/evidence-v1/evidence.json");

#[test]
fn attest_verify_json_is_machine_readable_and_uses_stable_exit_codes() {
    let temp = tempfile::tempdir().unwrap();
    let evidence = temp.path().join("evidence.json");
    let private = temp.path().join("local.key");
    let public = temp.path().join("local.pub");
    let attestation = temp.path().join("attestation.json");
    fs::write(&evidence, EVIDENCE).unwrap();
    let binary = env!("CARGO_BIN_EXE_depguard");
    assert!(
        Command::new(binary)
            .args([
                "key-generate",
                "--private-key",
                private.to_str().unwrap(),
                "--public-key",
                public.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(binary)
            .args([
                "attest",
                evidence.to_str().unwrap(),
                "--key",
                private.to_str().unwrap(),
                "--output",
                attestation.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    let valid = Command::new(binary)
        .args([
            "attest-verify",
            attestation.to_str().unwrap(),
            "--public-key",
            public.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(valid.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&valid.stdout).unwrap()["status"],
        "VALID"
    );

    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&attestation).unwrap()).unwrap();
    let payload = STANDARD
        .decode(envelope["payload"].as_str().unwrap())
        .unwrap();
    let mut statement: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    statement["predicate"]["evidence"]["subject"]["candidate"]["version"] =
        serde_json::json!("2.0.1");
    envelope["payload"] =
        serde_json::json!(STANDARD.encode(serde_json::to_vec(&statement).unwrap()));
    fs::write(&attestation, serde_json::to_vec(&envelope).unwrap()).unwrap();
    let invalid = Command::new(binary)
        .args([
            "attest-verify",
            attestation.to_str().unwrap(),
            "--public-key",
            public.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(42));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&invalid.stdout).unwrap(),
        serde_json::json!({"status":"INVALID","reason":"INVALID_SIGNATURE"})
    );

    fs::write(&attestation, b"not json").unwrap();
    let malformed = Command::new(binary)
        .args([
            "attest-verify",
            attestation.to_str().unwrap(),
            "--public-key",
            public.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(malformed.status.code(), Some(41));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&malformed.stdout).unwrap(),
        serde_json::json!({"status":"INVALID","reason":"MALFORMED_DSSE"})
    );
}
