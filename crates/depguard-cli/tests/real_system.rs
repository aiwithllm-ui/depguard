//! Docker-backed system test. It uses a disposable localhost-only Verdaccio instance;
//! credentials and storage are generated below and are removed by TempDir/ContainerGuard.

use base64::{Engine, engine::general_purpose::STANDARD};
use depguard_attestation::{DsseEnvelope, ephemeral_signing_key, sign, verify};
use depguard_evidence::PublicCompatibilityEvidenceV1;
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

struct ContainerGuard(String);
impl Drop for ContainerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}

fn command(program: &str, args: &[&str], cwd: &Path) -> Output {
    Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}

fn assert_success(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn wait_for_registry(url: &str) {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(20) {
        if Command::new("npm")
            .args(["ping", "--registry", url])
            .output()
            .is_ok_and(|o| o.status.success())
        {
            return;
        }
        thread::sleep(Duration::from_millis(200));
    }
    panic!("Verdaccio was not ready at {url}");
}

fn write_registry(temp: &TempDir, port: u16) -> (PathBuf, String) {
    let username = "depguard-test";
    let password = format!("depguard-{}", std::process::id());
    let hash = Command::new("htpasswd")
        .args(["-nbB", username, &password])
        .output()
        .expect("htpasswd available");
    assert_success(&hash, "generate temporary htpasswd entry");
    let conf = temp.path().join("config.yaml");
    fs::write(&conf, "storage: /verdaccio/storage\nauth:\n  htpasswd:\n    file: /verdaccio/conf/htpasswd\n    max_users: -1\nuplinks: {}\npackages:\n  '@*/*':\n    access: $all\n    publish: $all\n    unpublish: $all\n  '**':\n    access: $all\n    publish: $all\n    unpublish: $all\nlog:\n  type: stdout\n  level: warn\n").unwrap();
    fs::write(temp.path().join("htpasswd"), hash.stdout).unwrap();
    let token = STANDARD.encode(format!("{username}:{password}"));
    fs::write(
        temp.path().join("npmrc"),
        format!("//127.0.0.1:{port}/:_auth={token}\n//127.0.0.1:{port}/:always-auth=true\n"),
    )
    .unwrap();
    (conf, format!("http://127.0.0.1:{port}"))
}

fn copy_fixture(source: &Path, target: &Path) {
    for entry in walkdir::WalkDir::new(source)
        .into_iter()
        .filter_map(Result::ok)
    {
        let relative = entry.path().strip_prefix(source).unwrap();
        if relative
            .components()
            .any(|part| part.as_os_str() == ".depguard")
        {
            continue;
        }
        let destination = target.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(destination).unwrap();
        } else if entry.file_type().is_file() {
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}

#[test]
fn depguard_system_verification() {
    if !Command::new("docker")
        .args(["info"])
        .output()
        .is_ok_and(|o| o.status.success())
    {
        eprintln!("skipping Docker system test: daemon unavailable");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let (config, registry) = write_registry(&temp, port);
    let name = format!("depguard-system-{}", std::process::id());
    let docker = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "--name",
            &name,
            "-p",
            &format!("127.0.0.1:{port}:4873"),
            "-v",
            &format!("{}:/verdaccio/conf/config.yaml:ro", config.display()),
            "-v",
            &format!(
                "{}:/verdaccio/conf/htpasswd:ro",
                temp.path().join("htpasswd").display()
            ),
            "verdaccio/verdaccio:5",
        ])
        .output()
        .unwrap();
    assert_success(&docker, "start Verdaccio");
    let _registry = ContainerGuard(name);
    wait_for_registry(&registry);
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let npmrc = temp.path().join("npmrc");
    for version in ["1.0.0", "2.0.0"] {
        let fixture = root
            .join("fixtures/registry-packages/example-package")
            .join(version);
        let published = Command::new("npm")
            .args([
                "--userconfig",
                npmrc.to_str().unwrap(),
                "publish",
                "--registry",
                &registry,
                "--ignore-scripts",
            ])
            .current_dir(fixture)
            .output()
            .unwrap();
        assert_success(&published, "publish controlled fixture");
    }
    let versions = command(
        "npm",
        &[
            "view",
            "example-package",
            "versions",
            "--json",
            "--registry",
            &registry,
        ],
        &root,
    );
    assert_success(&versions, "read controlled versions");
    let text = String::from_utf8_lossy(&versions.stdout);
    assert!(text.contains("1.0.0") && text.contains("2.0.0"));
    let project = temp.path().join("consumer");
    let evidence_file = temp.path().join("evidence.json");
    let private_key = temp.path().join("local.key");
    let public_key = temp.path().join("local.pub");
    let attestation_file = temp.path().join("attestation.json");
    copy_fixture(&root.join("fixtures/npm-real-upgrade"), &project);
    let output = Command::new(env!("CARGO_BIN_EXE_depguard"))
        .args([
            "verify",
            "example-package@2.0.0",
            "--project",
            project.to_str().unwrap(),
            "--registry",
            &registry,
            "--json",
            "--evidence-out",
            evidence_file.to_str().unwrap(),
        ])
        .env("AWS_SECRET_ACCESS_KEY", "DEPGUARD_SHOULD_NEVER_SEE_THIS")
        .env("NPM_TOKEN", "DEPGUARD_SHOULD_NEVER_SEE_THIS")
        .env("DATABASE_URL", "DEPGUARD_SHOULD_NEVER_SEE_THIS")
        .env("GITHUB_TOKEN", "DEPGUARD_SHOULD_NEVER_SEE_THIS")
        .output()
        .unwrap();
    assert_success(&output, "real public depguard CLI");
    let evidence: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        evidence["installation"]["baselineInstalledVersion"],
        "1.0.0"
    );
    assert_eq!(
        evidence["installation"]["candidateInstalledVersion"],
        "2.0.0"
    );
    assert_ne!(
        evidence["compatibilityEvidence"]["artifacts"]["baselineArtifactDigest"],
        evidence["compatibilityEvidence"]["artifacts"]["candidateArtifactDigest"]
    );
    assert_eq!(
        evidence["installation"]["artifactIntegrity"]["baseline"],
        true
    );
    assert_eq!(
        evidence["installation"]["artifactIntegrity"]["candidate"],
        true
    );
    assert_eq!(
        evidence["compatibilityEvidence"]["verification"]["baseline"][2]["status"],
        "PASSED"
    );
    assert_eq!(
        evidence["compatibilityEvidence"]["verification"]["candidate"][2]["status"],
        "FAILED"
    );
    assert_eq!(
        evidence["observed"]["network"]["status"],
        "DENIED_BY_SANDBOX_POLICY"
    );
    let files = evidence["compatibilityEvidence"]["observations"]["filesystem"].to_string();
    assert!(files.contains("candidate-marker"));
    assert!(files.contains("sandbox-nonroot-and-secrets-isolated"));
    assert!(
        !evidence["compatibilityEvidence"]["observations"]["processes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        evidence["compatibilityEvidenceDigest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    let public: PublicCompatibilityEvidenceV1 =
        serde_json::from_value(evidence["compatibilityEvidence"].clone()).unwrap();
    let key = ephemeral_signing_key();
    let mut attestation: DsseEnvelope = sign(public, &key).unwrap();
    verify(&attestation, &key.verifying_key()).unwrap();
    attestation.payload.push('x');
    assert!(verify(&attestation, &key.verifying_key()).is_err());
    assert_success(
        &Command::new(env!("CARGO_BIN_EXE_depguard"))
            .args([
                "key-generate",
                "--private-key",
                private_key.to_str().unwrap(),
                "--public-key",
                public_key.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
        "key-generate CLI",
    );
    assert_success(
        &Command::new(env!("CARGO_BIN_EXE_depguard"))
            .args([
                "attest",
                evidence_file.to_str().unwrap(),
                "--key",
                private_key.to_str().unwrap(),
                "--output",
                attestation_file.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
        "attest CLI",
    );
    let _ = Command::new("docker")
        .args(["rm", "-f", &_registry.0])
        .output();
    let verified = Command::new(env!("CARGO_BIN_EXE_depguard"))
        .args([
            "attest-verify",
            attestation_file.to_str().unwrap(),
            "--public-key",
            public_key.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success(&verified, "offline attest-verify CLI");
    let verified_json: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified_json["status"], "VALID");
    assert_eq!(verified_json["evidenceSchemaVersion"], "1");
    assert_eq!(verified_json["verificationMethodologyVersion"], "1");

    let mut tampered: serde_json::Value =
        serde_json::from_slice(&fs::read(&attestation_file).unwrap()).unwrap();
    let payload = STANDARD
        .decode(tampered["payload"].as_str().unwrap())
        .unwrap();
    let mut statement: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    statement["predicate"]["evidence"]["subject"]["candidate"]["version"] =
        serde_json::json!("2.0.1");
    tampered["payload"] =
        serde_json::json!(STANDARD.encode(serde_json::to_vec(&statement).unwrap()));
    fs::write(&attestation_file, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let invalid = Command::new(env!("CARGO_BIN_EXE_depguard"))
        .args([
            "attest-verify",
            attestation_file.to_str().unwrap(),
            "--public-key",
            public_key.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(42));
    let invalid_json: serde_json::Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(
        invalid_json,
        serde_json::json!({"status": "INVALID", "reason": "INVALID_SIGNATURE"})
    );
}
