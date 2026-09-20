use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use depguard_config::load;
use depguard_core::{BehaviorObservation, CanonicalEvidence, CommandStatus};
use depguard_diff::compare;
use depguard_evidence::{
    Artifacts, Policy as PublicPolicy, VerificationRun, VerificationRunMetadata,
    project as project_public,
};
use depguard_npm::{NpmRegistry, current_direct_version, metadata_delta};
use depguard_observer::{behavior_digest, filesystem_snapshot};
use depguard_policy::evaluate;
use depguard_provenance::inspect_npm;
use depguard_resolver::prepare_twins;
use depguard_sandbox::{SandboxConfig, run as run_sandbox};
use depguard_security::osv_npm;
use std::{collections::BTreeMap, path::Path, time::Duration};
#[derive(Parser)]
#[command(
    name = "depguard",
    version,
    about = "Local dependency compatibility evidence"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Version,
    Doctor,
    KeyGenerate {
        #[arg(long)]
        private_key: std::path::PathBuf,
        #[arg(long)]
        public_key: std::path::PathBuf,
    },
    Attest {
        evidence: std::path::PathBuf,
        #[arg(long)]
        key: std::path::PathBuf,
        #[arg(long)]
        output: std::path::PathBuf,
    },
    AttestVerify {
        attestation: std::path::PathBuf,
        #[arg(long)]
        public_key: std::path::PathBuf,
        #[arg(long)]
        json: bool,
    },
    Verify {
        package: String,
        #[arg(long)]
        json: bool,
        /// Project to verify. Defaults to the current directory.
        #[arg(long)]
        project: Option<std::path::PathBuf>,
        /// npm registry used only for the controlled fetch/preparation stage.
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        evidence_out: Option<std::path::PathBuf>,
    },
}
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let verification_json = matches!(&cli.command, Command::AttestVerify { json: true, .. });
    if let Err(error) = run(cli).await {
        if let Some(verification_error) =
            error.downcast_ref::<depguard_attestation::VerificationError>()
        {
            if verification_json {
                println!(
                    "{}",
                    serde_json::json!({"status":"INVALID", "reason": verification_error.code()})
                );
            } else {
                eprintln!("DepGuard: {}", verification_error.code());
            }
            std::process::exit(verification_error.exit_code());
        }
        eprintln!("DepGuard: {error:#}");
        std::process::exit(40);
    }
}
async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Version => println!("depguard {}", env!("CARGO_PKG_VERSION")),
        Command::Doctor => println!("Docker: {}", depguard_sandbox::doctor().await?),
        Command::KeyGenerate {
            private_key,
            public_key,
        } => key_generate(&private_key, &public_key)?,
        Command::Attest {
            evidence,
            key,
            output,
        } => attest(&evidence, &key, &output)?,
        Command::AttestVerify {
            attestation,
            public_key,
            json,
        } => attest_verify(&attestation, &public_key, json)?,
        Command::Verify {
            package,
            json,
            project,
            registry,
            evidence_out,
        } => {
            verify(
                &package,
                json,
                project.as_deref(),
                registry.as_deref(),
                evidence_out.as_deref(),
            )
            .await?
        }
    }
    Ok(())
}
fn key_generate(private: &Path, public: &Path) -> Result<()> {
    let key = depguard_attestation::ephemeral_signing_key();
    std::fs::write(private, depguard_attestation::private_key_base64(&key))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::write(
        public,
        depguard_attestation::public_key_base64(&key.verifying_key()),
    )?;
    println!("LOCAL_DEVELOPMENT_KEY generated");
    Ok(())
}
fn attest(evidence: &Path, key: &Path, output: &Path) -> Result<()> {
    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(evidence)?)?;
    depguard_evidence::validate_json_value(&raw)?;
    let public: depguard_evidence::PublicCompatibilityEvidenceV1 = serde_json::from_value(raw)?;
    let key = depguard_attestation::signing_key_from_base64(&std::fs::read_to_string(key)?)?;
    let envelope = depguard_attestation::sign(public, &key)?;
    std::fs::write(output, serde_json::to_vec_pretty(&envelope)?)?;
    println!("attestation: {}", output.display());
    Ok(())
}
fn attest_verify(attestation: &Path, public: &Path, json: bool) -> Result<()> {
    let envelope: depguard_attestation::DsseEnvelope =
        serde_json::from_slice(&std::fs::read(attestation)?)
            .map_err(|_| depguard_attestation::VerificationError::MalformedDsse)?;
    let key = depguard_attestation::verifying_key_from_base64(&std::fs::read_to_string(public)?)?;
    let summary = depguard_attestation::verify(&envelope, &key)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": "VALID",
                "evidenceSchemaVersion": summary.evidence_schema_version,
                "verificationMethodologyVersion": summary.verification_methodology_version,
                "predicateType": summary.predicate_type,
                "signerAssurance": summary.signer_assurance,
            })
        );
    } else {
        println!("VALID");
    }
    Ok(())
}

fn parse_spec(spec: &str) -> Result<(String, String)> {
    let at = spec.rfind('@').context("use package@exact-version")?;
    if at == 0 || at == spec.len() - 1 {
        anyhow::bail!("use package@exact-version");
    }
    Ok((spec[..at].into(), spec[at + 1..].into()))
}
async fn verify(
    spec: &str,
    json: bool,
    project: Option<&Path>,
    registry_url: Option<&str>,
    evidence_out: Option<&Path>,
) -> Result<()> {
    depguard_sandbox::doctor().await?;
    let root = match project {
        Some(path) => path.canonicalize()?,
        None => std::env::current_dir()?,
    };
    let (name, to) = parse_spec(spec)?;
    let from = current_direct_version(&root, &name)?;
    let cfg = load(&root.join("depguard.yaml"))?;
    let registry = match registry_url {
        Some(url) => NpmRegistry::with_base(url)?,
        None => NpmRegistry::new()?,
    };
    let from_meta = registry
        .metadata(&name, &from)
        .await
        .context("fetch baseline npm metadata")?;
    let to_meta = registry
        .metadata(&name, &to)
        .await
        .context("fetch candidate npm metadata")?;
    let cache = root.join(".depguard/cache");
    let from_artifact = registry.fetch(&from_meta, &cache).await?;
    let to_artifact = registry.fetch(&to_meta, &cache).await?;
    let twins = prepare_twins(&root, &name, &from_artifact, &to_artifact).await?;
    let commands = commands(&twins.baseline.root, &cfg.verify.commands)?;
    let sandbox = SandboxConfig {
        image: std::env::var("DEPGUARD_SANDBOX_IMAGE").unwrap_or_else(|_| "node:20-alpine".into()),
        memory: cfg.sandbox.memory.clone(),
        cpus: cfg.sandbox.cpus,
        timeout: parse_timeout(&cfg.sandbox.timeout)?,
        network: cfg.sandbox.network.clone(),
    };
    let baseline = execute(&twins.baseline.root, &commands, &sandbox).await?;
    if baseline.0.iter().any(|result| {
        matches!(
            result.status,
            CommandStatus::Failed | CommandStatus::TimedOut | CommandStatus::InfrastructureFailure
        )
    }) {
        anyhow::bail!("BASELINE_INVALID: existing dependency state did not pass verification")
    }
    let candidate = execute(&twins.candidate.root, &commands, &sandbox).await?;
    let baseline_installed = installed_version(&twins.baseline.root, &name)?;
    let candidate_installed = installed_version(&twins.candidate.root, &name)?;
    if baseline_installed != evidence_package_version(&from_meta)
        || candidate_installed != evidence_package_version(&to_meta)
    {
        anyhow::bail!("prepared twin installed a version other than its resolved package metadata")
    }
    let base_behavior = BehaviorObservation {
        measurement_method: "docker-top-v1; filesystem-snapshot-v1; network-deny".into(),
        processes: baseline.1,
        filesystem: filesystem_snapshot(&twins.baseline.root)?,
        network: vec![],
        wall_duration_ms: baseline.0.iter().map(|r| r.duration_ms).sum(),
        cpu_ms: None,
        peak_memory_bytes: None,
    };
    let candidate_behavior = BehaviorObservation {
        measurement_method: "docker-top-v1; filesystem-snapshot-v1; network-deny".into(),
        processes: candidate.1,
        filesystem: filesystem_snapshot(&twins.candidate.root)?,
        network: vec![],
        wall_duration_ms: candidate.0.iter().map(|r| r.duration_ms).sum(),
        cpu_ms: None,
        peak_memory_bytes: None,
    };
    let behavior = compare(&base_behavior, &candidate_behavior);
    let osv = osv_npm(&name, &to).await;
    let provenance = inspect_npm(&to_meta);
    let delta = metadata_delta(&from_meta, &to_meta);
    let policy = evaluate(
        &cfg.policy,
        &delta,
        &osv,
        &provenance,
        !behavior.new_network_destinations.is_empty(),
    );
    let mut results = BTreeMap::new();
    results.insert("baseline".into(), baseline.0);
    results.insert("candidate".into(), candidate.0);
    let evidence = CanonicalEvidence {
        schema_version: "2".into(),
        normalization_version: "1".into(),
        methodology_version: "1".into(),
        package_purl: to_artifact.coordinate.purl(),
        from_version: from,
        to_version: to,
        baseline_artifact_sha256: from_artifact.sha256.clone(),
        candidate_artifact_sha256: to_artifact.sha256.clone(),
        baseline_lockfile_digest: twins.baseline.lockfile_digest.clone(),
        candidate_lockfile_digest: twins.candidate.lockfile_digest.clone(),
        baseline_graph_digest: twins.baseline.graph_digest.clone(),
        candidate_graph_digest: twins.candidate.graph_digest.clone(),
        command_results: results,
        behavior_digests: BTreeMap::from([
            ("baseline".into(), behavior_digest(&base_behavior)),
            ("candidate".into(), behavior_digest(&candidate_behavior)),
        ]),
        policy_outcome: policy.outcome,
        external_intelligence: vec![osv],
        provenance,
    };
    let public_evidence = project_public(
        "npm",
        &name,
        &from_artifact.coordinate,
        &to_artifact.coordinate,
        Artifacts {
            baseline_artifact_digest: from_artifact.sha256.clone(),
            candidate_artifact_digest: to_artifact.sha256.clone(),
            baseline_registry_integrity: from_artifact.integrity.clone(),
            candidate_registry_integrity: to_artifact.integrity.clone(),
            baseline_lockfile_digest: twins.baseline.lockfile_digest.clone(),
            candidate_lockfile_digest: twins.candidate.lockfile_digest.clone(),
            baseline_dependency_graph_digest: twins.baseline.graph_digest.clone(),
            candidate_dependency_graph_digest: twins.candidate.graph_digest.clone(),
            behavior_evidence_digest: behavior_digest(&candidate_behavior),
        },
        evidence.command_results.clone(),
        &base_behavior,
        &candidate_behavior,
        evidence.external_intelligence.clone(),
        evidence.provenance.clone(),
        PublicPolicy {
            outcome: evidence.policy_outcome.clone(),
            findings: policy.findings.clone(),
        },
        sandbox.image.clone(),
    );
    let public_run = VerificationRun::new(
        public_evidence,
        VerificationRunMetadata {
            run_id: format!("local-{}", std::process::id()),
            raw_wall_duration_ms: base_behavior.wall_duration_ms
                + candidate_behavior.wall_duration_ms,
            started_at: None,
            completed_at: None,
            container_ids: vec![],
            temporary_paths: vec![],
        },
    )?;
    if let Some(path) = evidence_out {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&public_run.compatibility_evidence)?,
        )?;
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "compatibilityEvidence":public_run.compatibility_evidence,
                "compatibilityEvidenceDigest":public_run.compatibility_evidence_digest,
                "run": public_run.run,
                "installation": {
                    "baselineInstalledVersion": baseline_installed,
                    "candidateInstalledVersion": candidate_installed,
                    "artifactIntegrity": {
                        "baseline": from_artifact.integrity_verified,
                        "candidate": to_artifact.integrity_verified
                    }
                },
                    "observed": {
                        "behaviorDiff":behavior,
                        "processObservation": {"status":"PARTIAL", "backend":"docker-process-polling"},
                        "network": {"status":"DENIED_BY_SANDBOX_POLICY", "observation":"NOT_IMPLEMENTED"}
                },
                "policy":{"findings":policy.findings}
            }))?
        );
    } else {
        println!(
            "DepGuard verification\n{}\n{} -> {}\nbaseline artifact: {}\ncandidate artifact: {}\nbaseline installed state lock: {}\ncandidate installed state lock: {}\nnetwork: DENIED BY SANDBOX POLICY\ncanonical evidence: {}",
            evidence.package_purl,
            evidence.from_version,
            evidence.to_version,
            evidence.baseline_artifact_sha256,
            evidence.candidate_artifact_sha256,
            evidence.baseline_lockfile_digest,
            evidence.candidate_lockfile_digest,
            evidence.digest()
        );
    }
    Ok(())
}
fn evidence_package_version(metadata: &depguard_core::PackageMetadata) -> String {
    metadata.coordinate.version.clone()
}
fn installed_version(root: &Path, package: &str) -> Result<String> {
    let path = root.join("node_modules").join(package).join("package.json");
    let package: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&path)
            .with_context(|| format!("read installed package metadata at {}", path.display()))?,
    )?;
    package
        .get("version")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .context("installed package metadata has no version")
}
fn commands(
    root: &Path,
    overrides: &BTreeMap<String, String>,
) -> Result<Vec<(String, Option<String>)>> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("package.json"))?)?;
    let scripts = manifest
        .get("scripts")
        .and_then(serde_json::Value::as_object);
    let mut output = vec![(
        "install".into(),
        Some("npm ci --offline --ignore-scripts --no-audit --no-fund".into()),
    )];
    for name in ["build", "test", "typecheck", "lint", "integration", "e2e"] {
        if let Some(c) = overrides.get(name) {
            output.push((name.into(), Some(c.clone())));
        } else if scripts.is_some_and(|s| s.contains_key(name)) {
            output.push((name.into(), Some(format!("npm run {name}"))));
        } else {
            output.push((name.into(), None));
        }
    }
    Ok(output)
}
async fn execute(
    root: &Path,
    commands: &[(String, Option<String>)],
    sandbox: &SandboxConfig,
) -> Result<(
    Vec<depguard_core::CommandResult>,
    Vec<depguard_core::ProcessObservation>,
)> {
    let mut results = vec![];
    let mut processes = vec![];
    for (name, command) in commands {
        let Some(command) = command else {
            results.push(depguard_core::CommandResult {
                name: name.clone(),
                status: CommandStatus::NotConfigured,
                exit_code: None,
                duration_ms: 0,
                cpu_ms: None,
                peak_memory_bytes: None,
                stdout_digest: depguard_core::sha256_bytes(b""),
                stderr_digest: depguard_core::sha256_bytes(b""),
            });
            continue;
        };
        let r = run_sandbox(root, command, sandbox, name).await?;
        processes.extend(r.processes);
        let failed = r.command.status != CommandStatus::Passed;
        results.push(r.command);
        if failed {
            break;
        }
    }
    Ok((results, processes))
}
fn parse_timeout(value: &str) -> Result<Duration> {
    let seconds = if let Some(v) = value.strip_suffix('m') {
        v.parse::<u64>()? * 60
    } else if let Some(v) = value.strip_suffix('s') {
        v.parse()?
    } else {
        anyhow::bail!("timeout must end in s or m")
    };
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_scripts_are_explicit_not_configured() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("package.json"),
            r#"{"scripts":{"test":"node --test"}}"#,
        )
        .unwrap();
        let plan = commands(project.path(), &BTreeMap::new()).unwrap();
        assert_eq!(plan.len(), 7);
        assert!(
            plan.iter()
                .any(|(name, command)| name == "build" && command.is_none())
        );
        assert!(
            plan.iter()
                .any(|(name, command)| name == "test" && command.is_some())
        );
        assert!(
            plan.iter()
                .any(|(name, command)| name == "e2e" && command.is_none())
        );
    }
}
