//! Hardened Docker backend. It deliberately supports only network=deny until a recording
//! proxy exists; silently enabling unrestricted network would violate DepGuard's boundary.
use anyhow::{Context, Result, bail};
use depguard_core::{CommandResult, CommandStatus, ProcessObservation};
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{process::Command, time::sleep};

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub image: String,
    pub memory: String,
    pub cpus: u8,
    pub timeout: Duration,
    pub network: String,
}
#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub command: CommandResult,
    pub processes: Vec<ProcessObservation>,
}

pub async fn doctor() -> Result<String> {
    let output = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .await
        .context("run docker info")?;
    if !output.status.success() {
        bail!(
            "Docker daemon is unavailable: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().into())
}

pub async fn run(
    workspace: &Path,
    command: &str,
    cfg: &SandboxConfig,
    label: &str,
) -> Result<SandboxResult> {
    if cfg.network != "deny" {
        bail!(
            "network mode '{}' is not available safely yet; use deny",
            cfg.network
        );
    }
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let name = format!("depguard-{}-{}", std::process::id(), nonce);
    let mount = format!("{}:/workspace:rw", workspace.display());
    let args = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        name.clone(),
        "--network=none".into(),
        "--read-only".into(),
        "--user=10001:10001".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges".into(),
        "--pids-limit=128".into(),
        "--memory".into(),
        cfg.memory.clone(),
        "--cpus".into(),
        cfg.cpus.to_string(),
        "--tmpfs".into(),
        "/tmp:rw,nosuid,nodev,size=256m".into(),
        "--tmpfs".into(),
        "/home/depguard:rw,nosuid,nodev,size=64m".into(),
        "-v".into(),
        mount,
        "-w".into(),
        "/workspace".into(),
        "-e".into(),
        "HOME=/home/depguard".into(),
        "-e".into(),
        "TMPDIR=/tmp".into(),
        "-e".into(),
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        "-e".into(),
        "LANG=C.UTF-8".into(),
        "-e".into(),
        "CI=true".into(),
        "-e".into(),
        "DEPGUARD_OBSERVATION_DIR=/workspace/.depguard-observation".into(),
        cfg.image.clone(),
        "sh".into(),
        "-lc".into(),
        command.into(),
    ];
    let output = Command::new("docker")
        .args(&args)
        .output()
        .await
        .context("start hardened Docker sandbox")?;
    if !output.status.success() {
        bail!(
            "unable to start sandbox: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let started = Instant::now();
    let mut processes = BTreeSet::new();
    let mut timed_out = false;
    loop {
        let top = Command::new("docker")
            .args(["top", &name, "-eo", "pid,ppid,args"])
            .output()
            .await;
        if let Ok(top) = top {
            collect_processes(&String::from_utf8_lossy(&top.stdout), &mut processes);
        }
        let inspect = Command::new("docker")
            .args(["inspect", "--format", "{{.State.Running}}", &name])
            .output()
            .await?;
        if String::from_utf8_lossy(&inspect.stdout).trim() != "true" {
            break;
        }
        if started.elapsed() >= cfg.timeout {
            timed_out = true;
            let _ = Command::new("docker").args(["kill", &name]).output().await;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let logs = Command::new("docker")
        .args(["logs", &name])
        .output()
        .await?;
    let exit = Command::new("docker")
        .args(["inspect", "--format", "{{.State.ExitCode}}", &name])
        .output()
        .await?;
    let exit_code = String::from_utf8_lossy(&exit.stdout)
        .trim()
        .parse::<i32>()
        .ok();
    let _ = Command::new("docker")
        .args(["rm", "-f", &name])
        .output()
        .await;
    let status = if timed_out {
        CommandStatus::TimedOut
    } else if exit_code == Some(0) {
        CommandStatus::Passed
    } else {
        CommandStatus::Failed
    };
    Ok(SandboxResult {
        command: CommandResult {
            name: label.into(),
            status,
            exit_code,
            duration_ms: started.elapsed().as_millis(),
            cpu_ms: None,
            peak_memory_bytes: None,
            stdout_digest: depguard_core::sha256_bytes(&logs.stdout),
            stderr_digest: depguard_core::sha256_bytes(&logs.stderr),
        },
        processes: processes.into_iter().collect(),
    })
}
fn collect_processes(output: &str, processes: &mut BTreeSet<ProcessObservation>) {
    for line in output.lines().skip(1) {
        let mut p = line.split_whitespace();
        let _pid = p.next();
        let _ppid = p.next();
        let command = p.collect::<Vec<_>>().join(" ");
        if command.is_empty() {
            continue;
        }
        let mut parts = command.split_whitespace();
        let executable: String = parts.next().unwrap_or_default().into();
        let arguments: Vec<String> = parts
            .map(|x| {
                if x.contains("token=") || x.contains("password=") {
                    "<redacted>".into()
                } else {
                    x.into()
                }
            })
            .collect();
        // `docker top` is sampled. Shell/npm/test-runner entries can appear or disappear
        // between samples; preserve independently spawned Node children as the stable
        // currently-supported process signal.
        if !executable.ends_with("node") || arguments.first().map(String::as_str) != Some("-e") {
            continue;
        }
        processes.insert(ProcessObservation {
            executable,
            arguments,
            parent_executable: None,
            exit_code: None,
        });
    }
}
