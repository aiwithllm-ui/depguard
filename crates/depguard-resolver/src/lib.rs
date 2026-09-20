use anyhow::{Context, Result, bail};
use depguard_core::{Artifact, PreparedWorld};
use depguard_npm::lock_graph;
use std::{fs, path::Path};
use tempfile::TempDir;
use tokio::process::Command;

#[cfg(unix)]
fn make_workspace_writable(root: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
    {
        let mode = if entry.file_type().is_dir() {
            0o777
        } else {
            0o666
        };
        fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_workspace_writable(_: &Path) -> Result<()> {
    Ok(())
}

pub struct TwinWorkspaces {
    pub _temp: TempDir,
    pub baseline: PreparedWorld,
    pub candidate: PreparedWorld,
}
fn copy_project(source: &Path, target: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(source)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        let rel = entry.path().strip_prefix(source)?;
        if rel.components().any(|c| {
            matches!(
                c.as_os_str().to_str(),
                Some("node_modules")
                    | Some(".git")
                    | Some(".depguard")
                    | Some(".env")
                    | Some(".npmrc")
                    | Some(".aws")
                    | Some(".ssh")
            )
        }) {
            continue;
        }
        let out = target.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(out)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?
            };
            fs::copy(entry.path(), out)?;
        }
    }
    Ok(())
}
async fn prepare_world(root: &Path, name: &str, artifact: &Artifact) -> Result<PreparedWorld> {
    let artifacts = root.join(".depguard/artifacts");
    tokio::fs::create_dir_all(&artifacts).await?;
    let local = artifacts.join(format!(
        "{}-{}.tgz",
        artifact.coordinate.name.replace('/', "_"),
        artifact.coordinate.version
    ));
    tokio::fs::copy(&artifact.cache_path, &local).await?;
    let manifest_path = root.join("package.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let mut found = false;
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(entries) = manifest
            .get_mut(section)
            .and_then(serde_json::Value::as_object_mut)
            && entries.contains_key(name)
        {
            entries.insert(
                name.into(),
                serde_json::Value::String(format!(
                    "file:.depguard/artifacts/{}",
                    local.file_name().unwrap().to_string_lossy()
                )),
            );
            found = true;
        }
    }
    if !found {
        bail!("{name} is not a direct dependency");
    }
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    let output = Command::new("npm")
        .args([
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--offline",
            "--no-audit",
            "--no-fund",
        ])
        .current_dir(root)
        .output()
        .await
        .context("prepare deterministic npm lockfile")?;
    if !output.status.success() {
        bail!(
            "npm could not prepare local lockfile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let lock_path = root.join("package-lock.json");
    let lock = fs::read(&lock_path).context("prepared project has no package-lock.json")?;
    let graph = lock_graph(root)?;
    Ok(PreparedWorld {
        root: root.into(),
        package: artifact.coordinate.clone(),
        artifact: artifact.clone(),
        lockfile_digest: depguard_core::sha256_bytes(&lock),
        graph_digest: graph.digest(),
        graph,
    })
}
pub async fn prepare_twins(
    source: &Path,
    dependency: &str,
    baseline: &Artifact,
    candidate: &Artifact,
) -> Result<TwinWorkspaces> {
    let temp = tempfile::tempdir()?;
    let base = temp.path().join("baseline");
    let cand = temp.path().join("candidate");
    copy_project(source, &base)?;
    copy_project(source, &cand)?;
    let baseline = prepare_world(&base, dependency, baseline).await?;
    let candidate = prepare_world(&cand, dependency, candidate).await?;
    // The container runs as an explicit unprivileged UID. The copied temporary tree must
    // be writable by that UID for npm to create node_modules; no user tree is modified.
    make_workspace_writable(&base)?;
    make_workspace_writable(&cand)?;
    Ok(TwinWorkspaces {
        _temp: temp,
        baseline,
        candidate,
    })
}
