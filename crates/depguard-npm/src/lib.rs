//! npm adapter. Registry access and artifact verification happen before sandbox execution.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use depguard_core::{Artifact, DependencyGraph, PackageCoordinate, PackageMetadata, sha256_bytes};
use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha512};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Clone)]
pub struct NpmRegistry {
    client: Client,
    base: String,
}
impl NpmRegistry {
    pub fn new() -> Result<Self> {
        Self::with_base(
            &std::env::var("DEPGUARD_NPM_REGISTRY")
                .unwrap_or_else(|_| "https://registry.npmjs.org".into()),
        )
    }
    pub fn with_base(base: &str) -> Result<Self> {
        Ok(Self {
            client: Client::builder().user_agent("depguard/0.2.0").build()?,
            base: base.trim_end_matches('/').into(),
        })
    }
    pub async fn metadata(&self, package: &str, version: &str) -> Result<PackageMetadata> {
        let package_path = package.replace('/', "%2f");
        let root: Value = self
            .client
            .get(format!("{}/{}", self.base, package_path))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let version_data = root
            .get("versions")
            .and_then(|v| v.get(version))
            .cloned()
            .context("requested npm version was not returned by registry")?;
        parse_metadata(
            package,
            version,
            &version_data,
            root.get("time")
                .and_then(|v| v.get(version))
                .and_then(Value::as_str),
        )
    }
    pub async fn fetch(&self, metadata: &PackageMetadata, cache_root: &Path) -> Result<Artifact> {
        let url = metadata
            .tarball_url
            .as_ref()
            .context("npm metadata did not include dist.tarball")?;
        let response = self.client.get(url).send().await?.error_for_status()?;
        let bytes = response.bytes().await?;
        let sha256 = sha256_bytes(&bytes);
        if let Some(integrity) = &metadata.dist_integrity {
            verify_sri(integrity, &bytes)?;
        }
        let path = cache_root
            .join("sha256")
            .join(sha256.trim_start_matches("sha256:"));
        tokio::fs::create_dir_all(&path).await?;
        let artifact_path = path.join("package.tgz");
        if !artifact_path.exists() {
            tokio::fs::write(&artifact_path, &bytes).await?;
        }
        Ok(Artifact {
            coordinate: metadata.coordinate.clone(),
            source_url: url.clone(),
            integrity: metadata.dist_integrity.clone(),
            sha256,
            cache_path: artifact_path,
            size_bytes: bytes.len() as u64,
            integrity_verified: metadata.dist_integrity.is_some(),
        })
    }
}

fn map_strings(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.into())))
                .collect()
        })
        .unwrap_or_default()
}
fn parse_metadata(
    name: &str,
    version: &str,
    v: &Value,
    published: Option<&str>,
) -> Result<PackageMetadata> {
    let dist = v.get("dist").unwrap_or(&Value::Null);
    let maintainers = v
        .get("maintainers")
        .and_then(Value::as_array)
        .map(|xs| {
            xs.iter()
                .filter_map(|x| {
                    x.get("email")
                        .or_else(|| x.get("name"))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default();
    let repository = v
        .get("repository")
        .and_then(|r| r.get("url").or(Some(r)))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(PackageMetadata {
        coordinate: PackageCoordinate {
            ecosystem: "npm".into(),
            name: name.into(),
            version: version.into(),
        },
        published_at: published.map(str::to_owned),
        maintainers,
        repository,
        license: v.get("license").and_then(Value::as_str).map(str::to_owned),
        engines: map_strings(v.get("engines")),
        dependencies: map_strings(v.get("dependencies")),
        optional_dependencies: map_strings(v.get("optionalDependencies")),
        peer_dependencies: map_strings(v.get("peerDependencies")),
        scripts: map_strings(v.get("scripts")),
        dist_integrity: dist
            .get("integrity")
            .and_then(Value::as_str)
            .map(str::to_owned),
        tarball_url: dist
            .get("tarball")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}
pub fn verify_sri(integrity: &str, bytes: &[u8]) -> Result<()> {
    let token = integrity
        .split_whitespace()
        .next()
        .context("empty npm integrity")?;
    let (algorithm, encoded) = token.split_once('-').context("invalid npm SRI format")?;
    if algorithm != "sha512" {
        bail!("unsupported npm SRI algorithm: {algorithm}");
    }
    let expected = STANDARD.decode(encoded)?;
    let actual = Sha512::digest(bytes);
    if expected.as_slice() != actual.as_slice() {
        bail!("npm artifact integrity mismatch");
    }
    Ok(())
}

pub fn current_direct_version(project: &Path, package: &str) -> Result<String> {
    let manifest: Value = serde_json::from_slice(&fs::read(project.join("package.json"))?)?;
    if let Ok(lock) = fs::read(project.join("package-lock.json")) {
        let lock: Value = serde_json::from_slice(&lock)?;
        if let Some(v) = lock
            .pointer(&format!("/packages/node_modules/{package}/version"))
            .and_then(Value::as_str)
        {
            return Ok(v.into());
        }
    }
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(v) = manifest
            .pointer(&format!("/{section}/{package}"))
            .and_then(Value::as_str)
        {
            return Ok(v
                .trim_start_matches(['^', '~', 'v', '=', '>', '<', ' '])
                .into());
        }
    }
    bail!("{package} is not a direct dependency")
}
pub fn lock_graph(project: &Path) -> Result<DependencyGraph> {
    let lock_path = project.join("package-lock.json");
    if !lock_path.exists() {
        return Ok(DependencyGraph::default());
    }
    let lock: Value = serde_json::from_slice(&fs::read(lock_path)?)?;
    let mut graph = DependencyGraph::default();
    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        for (location, entry) in packages {
            if location.is_empty() {
                continue;
            }
            if let Some(version) = entry.get("version").and_then(Value::as_str) {
                graph.nodes.insert(location.clone(), version.into());
            }
            let deps = entry
                .get("dependencies")
                .and_then(Value::as_object)
                .map(|d| d.keys().cloned().collect())
                .unwrap_or_default();
            graph.edges.insert(location.clone(), deps);
        }
    }
    Ok(graph)
}
pub fn metadata_delta(from: &PackageMetadata, to: &PackageMetadata) -> BTreeMap<String, Value> {
    let mut result = BTreeMap::new();
    result.insert(
        "licenseChanged".into(),
        Value::Bool(from.license != to.license),
    );
    result.insert(
        "maintainersChanged".into(),
        Value::Bool(from.maintainers != to.maintainers),
    );
    result.insert(
        "repositoryChanged".into(),
        Value::Bool(from.repository != to.repository),
    );
    result.insert(
        "enginesChanged".into(),
        Value::Bool(from.engines != to.engines),
    );
    result.insert(
        "newLifecycleScripts".into(),
        Value::Array(
            to.scripts
                .keys()
                .filter(|k| {
                    matches!(k.as_str(), "preinstall" | "install" | "postinstall")
                        && !from.scripts.contains_key(*k)
                })
                .map(|k| Value::String(k.clone()))
                .collect(),
        ),
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    #[test]
    fn validates_sri_and_rejects_corruption() {
        let bytes = b"controlled artifact";
        let sri = format!("sha512-{}", STANDARD.encode(Sha512::digest(bytes)));
        verify_sri(&sri, bytes).unwrap();
        assert!(verify_sri(&sri, b"controlled artifact!").is_err());
    }

    #[test]
    fn parses_registry_metadata() {
        let value: Value = serde_json::json!({"license":"MIT","dist":{"integrity":"sha512-YQ==","tarball":"http://registry/a.tgz"},"scripts":{"postinstall":"node x"}});
        let metadata = parse_metadata(
            "example-package",
            "1.0.0",
            &value,
            Some("2020-01-01T00:00:00Z"),
        )
        .unwrap();
        assert_eq!(metadata.coordinate.purl(), "pkg:npm/example-package@1.0.0");
        assert_eq!(metadata.scripts["postinstall"], "node x");
    }
}
