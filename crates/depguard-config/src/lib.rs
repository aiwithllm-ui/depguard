use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u8,
    #[serde(default)]
    pub verify: Verify,
    #[serde(default)]
    pub sandbox: Sandbox,
    #[serde(default)]
    pub behavior: Behavior,
    #[serde(default)]
    pub privacy: Privacy,
    #[serde(default)]
    pub policy: Policy,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Verify {
    #[serde(default)]
    pub commands: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sandbox {
    #[serde(default = "deny")]
    pub network: String,
    #[serde(default = "memory")]
    pub memory: String,
    #[serde(default = "cpus")]
    pub cpus: u8,
    #[serde(default = "timeout")]
    pub timeout: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Behavior {
    #[serde(default = "yes")]
    pub filesystem: bool,
    #[serde(default = "yes")]
    pub processes: bool,
    #[serde(default = "yes")]
    pub network: bool,
    #[serde(default = "yes")]
    pub performance: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Privacy {
    #[serde(default)]
    pub publish_evidence: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    #[serde(default)]
    pub vulnerabilities: BTreeMap<String, String>,
    #[serde(default)]
    pub lifecycle_scripts: BTreeMap<String, String>,
    #[serde(default)]
    pub provenance: BTreeMap<String, String>,
    #[serde(default)]
    pub licenses: LicensePolicy,
    #[serde(default)]
    pub behavior: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LicensePolicy {
    #[serde(default)]
    pub deny: Vec<String>,
}
fn deny() -> String {
    "deny".into()
}
fn memory() -> String {
    "4GiB".into()
}
fn cpus() -> u8 {
    2
}
fn timeout() -> String {
    "20m".into()
}
fn yes() -> bool {
    true
}
impl Default for Sandbox {
    fn default() -> Self {
        Self {
            network: deny(),
            memory: memory(),
            cpus: cpus(),
            timeout: timeout(),
        }
    }
}
impl Default for Behavior {
    fn default() -> Self {
        Self {
            filesystem: true,
            processes: true,
            network: true,
            performance: true,
        }
    }
}
impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            verify: Verify::default(),
            sandbox: Sandbox::default(),
            behavior: Behavior::default(),
            privacy: Privacy::default(),
            policy: Policy::default(),
        }
    }
}
pub fn load(path: &Path) -> Result<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let c: Config = serde_yaml::from_str(&fs::read_to_string(path).context("read depguard.yaml")?)
        .context("invalid depguard.yaml")?;
    if c.version != 1 {
        bail!("depguard.yaml version must be 1");
    }
    if !matches!(c.sandbox.network.as_str(), "deny" | "observe" | "allowlist") {
        bail!("sandbox.network must be deny, observe, or allowlist");
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_explicit_policy_and_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("depguard.yaml");
        fs::write(&path, "version: 1\nsandbox:\n  network: deny\n  memory: 1GiB\npolicy:\n  licenses:\n    deny: [AGPL-3.0]\n").unwrap();
        let config = load(&path).unwrap();
        assert_eq!(config.sandbox.memory, "1GiB");
        assert_eq!(config.policy.licenses.deny, ["AGPL-3.0"]);
    }
}
