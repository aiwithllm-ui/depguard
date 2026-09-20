use async_trait::async_trait;
use depguard_core::{Artifact, DependencyGraph, PackageMetadata};
use std::path::Path;

#[async_trait]
pub trait EcosystemAdapter: Send + Sync {
    fn ecosystem(&self) -> &'static str;
    async fn current_direct_version(&self, project: &Path, package: &str)
    -> anyhow::Result<String>;
    async fn resolve_metadata(
        &self,
        package: &str,
        version: &str,
    ) -> anyhow::Result<PackageMetadata>;
    async fn fetch_artifact(
        &self,
        metadata: &PackageMetadata,
        cache: &Path,
    ) -> anyhow::Result<Artifact>;
    fn graph_from_lockfile(&self, project: &Path) -> anyhow::Result<DependencyGraph>;
}
