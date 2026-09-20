use depguard_core::{BehaviorObservation, FileObservation, sha256_bytes};
use std::{fs, path::Path};
use walkdir::WalkDir;

pub fn filesystem_snapshot(root: &Path) -> anyhow::Result<Vec<FileObservation>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path == root
            || path.components().any(|p| {
                matches!(
                    p.as_os_str().to_str(),
                    Some("node_modules") | Some(".depguard")
                )
            })
        {
            continue;
        }
        let meta = fs::symlink_metadata(path)?;
        let relative = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        let kind = if meta.file_type().is_symlink() {
            "symlink"
        } else if meta.is_dir() {
            "directory"
        } else {
            "file"
        };
        let digest = if meta.is_file() {
            Some(sha256_bytes(&fs::read(path)?))
        } else {
            None
        };
        #[cfg(unix)]
        let executable = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let executable = false;
        files.push(FileObservation {
            path: normalize_path(&relative),
            kind: kind.into(),
            size: meta.len(),
            sha256: digest,
            executable,
        });
    }
    files.sort();
    Ok(files)
}
pub fn normalize_path(path: &str) -> String {
    path.split('/')
        .map(|part| {
            if part.starts_with("depguard-") || part.starts_with("tmp-") {
                "<temp>"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}
pub fn behavior_digest(observation: &BehaviorObservation) -> String {
    let mut normalized = observation.clone();
    normalized.wall_duration_ms = 0;
    normalized.cpu_ms = None;
    normalized.peak_memory_bytes = None;
    sha256_bytes(&serde_json::to_vec(&normalized).expect("serialize observation"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_temporary_path_segments() {
        assert_eq!(
            normalize_path("tmp-42/depguard-run/file"),
            "<temp>/<temp>/file"
        );
    }
}
