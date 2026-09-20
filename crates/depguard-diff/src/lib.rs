use depguard_core::{BehaviorObservation, FileObservation, ProcessObservation};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehaviorDiff {
    pub new_processes: Vec<ProcessObservation>,
    pub removed_processes: Vec<ProcessObservation>,
    pub created_files: Vec<FileObservation>,
    pub removed_files: Vec<FileObservation>,
    pub modified_files: Vec<String>,
    pub new_network_destinations: Vec<String>,
}
pub fn compare(base: &BehaviorObservation, candidate: &BehaviorObservation) -> BehaviorDiff {
    let bp: BTreeSet<_> = base.processes.iter().cloned().collect();
    let cp: BTreeSet<_> = candidate.processes.iter().cloned().collect();
    let bf: BTreeSet<_> = base.filesystem.iter().cloned().collect();
    let cf: BTreeSet<_> = candidate.filesystem.iter().cloned().collect();
    let bn: BTreeSet<_> = base.network.iter().cloned().collect();
    let cn: BTreeSet<_> = candidate.network.iter().cloned().collect();
    BehaviorDiff {
        new_processes: cp.difference(&bp).cloned().collect(),
        removed_processes: bp.difference(&cp).cloned().collect(),
        created_files: cf.difference(&bf).cloned().collect(),
        removed_files: bf.difference(&cf).cloned().collect(),
        modified_files: candidate
            .filesystem
            .iter()
            .filter_map(|f| {
                base.filesystem
                    .iter()
                    .find(|b| b.path == f.path && b.sha256 != f.sha256)
                    .map(|_| f.path.clone())
            })
            .collect(),
        new_network_destinations: cn
            .difference(&bn)
            .map(|n| format!("{}:{}", n.destination, n.port))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_created_file() {
        let candidate = BehaviorObservation {
            filesystem: vec![FileObservation {
                path: "marker".into(),
                kind: "file".into(),
                size: 1,
                sha256: None,
                executable: false,
            }],
            ..Default::default()
        };
        assert_eq!(
            compare(&BehaviorObservation::default(), &candidate).created_files[0].path,
            "marker"
        );
    }
}
