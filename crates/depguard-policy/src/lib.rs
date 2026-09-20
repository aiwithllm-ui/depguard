use depguard_config::Policy;
use depguard_core::{ExternalIntelligence, ProvenanceEvidence};
use std::collections::BTreeMap;
#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub outcome: String,
    pub findings: Vec<String>,
}
pub fn evaluate(
    policy: &Policy,
    delta: &BTreeMap<String, serde_json::Value>,
    osv: &ExternalIntelligence,
    provenance: &ProvenanceEvidence,
    new_network: bool,
) -> PolicyResult {
    let mut findings = Vec::new();
    let mut deny = false;
    if delta
        .get("newLifecycleScripts")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|v| !v.is_empty())
        && policy
            .lifecycle_scripts
            .get("newlyAdded")
            .is_some_and(|v| v == "review")
    {
        findings.push("policy: new lifecycle scripts require review".into());
    }
    if provenance.status == "invalid"
        && policy
            .provenance
            .get("invalid")
            .is_some_and(|v| v == "deny")
    {
        deny = true;
        findings.push("policy: invalid provenance denied".into());
    }
    if new_network
        && policy
            .behavior
            .get("newNetworkDestination")
            .is_some_and(|v| v == "review")
    {
        findings.push("policy: new network destination requires review".into());
    }
    if !osv.findings.is_empty()
        && policy
            .vulnerabilities
            .get("high")
            .is_some_and(|v| v == "deny")
    {
        deny = true;
        findings.push("policy: vulnerability denied".into());
    }
    let outcome = if deny {
        "POLICY_DENIED"
    } else if findings.is_empty() {
        "NO_POLICY_FINDING"
    } else {
        "REVIEW_REQUIRED"
    };
    PolicyResult {
        outcome: outcome.into(),
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_script_requires_review() {
        let policy = Policy {
            lifecycle_scripts: BTreeMap::from([("newlyAdded".into(), "review".into())]),
            ..Default::default()
        };
        let delta = BTreeMap::from([(
            "newLifecycleScripts".into(),
            serde_json::json!(["postinstall"]),
        )]);
        let result = evaluate(
            &policy,
            &delta,
            &ExternalIntelligence::default(),
            &ProvenanceEvidence::default(),
            false,
        );
        assert_eq!(result.outcome, "REVIEW_REQUIRED");
    }
}
