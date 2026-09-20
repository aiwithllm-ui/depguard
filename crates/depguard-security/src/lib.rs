use depguard_core::ExternalIntelligence;
use serde::Deserialize;

#[derive(Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}
#[derive(Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
}
pub async fn osv_npm(package: &str, version: &str) -> ExternalIntelligence {
    let body = serde_json::json!({"package":{"ecosystem":"npm","name":package},"version":version});
    let timestamp = format!("{:?}", std::time::SystemTime::now());
    match reqwest::Client::new()
        .post("https://api.osv.dev/v1/query")
        .json(&body)
        .send()
        .await
    {
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.json::<OsvResponse>().await {
                Ok(parsed) => ExternalIntelligence {
                    provider: "OSV".into(),
                    retrieved_at: Some(timestamp),
                    source_id: Some("https://api.osv.dev/v1/query".into()),
                    status: "available".into(),
                    findings: parsed
                        .vulns
                        .into_iter()
                        .map(|v| {
                            if v.aliases.is_empty() {
                                v.id
                            } else {
                                format!("{} ({})", v.id, v.aliases.join(","))
                            }
                        })
                        .collect(),
                },
                Err(error) => unavailable("OSV", error.to_string(), timestamp),
            },
            Err(error) => unavailable("OSV", error.to_string(), timestamp),
        },
        Err(error) => unavailable("OSV", error.to_string(), timestamp),
    }
}
fn unavailable(provider: &str, error: String, timestamp: String) -> ExternalIntelligence {
    ExternalIntelligence {
        provider: provider.into(),
        retrieved_at: Some(timestamp),
        source_id: None,
        status: format!("unavailable: {error}"),
        findings: vec![],
    }
}
