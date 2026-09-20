//! Explicit opt-in HTTP client for the optional DepGuard global network.
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IngestStatus {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestResponse {
    pub status: IngestStatus,
    #[serde(default)]
    pub evidence_id: Option<String>,
    #[serde(default)]
    pub duplicate: Option<bool>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct NetworkClient {
    base_url: String,
    http: reqwest::Client,
}

impl NetworkClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
            bail!("network URL must be http(s)");
        }
        Ok(Self {
            base_url,
            http: reqwest::Client::builder().build()?,
        })
    }

    /// Sends exactly the supplied signed envelope bytes—never a project tree,
    /// logs, environment, or credentials.
    pub async fn publish_bytes(&self, attestation: Vec<u8>) -> Result<IngestResponse> {
        let response = self
            .http
            .post(format!("{}/v1/evidence", self.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(attestation)
            .send()
            .await
            .context("submit attestation")?;
        let status = response.status();
        let body: IngestResponse = response.json().await.context("decode network response")?;
        if !status.is_success() && body.status != IngestStatus::Rejected {
            bail!("network returned HTTP {status}");
        }
        Ok(body)
    }

    /// Submits exact already-signed V1 bytes and, only when supplied by the
    /// caller, an independent Sigstore bundle. The wrapper is network metadata;
    /// it cannot alter the bytes committed by the Sigstore signature.
    pub async fn publish_submission(
        &self,
        attestation: Vec<u8>,
        identity_proof: Option<Value>,
    ) -> Result<IngestResponse> {
        let body = NetworkSubmission {
            depguard_attestation: STANDARD.encode(attestation),
            identity_proof,
        };
        let response = self
            .http
            .post(format!("{}/v1/submissions", self.base_url))
            .json(&body)
            .send()
            .await
            .context("submit network submission")?;
        let status = response.status();
        let body: IngestResponse = response.json().await.context("decode network response")?;
        if !status.is_success() && body.status != IngestStatus::Rejected {
            bail!("network returned HTTP {status}");
        }
        Ok(body)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkSubmission {
    depguard_attestation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_proof: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, body::Bytes, extract::State, routing::post};
    use std::{
        future::IntoFuture,
        sync::{Arc, Mutex},
    };

    async fn capture(
        State(captured): State<Arc<Mutex<Vec<u8>>>>,
        body: Bytes,
    ) -> Json<IngestResponse> {
        *captured.lock().unwrap() = body.to_vec();
        Json(IngestResponse {
            status: IngestStatus::Accepted,
            evidence_id: Some("sha256:test".into()),
            duplicate: Some(false),
            reason: None,
        })
    }

    #[tokio::test]
    #[ignore = "requires loopback listener permission; run explicitly in the network audit"]
    async fn publish_sends_exact_attestation_bytes_only() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/v1/evidence", post(capture))
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(axum::serve(listener, app).into_future());
        let public_attestation = br#"{"payloadType":"application/vnd.in-toto+json","payload":"public-only","signatures":[]}"#.to_vec();

        let reply = NetworkClient::new(url)
            .unwrap()
            .publish_bytes(public_attestation.clone())
            .await
            .unwrap();

        assert_eq!(reply.status, IngestStatus::Accepted);
        assert_eq!(*captured.lock().unwrap(), public_attestation);
        server.abort();
    }
}
