use reqwest::StatusCode;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::types::{
    FailMode, FrameworkId, SigilClient, SigilClientBuilder, SigilClientError, SigilConfig,
    SigilDecision, SigilIntent, SigilResult,
};

const DEFAULT_API_URL: &str = "https://sign.sigilcore.com";
const DEFAULT_TIMEOUT_SECS: u64 = 5;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizeRequest<'a> {
    framework: &'a FrameworkId,
    agent_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_commit: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_id: Option<u64>,
    intent: AuthorizeIntent<'a>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizeIntent<'a> {
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_address: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct AuthorizeResponse {
    status: String,
    #[serde(default, alias = "errorCode")]
    error_code: Option<String>,
    message: Option<String>,
    #[serde(default, alias = "holdId")]
    hold_id: Option<String>,
    #[serde(default, alias = "policyHash")]
    policy_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct IntentCommitPreimage<'a> {
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<&'a str>,
    ts: u64,
}

impl SigilClientBuilder {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            api_url: DEFAULT_API_URL.to_string(),
            agent_id: Some("agent".to_string()),
            framework: FrameworkId::AgentHooks,
            fail_mode: FailMode::Closed,
            request_timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    pub fn api_url(mut self, api_url: impl Into<String>) -> Self {
        self.api_url = api_url.into();
        self
    }

    pub fn agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    pub fn framework(mut self, framework: FrameworkId) -> Self {
        self.framework = framework;
        self
    }

    pub fn fail_mode(mut self, fail_mode: FailMode) -> Self {
        self.fail_mode = fail_mode;
        self
    }

    pub fn request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    pub fn build(self) -> Result<SigilClient, SigilClientError> {
        let api_url = self.api_url.trim();
        if api_url.is_empty() {
            return Err(SigilClientError::InvalidConfig {
                field: "api_url",
                message: "must not be empty".to_string(),
            });
        }
        reqwest::Url::parse(api_url).map_err(|err| SigilClientError::InvalidConfig {
            field: "api_url",
            message: err.to_string(),
        })?;

        if self.request_timeout.is_zero() {
            return Err(SigilClientError::InvalidConfig {
                field: "request_timeout",
                message: "must be greater than zero".to_string(),
            });
        }

        let http = reqwest::Client::builder()
            .timeout(self.request_timeout)
            .build()
            .map_err(SigilClientError::HttpClient)?;

        Ok(SigilClient {
            config: SigilConfig {
                api_key: self.api_key,
                api_url: api_url.to_string(),
                agent_id: self.agent_id,
                framework: self.framework,
                fail_mode: self.fail_mode,
                request_timeout: self.request_timeout,
            },
            http,
        })
    }
}

impl SigilClient {
    pub fn builder(api_key: impl Into<String>) -> SigilClientBuilder {
        SigilClientBuilder::new(api_key)
    }

    pub fn config(&self) -> &SigilConfig {
        &self.config
    }

    pub fn build_authorize_request(
        &self,
        intent: &SigilIntent,
    ) -> Result<String, SigilClientError> {
        let tx_commit = match intent.tx_commit.as_deref() {
            Some(value) => Some(value.to_string()),
            None => Some(generate_intent_commit(intent)?),
        };

        let request = AuthorizeRequest {
            framework: &self.config.framework,
            agent_id: intent
                .agent_id
                .as_deref()
                .or(self.config.agent_id.as_deref())
                .unwrap_or("agent"),
            tx_commit: tx_commit.as_deref(),
            chain_id: intent.chain_id,
            intent: AuthorizeIntent {
                action: &intent.action,
                command: intent.command.as_deref(),
                url: intent.url.as_deref(),
                path: intent.path.as_deref(),
                target_address: intent.to.as_deref(),
                amount: intent.amount.as_deref(),
                metadata: intent.metadata.as_ref(),
            },
        };

        let json = serde_json::to_string_pretty(&request).map_err(SigilClientError::Serialize)?;
        Ok(format!("{json}\n"))
    }

    pub async fn check_intent(
        &self,
        intent: &SigilIntent,
    ) -> Result<SigilResult, SigilClientError> {
        let body = self.build_authorize_request(intent)?;
        let mut response = match self
            .http
            .post(format!("{}/v1/authorize", self.config.api_url))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .body(body)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                return Ok(self.classify_unreachable(err.to_string()));
            }
        };

        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Ok(SigilResult {
                decision: SigilDecision::Denied,
                error_code: Some("SIGIL_AUTH_FAILURE".to_string()),
                message: Some(format!("Authentication failed ({})", response.status())),
                ..SigilResult::default()
            });
        }

        if response.status().is_server_error() {
            return Ok(
                self.classify_unreachable(format!("Sigil server error ({})", response.status()))
            );
        }

        let response_body = match read_response_body(&mut response).await {
            Ok(body) => body,
            Err(err) => return Ok(self.classify_unreachable(err)),
        };

        let data: AuthorizeResponse = match serde_json::from_slice(&response_body) {
            Ok(data) => data,
            Err(err) => return Ok(self.classify_unreachable(err.to_string())),
        };

        let policy_hash = data.policy_hash;

        match data.status.as_str() {
            "APPROVED" => Ok(SigilResult {
                decision: SigilDecision::Approved,
                policy_hash,
                ..SigilResult::default()
            }),
            "PENDING" => Ok(SigilResult {
                decision: SigilDecision::Pending,
                hold_id: data.hold_id,
                policy_hash,
                message: data.message,
                ..SigilResult::default()
            }),
            _ => Ok(SigilResult {
                decision: SigilDecision::Denied,
                error_code: Some(
                    data.error_code
                        .unwrap_or_else(|| "SIGIL_POLICY_VIOLATION".to_string()),
                ),
                message: Some(
                    data.message
                        .unwrap_or_else(|| "Action blocked by policy".to_string()),
                ),
                policy_hash,
                ..SigilResult::default()
            }),
        }
    }

    fn classify_unreachable(&self, message: String) -> SigilResult {
        match self.config.fail_mode {
            FailMode::Open => SigilResult {
                decision: SigilDecision::Approved,
                message: Some("Sigil unreachable - fail open".to_string()),
                fail_open: true,
                ..SigilResult::default()
            },
            FailMode::Closed => SigilResult {
                decision: SigilDecision::Denied,
                error_code: Some(crate::SIGIL_UNREACHABLE.to_string()),
                message: Some(message),
                ..SigilResult::default()
            },
        }
    }
}

fn generate_intent_commit(intent: &SigilIntent) -> Result<String, SigilClientError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(SigilClientError::Clock)?
        .as_secs();
    generate_intent_commit_at(intent, now)
}

fn generate_intent_commit_at(intent: &SigilIntent, now: u64) -> Result<String, SigilClientError> {
    let preimage = IntentCommitPreimage {
        action: &intent.action,
        command: intent.command.as_deref(),
        url: intent.url.as_deref(),
        path: intent.path.as_deref(),
        to: intent.to.as_deref(),
        amount: intent.amount.as_deref(),
        ts: now,
    };
    let bytes = serde_json::to_vec(&preimage).map_err(SigilClientError::Serialize)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

async fn read_response_body(response: &mut reqwest::Response) -> Result<Vec<u8>, String> {
    if let Some(content_length) = response.content_length()
        && content_length > MAX_RESPONSE_BYTES as u64
    {
        return Err(format!(
            "Sigil response exceeded {MAX_RESPONSE_BYTES} bytes"
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|err| err.to_string())? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(format!(
                "Sigil response exceeded {MAX_RESPONSE_BYTES} bytes"
            ));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::generate_intent_commit_at;
    use crate::SigilIntent;

    #[test]
    fn generated_commit_omits_absent_optional_fields() {
        let intent = SigilIntent {
            action: "bash".to_string(),
            command: Some("echo hi".to_string()),
            ..SigilIntent::default()
        };

        let commit = generate_intent_commit_at(&intent, 1_700_000_000).expect("commit");
        assert_eq!(
            commit,
            "6fd4947d41a7b08df3fede4821f93f9c92176a828b7fd9669772577a415e0f9d"
        );
    }
}
