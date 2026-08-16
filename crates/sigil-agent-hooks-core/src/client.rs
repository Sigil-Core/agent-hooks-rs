use reqwest::StatusCode;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::types::{
    FailMode, FrameworkId, SigilClient, SigilClientBuilder, SigilClientError, SigilConfig,
    SigilDecision, SigilIntent, SigilResult,
};

const DEFAULT_API_URL: &str = "https://sign.sigilcore.com";
const DEFAULT_TIMEOUT_SECS: u64 = 5;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
static DEFAULT_TASK_ID: OnceLock<String> = OnceLock::new();

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
    arguments: Option<&'a serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a crate::HttpMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_address: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    calldata: Option<&'a str>,
    #[serde(rename = "task_id", skip_serializing_if = "Option::is_none")]
    task_id: Option<&'a str>,
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
    arguments: Option<&'a serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a crate::HttpMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    calldata: Option<&'a str>,
    ts: u64,
}

impl SigilClientBuilder {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            api_url: DEFAULT_API_URL.to_string(),
            agent_id: Some("agent".to_string()),
            task_id: None,
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

    pub fn task_id(mut self, task_id: impl Into<String>) -> Self {
        self.task_id = Some(task_id.into());
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
                task_id: self.task_id,
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

    pub fn resolve_task_id(&self, intent: &SigilIntent) -> String {
        intent
            .task_id
            .clone()
            .or_else(|| self.config.task_id.clone())
            .unwrap_or_else(default_task_id)
    }

    pub fn build_authorize_request(
        &self,
        intent: &SigilIntent,
    ) -> Result<String, SigilClientError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(SigilClientError::Clock)?
            .as_secs();
        self.build_authorize_request_at(intent, now)
    }

    fn build_authorize_request_at(
        &self,
        intent: &SigilIntent,
        now: u64,
    ) -> Result<String, SigilClientError> {
        validate_intent(intent)?;
        let tx_commit = match intent.tx_commit.as_deref() {
            Some(value) => Some(value.to_string()),
            None => Some(generate_intent_commit_at(intent, now)?),
        };
        let task_id = self.resolve_task_id(intent);

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
                arguments: intent
                    .arguments
                    .as_ref()
                    .and_then(serde_json::Value::as_object),
                command: intent.command.as_deref(),
                url: intent.url.as_deref(),
                method: (intent.action == "http")
                    .then_some(intent.method.as_ref())
                    .flatten(),
                path: intent.path.as_deref(),
                target_address: intent.to.as_deref(),
                amount: intent.amount.as_deref(),
                calldata: intent.calldata.as_deref(),
                task_id: Some(task_id.as_str()),
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
        self.check_intent_at(intent, None).await
    }

    async fn check_intent_at(
        &self,
        intent: &SigilIntent,
        timestamp_override: Option<u64>,
    ) -> Result<SigilResult, SigilClientError> {
        let body = match timestamp_override {
            Some(now) => self.build_authorize_request_at(intent, now)?,
            None => self.build_authorize_request(intent)?,
        };
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

fn default_task_id() -> String {
    DEFAULT_TASK_ID
        .get_or_init(|| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default();
            let pid = std::process::id();
            let digest = Sha256::digest(format!("{pid}:{now}").as_bytes());
            format!("rust-task-{}", &format!("{digest:x}")[..16])
        })
        .clone()
}

fn generate_intent_commit_at(intent: &SigilIntent, now: u64) -> Result<String, SigilClientError> {
    validate_intent(intent)?;
    let preimage = IntentCommitPreimage {
        action: &intent.action,
        arguments: intent
            .arguments
            .as_ref()
            .and_then(serde_json::Value::as_object),
        command: intent.command.as_deref(),
        url: intent.url.as_deref(),
        method: (intent.action == "http")
            .then_some(intent.method.as_ref())
            .flatten(),
        path: intent.path.as_deref(),
        to: intent.to.as_deref(),
        amount: intent.amount.as_deref(),
        calldata: intent.calldata.as_deref(),
        ts: now,
    };
    let bytes = serde_json::to_vec(&preimage).map_err(SigilClientError::Serialize)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

fn validate_intent(intent: &SigilIntent) -> Result<(), SigilClientError> {
    if intent.action.is_empty() {
        return Err(SigilClientError::InvalidConfig {
            field: "intent.action",
            message: "must be a non-empty string".to_string(),
        });
    }
    if intent
        .chain_id
        .is_some_and(|value| value > 9_007_199_254_740_991)
    {
        return Err(SigilClientError::InvalidConfig {
            field: "intent.chain_id",
            message: "must be within the shared JavaScript safe-integer domain".to_string(),
        });
    }
    if intent
        .arguments
        .as_ref()
        .is_some_and(|value| !value.is_object())
    {
        return Err(SigilClientError::InvalidConfig {
            field: "intent.arguments",
            message: "must be a JSON object when present".to_string(),
        });
    }
    if intent
        .metadata
        .as_ref()
        .is_some_and(|value| !value.is_object())
    {
        return Err(SigilClientError::InvalidConfig {
            field: "intent.metadata",
            message: "must be a JSON object when present".to_string(),
        });
    }
    Ok(())
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
    use crate::{FrameworkId, HttpMethod, SigilClient, SigilIntent};
    use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
    use std::sync::{Arc, Mutex};
    use tokio::{net::TcpListener, sync::oneshot};

    #[derive(Clone)]
    struct MockState {
        captures: Arc<Mutex<Vec<String>>>,
    }

    struct TestServer {
        base_url: String,
        captures: Arc<Mutex<Vec<String>>>,
        shutdown: Option<oneshot::Sender<()>>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
        }
    }

    async fn authorize(State(state): State<MockState>, body: Bytes) -> (StatusCode, &'static str) {
        let payload = String::from_utf8(body.to_vec()).expect("utf8 body");
        state.captures.lock().expect("capture lock").push(payload);
        (StatusCode::OK, "{\"status\":\"APPROVED\"}")
    }

    async fn spawn() -> TestServer {
        let captures = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            captures: Arc::clone(&captures),
        };
        let app = Router::new()
            .route("/v1/authorize", post(authorize))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });

        TestServer {
            base_url: format!("http://{addr}"),
            captures,
            shutdown: Some(tx),
        }
    }

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

    #[test]
    fn generated_commit_binds_arguments() {
        let first = SigilIntent {
            action: "custom".to_string(),
            arguments: Some(serde_json::json!({"query": "first"})),
            ..SigilIntent::default()
        };
        let second = SigilIntent {
            arguments: Some(serde_json::json!({"query": "second"})),
            ..first.clone()
        };

        assert_ne!(
            generate_intent_commit_at(&first, 1_700_000_000).expect("first commit"),
            generate_intent_commit_at(&second, 1_700_000_000).expect("second commit")
        );
    }

    #[tokio::test]
    async fn auto_generated_commit_matches_wire_fixture_with_pinned_timestamp() {
        let server = spawn().await;
        let client = SigilClient::builder("sk_fixture")
            .api_url(server.base_url.clone())
            .agent_id("config-agent")
            .framework(FrameworkId::AgentHooks)
            .build()
            .expect("client should build");

        let intent = SigilIntent {
            action: "bash".to_string(),
            agent_id: Some("intent-agent".to_string()),
            command: Some("echo hi".to_string()),
            ..SigilIntent::default()
        };

        let _ = client
            .check_intent_at(&intent, Some(1_700_000_000))
            .await
            .expect("request should succeed");

        let captured = server.captures.lock().expect("capture lock");
        let body = captured.first().expect("captured body");
        let body: serde_json::Value = serde_json::from_str(body).expect("json body");
        assert_eq!(body["framework"], "agent-hooks");
        assert_eq!(body["agentId"], "intent-agent");
        assert_eq!(
            body["txCommit"],
            "6fd4947d41a7b08df3fede4821f93f9c92176a828b7fd9669772577a415e0f9d"
        );
        assert_eq!(body["intent"]["action"], "bash");
        assert_eq!(body["intent"]["command"], "echo hi");
        assert!(
            body["intent"]["task_id"]
                .as_str()
                .is_some_and(|value| value.starts_with("rust-task-"))
        );
    }

    #[test]
    fn generated_commit_includes_action_gated_method_and_calldata() {
        let intent = SigilIntent {
            action: "http".to_string(),
            url: Some("https://example.test".to_string()),
            method: Some(HttpMethod::Post),
            calldata: Some("0xdeadbeef".to_string()),
            ..SigilIntent::default()
        };
        assert_eq!(
            generate_intent_commit_at(&intent, 1_700_000_000).expect("commit"),
            "06a913719e8674cd932d5b9e89592950ce6b8f728d4ac2a9494f22eedb98e0fa"
        );
    }

    #[tokio::test]
    async fn intent_bridge_fields_match_the_frozen_wire_contract() {
        let server = spawn().await;
        let client = SigilClient::builder("sk_fixture")
            .api_url(server.base_url.clone())
            .agent_id("fixture-agent")
            .task_id("fixture-task")
            .framework(FrameworkId::AgentHooks)
            .build()
            .expect("client should build");
        let intent = SigilIntent {
            action: "http".to_string(),
            arguments: Some(serde_json::json!({"query": "status"})),
            url: Some("https://example.test".to_string()),
            method: Some(HttpMethod::Delete),
            calldata: Some("0xdeadbeef".to_string()),
            tx_commit: Some("1".repeat(64)),
            ..SigilIntent::default()
        };

        client
            .check_intent(&intent)
            .await
            .expect("request should succeed");
        let body: serde_json::Value = serde_json::from_str(
            server
                .captures
                .lock()
                .expect("capture lock")
                .first()
                .expect("captured body"),
        )
        .expect("JSON body");
        assert_eq!(
            body["intent"]["arguments"],
            serde_json::json!({"query": "status"})
        );
        assert_eq!(body["intent"]["method"], "DELETE");
        assert_eq!(body["intent"]["calldata"], "0xdeadbeef");
    }

    #[tokio::test]
    async fn method_is_absent_for_non_http_actions() {
        let server = spawn().await;
        let client = SigilClient::builder("sk_fixture")
            .api_url(server.base_url.clone())
            .task_id("fixture-task")
            .build()
            .expect("client should build");
        let intent = SigilIntent {
            action: "web_fetch".to_string(),
            method: Some(HttpMethod::Get),
            tx_commit: Some("2".repeat(64)),
            ..SigilIntent::default()
        };

        client
            .check_intent(&intent)
            .await
            .expect("request should succeed");
        let body: serde_json::Value = serde_json::from_str(
            server
                .captures
                .lock()
                .expect("capture lock")
                .first()
                .expect("captured body"),
        )
        .expect("JSON body");
        assert!(body["intent"].get("method").is_none());
    }

    #[test]
    fn all_frozen_http_methods_are_closed_uppercase_values() {
        for (method, expected) in [
            (HttpMethod::Get, "\"GET\""),
            (HttpMethod::Head, "\"HEAD\""),
            (HttpMethod::Options, "\"OPTIONS\""),
            (HttpMethod::Post, "\"POST\""),
            (HttpMethod::Put, "\"PUT\""),
            (HttpMethod::Patch, "\"PATCH\""),
            (HttpMethod::Delete, "\"DELETE\""),
        ] {
            assert_eq!(
                serde_json::to_string(&method).expect("method JSON"),
                expected
            );
        }
        assert!(serde_json::from_str::<HttpMethod>("\"get\"").is_err());
        assert!(serde_json::from_str::<HttpMethod>("\"TRACE\"").is_err());
    }

    #[test]
    fn invalid_shared_intent_shapes_are_rejected_before_serialization() {
        for intent in [
            SigilIntent::default(),
            SigilIntent {
                action: "custom".to_string(),
                arguments: Some(serde_json::json!("not an object")),
                ..SigilIntent::default()
            },
            SigilIntent {
                action: "custom".to_string(),
                metadata: Some(serde_json::json!([])),
                ..SigilIntent::default()
            },
            SigilIntent {
                action: "custom".to_string(),
                chain_id: Some(9_007_199_254_740_992),
                ..SigilIntent::default()
            },
        ] {
            assert!(generate_intent_commit_at(&intent, 1_700_000_000).is_err());
        }
    }
}
