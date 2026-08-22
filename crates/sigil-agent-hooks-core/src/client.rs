use reqwest::StatusCode;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::decision::{
    AuthorizationVerificationContext, DecisionSurface, JwksCache, legacy_authorization,
    log_decision_verification, strict_json_value, validate_canonical_origin,
};
use crate::types::{
    DecisionJwk, DecisionVerificationMode, FailMode, FrameworkId, SigilClient, SigilClientBuilder,
    SigilClientError, SigilConfig, SigilDecision, SigilIntent, SigilResult,
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
    #[serde(rename = "request_nonce")]
    request_nonce: &'a str,
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
}

struct PreparedAuthorizeRequest {
    body: String,
    tx_commit: String,
    request_nonce: String,
}

#[derive(Debug)]
enum ResponseReadError {
    Transport(String),
    Protocol(String),
}

impl ResponseReadError {
    fn into_message(self) -> String {
        match self {
            Self::Transport(message) | Self::Protocol(message) => message,
        }
    }
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
            decision_verification_mode: DecisionVerificationMode::Enforce,
            expected_policy_hash: None,
            decision_record_jwk: None,
            attestation_issuer: "sigil-core".to_string(),
            #[cfg(any(test, feature = "test-certificates"))]
            additional_root_certificate_pem: None,
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

    pub fn decision_verification_mode(mut self, mode: DecisionVerificationMode) -> Self {
        self.decision_verification_mode = mode;
        self
    }

    pub fn expected_policy_hash(mut self, policy_hash: impl Into<String>) -> Self {
        self.expected_policy_hash = Some(policy_hash.into());
        self
    }

    pub fn decision_record_jwk(mut self, jwk: DecisionJwk) -> Self {
        self.decision_record_jwk = Some(jwk);
        self
    }

    pub fn attestation_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.attestation_issuer = issuer.into();
        self
    }

    #[cfg(any(test, feature = "test-certificates"))]
    #[doc(hidden)]
    pub fn additional_root_certificate_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.additional_root_certificate_pem = Some(pem.into());
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
        let api_url = validate_canonical_origin(api_url).map_err(|_| SigilClientError::InvalidConfig {
            field: "api_url",
            message: "must be an exact HTTPS root origin without credentials, path, query, or fragment".to_string(),
        })?;

        if self.request_timeout.is_zero() {
            return Err(SigilClientError::InvalidConfig {
                field: "request_timeout",
                message: "must be greater than zero".to_string(),
            });
        }
        if self.decision_verification_mode == DecisionVerificationMode::Enforce
            && self.expected_policy_hash.is_none()
        {
            return Err(SigilClientError::InvalidConfig {
                field: "expected_policy_hash",
                message: "is required in enforce mode".to_string(),
            });
        }
        if self
            .expected_policy_hash
            .as_deref()
            .is_some_and(|value| !is_lower_hex_64(value))
        {
            return Err(SigilClientError::InvalidConfig {
                field: "expected_policy_hash",
                message: "must be exactly 64 lowercase hexadecimal characters".to_string(),
            });
        }
        let attestation_issuer = self.attestation_issuer.trim().to_string();
        if attestation_issuer.is_empty() {
            return Err(SigilClientError::InvalidConfig {
                field: "attestation_issuer",
                message: "must not be empty".to_string(),
            });
        }

        let http_builder = reqwest::Client::builder()
            .timeout(self.request_timeout)
            .redirect(reqwest::redirect::Policy::none());
        let jwks_http_builder = reqwest::Client::builder()
            .timeout(self.request_timeout)
            .redirect(reqwest::redirect::Policy::none());
        #[cfg(any(test, feature = "test-certificates"))]
        let (http_builder, jwks_http_builder) =
            if let Some(pem) = self.additional_root_certificate_pem.as_deref() {
                let certificate = reqwest::Certificate::from_pem(pem).map_err(|err| {
                    SigilClientError::InvalidConfig {
                        field: "additional_root_certificate_pem",
                        message: err.to_string(),
                    }
                })?;
                (
                    http_builder.add_root_certificate(certificate.clone()),
                    jwks_http_builder.add_root_certificate(certificate),
                )
            } else {
                (http_builder, jwks_http_builder)
            };
        let http = http_builder.build().map_err(SigilClientError::HttpClient)?;
        let jwks_http = jwks_http_builder
            .build()
            .map_err(SigilClientError::HttpClient)?;

        Ok(SigilClient {
            config: SigilConfig {
                api_key: self.api_key,
                api_url,
                agent_id: self.agent_id,
                task_id: self.task_id,
                framework: self.framework,
                fail_mode: self.fail_mode,
                request_timeout: self.request_timeout,
                decision_verification_mode: self.decision_verification_mode,
                expected_policy_hash: self.expected_policy_hash,
                decision_record_jwk: self.decision_record_jwk,
                attestation_issuer,
                #[cfg(any(test, feature = "test-certificates"))]
                additional_root_certificate_pem: self.additional_root_certificate_pem,
            },
            http,
            jwks_http,
            jwks_cache: Arc::new(JwksCache::default()),
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
        Ok(self.prepare_authorize_request_at(intent, now)?.body)
    }

    fn prepare_authorize_request_at(
        &self,
        intent: &SigilIntent,
        now: u64,
    ) -> Result<PreparedAuthorizeRequest, SigilClientError> {
        validate_intent(intent)?;
        let tx_commit = match intent.tx_commit.as_deref() {
            Some(value) => value.to_string(),
            None => generate_intent_commit_at(intent, now)?,
        };
        let request_nonce = Uuid::new_v4().to_string();
        let task_id = self.resolve_task_id(intent);

        let request = AuthorizeRequest {
            framework: &self.config.framework,
            agent_id: intent
                .agent_id
                .as_deref()
                .or(self.config.agent_id.as_deref())
                .unwrap_or("agent"),
            tx_commit: Some(tx_commit.as_str()),
            request_nonce: &request_nonce,
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
        Ok(PreparedAuthorizeRequest {
            body: format!("{json}\n"),
            tx_commit,
            request_nonce,
        })
    }

    pub async fn check_intent(
        &self,
        intent: &SigilIntent,
    ) -> Result<SigilResult, SigilClientError> {
        self.check_intent_at(intent, None).await
    }

    fn response_status_error(&self, status: StatusCode) -> Option<SigilResult> {
        if status == StatusCode::UNAUTHORIZED {
            return Some(auth_failure(status));
        }
        if status.is_success() || status == StatusCode::FORBIDDEN {
            return None;
        }
        Some(self.classify_invalid_response(format!("Sigil server returned {status}")))
    }

    fn response_body_error(&self, status: StatusCode, message: String) -> SigilResult {
        if status == StatusCode::FORBIDDEN {
            auth_failure(status)
        } else {
            self.classify_invalid_response(message)
        }
    }

    async fn decode_authorize_response(
        &self,
        mut response: reqwest::Response,
        status: StatusCode,
    ) -> Result<(serde_json::Value, AuthorizeResponse), SigilResult> {
        let response_body = read_response_body(&mut response)
            .await
            .map_err(|error| self.response_body_error(status, error.into_message()))?;
        let value = strict_json_value(&response_body, MAX_RESPONSE_BYTES).map_err(|_| {
            self.response_body_error(status, "invalid authorization JSON".to_string())
        })?;
        let data: AuthorizeResponse = serde_json::from_value(value.clone())
            .map_err(|error| self.response_body_error(status, error.to_string()))?;
        if status == StatusCode::FORBIDDEN && data.status != "DENIED" {
            return Err(auth_failure(status));
        }
        Ok((value, data))
    }

    async fn check_intent_at(
        &self,
        intent: &SigilIntent,
        timestamp_override: Option<u64>,
    ) -> Result<SigilResult, SigilClientError> {
        if self.config.decision_verification_mode == DecisionVerificationMode::Warn
            && self.config.expected_policy_hash.is_none()
        {
            log_decision_verification(
                crate::DecisionVerificationReason::PolicyBinding,
                DecisionVerificationMode::Warn,
                DecisionSurface::Authorize,
            );
        }
        let now = match timestamp_override {
            Some(now) => now,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(SigilClientError::Clock)?
                .as_secs(),
        };
        let prepared = self.prepare_authorize_request_at(intent, now)?;
        let response = match self
            .http
            .post(format!("{}/v1/authorize", self.config.api_url))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .body(prepared.body)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                return Ok(self.classify_unreachable(err.to_string()));
            }
        };

        let response_status = response.status();
        if let Some(error) = self.response_status_error(response_status) {
            return Ok(error);
        }

        let (value, data) = match self
            .decode_authorize_response(response, response_status)
            .await
        {
            Ok(decoded) => decoded,
            Err(error) => return Ok(error),
        };
        let verification = self
            .verify_authorization_response(
                &value,
                &AuthorizationVerificationContext {
                    tx_commit: prepared.tx_commit,
                    request_nonce: prepared.request_nonce,
                    surface: DecisionSurface::Authorize,
                    execution: true,
                    now_unix_seconds: timestamp_override.map(|value| value as i64),
                },
            )
            .await;
        if let Some(reason) = verification.reason {
            log_decision_verification(
                reason,
                self.config.decision_verification_mode,
                DecisionSurface::Authorize,
            );
        }
        let verified_policy_hash = verification.verified_policy_hash().map(str::to_string);
        match verification.decision {
            SigilDecision::Allowed => Ok(SigilResult {
                decision: SigilDecision::Allowed,
                policy_hash: verified_policy_hash,
                authorization: verification.authorization,
                ..SigilResult::default()
            }),
            SigilDecision::Pending => Ok(SigilResult {
                decision: SigilDecision::Pending,
                hold_id: data.hold_id,
                policy_hash: verified_policy_hash,
                message: data.message,
                ..SigilResult::default()
            }),
            SigilDecision::Denied => {
                let verification_failed = verification.reason.is_some_and(|reason| {
                    data.status != "DENIED"
                        || !matches!(reason, crate::DecisionVerificationReason::RecordMissing)
                });
                Ok(SigilResult {
                    decision: SigilDecision::Denied,
                    error_code: Some(if verification_failed {
                        "SIGIL_DECISION_VERIFICATION_FAILED".to_string()
                    } else {
                        data.error_code
                            .unwrap_or_else(|| "SIGIL_POLICY_VIOLATION".to_string())
                    }),
                    message: Some(if verification_failed {
                        format!(
                            "Authorization response verification failed ({})",
                            verification
                                .reason
                                .map(|reason| reason.as_str())
                                .unwrap_or("malformed")
                        )
                    } else {
                        data.message
                            .unwrap_or_else(|| "Action blocked by policy".to_string())
                    }),
                    policy_hash: verified_policy_hash,
                    ..SigilResult::default()
                })
            }
        }
    }

    fn classify_unreachable(&self, message: String) -> SigilResult {
        match self.config.fail_mode {
            FailMode::Open => SigilResult {
                decision: SigilDecision::Allowed,
                authorization: Some(legacy_authorization()),
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

    fn classify_invalid_response(&self, message: String) -> SigilResult {
        SigilResult {
            decision: SigilDecision::Denied,
            error_code: Some("SIGIL_DECISION_VERIFICATION_FAILED".to_string()),
            message: Some(format!(
                "Authorization response verification failed ({message})"
            )),
            ..SigilResult::default()
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

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn auth_failure(status: StatusCode) -> SigilResult {
    SigilResult {
        decision: SigilDecision::Denied,
        error_code: Some("SIGIL_AUTH_FAILURE".to_string()),
        message: Some(format!("Authentication failed ({status})")),
        ..SigilResult::default()
    }
}

async fn read_response_body(
    response: &mut reqwest::Response,
) -> Result<Vec<u8>, ResponseReadError> {
    if let Some(content_length) = response.content_length()
        && content_length > MAX_RESPONSE_BYTES as u64
    {
        return Err(ResponseReadError::Protocol(format!(
            "Sigil response exceeded {MAX_RESPONSE_BYTES} bytes"
        )));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| ResponseReadError::Transport(err.to_string()))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(ResponseReadError::Protocol(format!(
                "Sigil response exceeded {MAX_RESPONSE_BYTES} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::generate_intent_commit_at;
    use crate::{DecisionVerificationMode, FrameworkId, HttpMethod, SigilClient, SigilIntent};
    use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
    use std::sync::{Arc, Mutex};
    use tokio::{net::TcpListener, sync::oneshot};

    mod support {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/mod.rs"));
    }
    use support::{TEST_CERT_PEM, TestTlsListener};

    struct AxumTlsListener(TestTlsListener);

    impl axum::serve::Listener for AxumTlsListener {
        type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
        type Addr = std::net::SocketAddr;

        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            self.0.accept().await.expect("TLS test accept")
        }

        fn local_addr(&self) -> std::io::Result<Self::Addr> {
            self.0.local_addr()
        }
    }

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
        let listener = AxumTlsListener(TestTlsListener::new(listener));
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });

        TestServer {
            base_url: format!("https://localhost:{}", addr.port()),
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
            .decision_verification_mode(DecisionVerificationMode::Warn)
            .api_url(server.base_url.clone())
            .additional_root_certificate_pem(TEST_CERT_PEM)
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
            .decision_verification_mode(DecisionVerificationMode::Warn)
            .api_url(server.base_url.clone())
            .additional_root_certificate_pem(TEST_CERT_PEM)
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
            .decision_verification_mode(DecisionVerificationMode::Warn)
            .api_url(server.base_url.clone())
            .additional_root_certificate_pem(TEST_CERT_PEM)
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
    fn builder_stores_the_normalized_attestation_issuer() {
        let client = SigilClient::builder("sk_fixture")
            .decision_verification_mode(DecisionVerificationMode::Warn)
            .attestation_issuer("  sigil-core  ")
            .build()
            .expect("client should build");

        assert_eq!(client.config.attestation_issuer, "sigil-core");
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
