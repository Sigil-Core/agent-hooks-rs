use axum::{
    Router,
    body::Bytes,
    extract::{Json, State},
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use sigil_agent_hooks_core::{
    DecisionJwk, DecisionVerificationMode, FailMode, FrameworkId, SigilClient, SigilDecision,
    SigilIntent, SigilResult, authorization_permits_execution, verified_authorization,
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{sleep, timeout},
};

mod support;
use support::{TEST_CERT_PEM, TestTlsListener};

struct AxumTlsListener(TestTlsListener);

impl axum::serve::Listener for AxumTlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        self.0.accept().await.expect("TLS test accept")
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

#[derive(Clone)]
struct MockServerState {
    response: MockResponse,
    captures: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone)]
enum MockBody {
    Json(serde_json::Value),
    Text(String),
}

#[derive(Clone)]
struct MockResponse {
    status: StatusCode,
    body: MockBody,
    delay: Duration,
}

struct RunningServer {
    base_url: String,
    captures: Arc<Mutex<Vec<String>>>,
    shutdown: Option<oneshot::Sender<()>>,
}

#[derive(Clone)]
struct SignedDeniedState {
    origin: String,
    signing_key: SigningKey,
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn authorize_handler(State(state): State<MockServerState>, body: Bytes) -> impl IntoResponse {
    let payload = String::from_utf8(body.to_vec()).expect("utf8 payload");
    state.captures.lock().expect("capture lock").push(payload);
    if !state.response.delay.is_zero() {
        sleep(state.response.delay).await;
    }

    match &state.response.body {
        MockBody::Json(body) => (state.response.status, Json(body.clone())).into_response(),
        MockBody::Text(body) => {
            let mut response = (state.response.status, body.clone()).into_response();
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/html"),
            );
            response
        }
    }
}

fn first_capture_json(server: &RunningServer) -> serde_json::Value {
    let captured = server.captures.lock().expect("capture lock");
    let body = captured.first().expect("captured body");
    serde_json::from_str(body).expect("captured json")
}

async fn spawn_server(response: MockResponse) -> RunningServer {
    let captures = Arc::new(Mutex::new(Vec::new()));
    let state = MockServerState {
        response,
        captures: Arc::clone(&captures),
    };
    let app = Router::new()
        .route("/v1/authorize", post(authorize_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    let listener = AxumTlsListener(TestTlsListener::new(listener));
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });

    RunningServer {
        base_url: format!("https://localhost:{}", addr.port()),
        captures,
        shutdown: Some(tx),
    }
}

async fn spawn_truncated_body_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("local addr");
    let mut listener = TestTlsListener::new(listener);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("TLS test accept");
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n{\"status\":\"APPROVED\"}",
            )
            .await
            .expect("truncated response prefix");
        stream.shutdown().await.expect("close truncated response");
    });
    format!("https://localhost:{}", addr.port())
}

#[tokio::test]
async fn tls_test_listener_reports_the_final_handshake_failure() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("local addr");
    let mut listener = TestTlsListener::new(listener);

    for _ in 0..3 {
        let mut stream = TcpStream::connect(addr).await.expect("plain TCP connect");
        stream
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .expect("invalid TLS bytes");
        stream.shutdown().await.expect("plain TCP shutdown");
    }

    let error = timeout(Duration::from_secs(1), listener.accept())
        .await
        .expect("bounded TLS retries should finish")
        .expect_err("invalid TLS handshakes should be reported");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

async fn signed_denied_handler(
    State(state): State<SignedDeniedState>,
    body: Bytes,
) -> impl IntoResponse {
    let request: serde_json::Value = serde_json::from_slice(&body).expect("authorize request");
    let tx_commit = request["txCommit"].as_str().expect("txCommit");
    let request_nonce = request["request_nonce"].as_str().expect("request nonce");
    let policy_hash = "b".repeat(64);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time")
        .as_secs() as i64;
    let header = serde_json::json!({
        "alg": "EdDSA",
        "kid": "test-denied-key",
        "typ": "sof-decision+jws"
    });
    let claims = serde_json::json!({
        "iss": state.origin,
        "aud": state.origin,
        "surface": "authorize",
        "decision": "DENIED",
        "intentHash": format!("{:x}", Sha256::digest(tx_commit.as_bytes())),
        "policyHash": policy_hash,
        "requestNonce": request_nonce,
        "iat": now,
        "exp": now + 60
    });
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = state.signing_key.sign(signing_input.as_bytes());
    let record = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );

    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "status": "DENIED",
            "error_code": "SIGIL_SIGNED_POLICY_BLOCKED",
            "message": "signed denial",
            "policyHash": policy_hash,
            "decision_record": record
        })),
    )
}

async fn spawn_signed_denied_server() -> (RunningServer, DecisionJwk) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("local addr");
    let origin = format!("https://localhost:{}", addr.port());
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let jwk = DecisionJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        kid: "test-denied-key".to_string(),
        x: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        r#use: Some("sig".to_string()),
        alg: Some("EdDSA".to_string()),
        key_ops: Some(vec!["verify".to_string()]),
    };
    let app = Router::new()
        .route("/v1/authorize", post(signed_denied_handler))
        .with_state(SignedDeniedState {
            origin: origin.clone(),
            signing_key,
        });
    let listener = AxumTlsListener(TestTlsListener::new(listener));
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });

    (
        RunningServer {
            base_url: origin,
            captures: Arc::new(Mutex::new(Vec::new())),
            shutdown: Some(tx),
        },
        jwk,
    )
}

fn test_client_builder(api_key: impl Into<String>) -> sigil_agent_hooks_core::SigilClientBuilder {
    SigilClient::builder(api_key)
        .decision_verification_mode(DecisionVerificationMode::Warn)
        .additional_root_certificate_pem(TEST_CERT_PEM)
}

fn fixture_bash_intent() -> SigilIntent {
    SigilIntent {
        action: "bash".to_string(),
        command: Some("echo hello".to_string()),
        tx_commit: Some(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        ..SigilIntent::default()
    }
}

#[tokio::test]
async fn unsigned_legacy_response_does_not_expose_an_unverified_policy_hash() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({
            "status": "APPROVED",
            "policyHash": "policy_hash_1",
        })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .agent_id("fixture-agent")
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Allowed, "{result:?}");
    assert_eq!(result.policy_hash, None);
}

#[tokio::test]
async fn omitted_verification_mode_denies_an_unsigned_allowed_response() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({ "status": "ALLOWED" })),
        delay: Duration::ZERO,
    })
    .await;
    let client = SigilClient::builder("sk_fixture")
        .api_url(server.base_url.clone())
        .expected_policy_hash("a".repeat(64))
        .additional_root_certificate_pem(TEST_CERT_PEM)
        .build()
        .expect("default enforce client should build with a policy pin");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should fail closed without a signed record");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(
        result.message.as_deref(),
        Some("Authorization response verification failed (record_missing)")
    );
    assert!(!authorization_permits_execution(&result));
}

#[tokio::test]
async fn denied_response_round_trips_error_code() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({
            "status": "DENIED",
            "policyHash": "unverified_denied_policy_hash",
            "error_code": "SIGIL_BASH_BLOCKED",
            "message": "blocked",
        })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(result.error_code.as_deref(), Some("SIGIL_BASH_BLOCKED"));
    assert_eq!(result.policy_hash, None);
}

#[tokio::test]
async fn pending_response_round_trips_hold_id() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({
            "status": "PENDING",
            "holdId": "hold_123",
            "policyHash": "unverified_pending_policy_hash",
            "message": "approval required",
        })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Pending);
    assert_eq!(result.hold_id.as_deref(), Some("hold_123"));
    assert_eq!(result.policy_hash, None);
}

#[tokio::test]
async fn auth_failures_are_not_classified_as_unreachable() {
    let server = spawn_server(MockResponse {
        status: StatusCode::UNAUTHORIZED,
        body: MockBody::Json(serde_json::json!({ "status": "DENIED" })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(result.error_code.as_deref(), Some("SIGIL_AUTH_FAILURE"));
}

#[tokio::test]
async fn valid_forbidden_denial_round_trips_policy_result() {
    let server = spawn_server(MockResponse {
        status: StatusCode::FORBIDDEN,
        body: MockBody::Json(serde_json::json!({
            "status": "DENIED",
            "error_code": "SIGIL_POLICY_BLOCKED",
            "message": "blocked by policy"
        })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(result.error_code.as_deref(), Some("SIGIL_POLICY_BLOCKED"));
    assert_eq!(result.message.as_deref(), Some("blocked by policy"));
}

#[tokio::test]
async fn signed_forbidden_denial_verifies_before_returning_policy_result() {
    let (server, jwk) = spawn_signed_denied_server().await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .decision_verification_mode(DecisionVerificationMode::Enforce)
        .expected_policy_hash("b".repeat(64))
        .decision_record_jwk(jwk)
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(
        result.error_code.as_deref(),
        Some("SIGIL_SIGNED_POLICY_BLOCKED")
    );
    assert_eq!(result.message.as_deref(), Some("signed denial"));
    assert!(!authorization_permits_execution(&result));
}

#[tokio::test]
async fn forbidden_non_denied_body_is_auth_failure_even_in_open_mode() {
    let server = spawn_server(MockResponse {
        status: StatusCode::FORBIDDEN,
        body: MockBody::Json(serde_json::json!({ "status": "APPROVED" })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .fail_mode(FailMode::Open)
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(result.error_code.as_deref(), Some("SIGIL_AUTH_FAILURE"));
    assert!(!result.fail_open);
    assert!(!authorization_permits_execution(&result));
}

#[tokio::test]
async fn malformed_forbidden_body_is_auth_failure() {
    let server = spawn_server(MockResponse {
        status: StatusCode::FORBIDDEN,
        body: MockBody::Text("not-json".to_string()),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(result.error_code.as_deref(), Some("SIGIL_AUTH_FAILURE"));
}

#[tokio::test]
async fn forbidden_denial_with_invalid_record_runs_verification() {
    let server = spawn_server(MockResponse {
        status: StatusCode::FORBIDDEN,
        body: MockBody::Json(serde_json::json!({
            "status": "DENIED",
            "error_code": "SIGIL_POLICY_BLOCKED",
            "decision_record": "not-a-jws"
        })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(
        result.error_code.as_deref(),
        Some("SIGIL_DECISION_VERIFICATION_FAILED")
    );
}

#[tokio::test]
async fn server_errors_are_invalid_responses_in_closed_mode() {
    let server = spawn_server(MockResponse {
        status: StatusCode::BAD_GATEWAY,
        body: MockBody::Json(serde_json::json!({ "status": "DENIED" })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .fail_mode(FailMode::Closed)
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(
        result.error_code.as_deref(),
        Some("SIGIL_DECISION_VERIFICATION_FAILED")
    );
}

#[tokio::test]
async fn server_errors_cannot_fail_open() {
    let server = spawn_server(MockResponse {
        status: StatusCode::SERVICE_UNAVAILABLE,
        body: MockBody::Json(serde_json::json!({ "status": "DENIED" })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .fail_mode(FailMode::Open)
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(
        result.error_code.as_deref(),
        Some("SIGIL_DECISION_VERIFICATION_FAILED")
    );
    assert!(!result.fail_open);
    assert!(!authorization_permits_execution(&result));
}

#[tokio::test]
async fn reached_rate_limit_cannot_fail_open_even_with_approved_body() {
    let server = spawn_server(MockResponse {
        status: StatusCode::TOO_MANY_REQUESTS,
        body: MockBody::Json(serde_json::json!({ "status": "APPROVED" })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .fail_mode(FailMode::Open)
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(
        result.error_code.as_deref(),
        Some("SIGIL_DECISION_VERIFICATION_FAILED")
    );
    assert!(!result.fail_open);
    assert!(!authorization_permits_execution(&result));
}

#[tokio::test]
async fn non_json_response_is_invalid_in_closed_mode() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Text("<html>bad gateway</html>".to_string()),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .fail_mode(FailMode::Closed)
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(
        result.error_code.as_deref(),
        Some("SIGIL_DECISION_VERIFICATION_FAILED")
    );
}

#[tokio::test]
async fn timeout_is_unreachable_in_closed_mode() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({ "status": "APPROVED" })),
        delay: Duration::from_millis(100),
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .request_timeout(Duration::from_millis(25))
        .fail_mode(FailMode::Closed)
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(result.error_code.as_deref(), Some("SIGIL_UNREACHABLE"));
}

#[tokio::test]
async fn default_enforce_preserves_explicit_fail_open_for_unreachable() {
    let client = SigilClient::builder("sk_fixture")
        .api_url("https://127.0.0.1:9")
        .fail_mode(FailMode::Open)
        .request_timeout(Duration::from_millis(25))
        .expected_policy_hash("a".repeat(64))
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Allowed);
    assert!(result.fail_open);
    assert!(authorization_permits_execution(&result));
    assert!(verified_authorization(&result).is_none());
}

#[tokio::test]
async fn reached_malformed_response_cannot_fail_open_in_default_enforce_mode() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Text("not-json".to_string()),
        delay: Duration::ZERO,
    })
    .await;
    let client = SigilClient::builder("sk_fixture")
        .api_url(server.base_url.clone())
        .fail_mode(FailMode::Open)
        .expected_policy_hash("a".repeat(64))
        .additional_root_certificate_pem(TEST_CERT_PEM)
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(
        result.error_code.as_deref(),
        Some("SIGIL_DECISION_VERIFICATION_FAILED")
    );
    assert!(!result.fail_open);
    assert!(!authorization_permits_execution(&result));
    assert!(verified_authorization(&result).is_none());
}

#[tokio::test]
async fn custom_framework_serializes_as_a_bare_string() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({ "status": "APPROVED" })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .framework(FrameworkId::Custom("custom-host".to_string()))
        .build()
        .expect("client should build");

    let _ = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    let body = first_capture_json(&server);
    assert_eq!(body["framework"], "custom-host");
}

#[tokio::test]
async fn intent_agent_id_overrides_config_agent_id() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({ "status": "APPROVED" })),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .agent_id("config-agent")
        .build()
        .expect("client should build");

    let intent = SigilIntent {
        action: "bash".to_string(),
        agent_id: Some("intent-agent".to_string()),
        command: Some("echo hi".to_string()),
        tx_commit: Some(
            "4444444444444444444444444444444444444444444444444444444444444444".to_string(),
        ),
        ..SigilIntent::default()
    };

    let _ = client
        .check_intent(&intent)
        .await
        .expect("check should succeed");

    let body = first_capture_json(&server);
    assert_eq!(body["agentId"], "intent-agent");
}

#[tokio::test]
async fn oversized_json_response_is_invalid() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Text(format!(
            "{{\"status\":\"APPROVED\",\"message\":\"{}\"}}",
            "x".repeat(70_000)
        )),
        delay: Duration::ZERO,
    })
    .await;
    let client = test_client_builder("sk_fixture")
        .api_url(server.base_url.clone())
        .fail_mode(FailMode::Open)
        .decision_verification_mode(DecisionVerificationMode::Enforce)
        .expected_policy_hash("a".repeat(64))
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(
        result.error_code.as_deref(),
        Some("SIGIL_DECISION_VERIFICATION_FAILED")
    );
    assert!(!result.fail_open);
    assert!(!authorization_permits_execution(&result));
    assert!(
        result
            .message
            .as_deref()
            .expect("message")
            .contains("exceeded 65536 bytes")
    );
}

#[tokio::test]
async fn body_protocol_read_error_cannot_fail_open() {
    let client = test_client_builder("sk_fixture")
        .api_url(spawn_truncated_body_server().await)
        .fail_mode(FailMode::Open)
        .decision_verification_mode(DecisionVerificationMode::Enforce)
        .expected_policy_hash("a".repeat(64))
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(
        result.error_code.as_deref(),
        Some("SIGIL_DECISION_VERIFICATION_FAILED")
    );
    assert!(!result.fail_open);
    assert!(!authorization_permits_execution(&result));
}

#[test]
fn builder_rejects_invalid_api_url() {
    for invalid in [
        "not a url",
        "http://sign.sigilcore.com",
        "https://user@sign.sigilcore.com",
        "https://sign.sigilcore.com/v1",
        "https://sign.sigilcore.com?query=yes",
        "https://sign.sigilcore.com#fragment",
    ] {
        let err = test_client_builder("sk_fixture")
            .api_url(invalid)
            .build()
            .expect_err("invalid URL should fail");

        assert!(err.to_string().contains("invalid api_url"), "{invalid}");
    }
}

#[test]
fn builder_accepts_and_canonicalizes_exact_https_root_origin() {
    let client = test_client_builder("sk_fixture")
        .api_url("https://sign.sigilcore.com:443/")
        .build()
        .expect("exact HTTPS root should build");

    assert_eq!(client.config().api_url, "https://sign.sigilcore.com");
}

#[test]
fn builder_rejects_zero_timeout() {
    let err = test_client_builder("sk_fixture")
        .request_timeout(Duration::ZERO)
        .build()
        .expect_err("zero timeout should fail");

    assert!(err.to_string().contains("request_timeout"));
}

#[test]
fn enforce_mode_requires_a_policy_pin_at_build_time() {
    let err = test_client_builder("sk_fixture")
        .decision_verification_mode(DecisionVerificationMode::Enforce)
        .build()
        .expect_err("enforce without policy pin should fail");

    assert!(err.to_string().contains("expected_policy_hash"));
}

#[test]
fn default_enforce_mode_requires_a_policy_pin_at_build_time() {
    let err = SigilClient::builder("sk_fixture")
        .build()
        .expect_err("default enforce mode without a policy pin should fail");

    assert!(err.to_string().contains("expected_policy_hash"));
}

#[test]
fn default_verification_mode_is_enforce() {
    assert_eq!(
        DecisionVerificationMode::default(),
        DecisionVerificationMode::Enforce
    );
    let client = SigilClient::builder("sk_fixture")
        .expected_policy_hash("a".repeat(64))
        .build()
        .expect("default enforce client should build with a policy pin");

    assert_eq!(
        client.config().decision_verification_mode,
        DecisionVerificationMode::Enforce
    );
}

#[test]
fn policy_pin_must_be_exact_lowercase_sha256_hex_in_every_mode() {
    for invalid in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
        let err = test_client_builder("sk_fixture")
            .expected_policy_hash(invalid)
            .build()
            .expect_err("invalid policy pin should fail");
        assert!(err.to_string().contains("expected_policy_hash"));
    }

    test_client_builder("sk_fixture")
        .expected_policy_hash("0123456789abcdef".repeat(4))
        .build()
        .expect("lowercase SHA-256 pin should build");
}

#[test]
fn a_raw_allowed_enum_cannot_counterfeit_execution_authority() {
    let forged = SigilResult {
        decision: SigilDecision::Allowed,
        ..SigilResult::default()
    };

    assert_eq!(forged.decision, SigilDecision::Allowed);
    assert!(!authorization_permits_execution(&forged));
}
