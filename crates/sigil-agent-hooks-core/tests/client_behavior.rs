use axum::{
    Router,
    body::Bytes,
    extract::{Json, State},
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    routing::post,
};
use sigil_agent_hooks_core::{
    FailMode, FrameworkId, SIGIL_UNREACHABLE, SigilClient, SigilDecision, SigilIntent,
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, sync::oneshot, time::sleep};

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
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });

    RunningServer {
        base_url: format!("http://{addr}"),
        captures,
        shutdown: Some(tx),
    }
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
async fn approved_response_preserves_policy_hash() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({
            "status": "APPROVED",
            "policyHash": "policy_hash_1",
        })),
        delay: Duration::ZERO,
    })
    .await;
    let client = SigilClient::builder("sk_fixture")
        .api_url(server.base_url.clone())
        .agent_id("fixture-agent")
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Approved);
    assert_eq!(result.policy_hash.as_deref(), Some("policy_hash_1"));
}

#[tokio::test]
async fn denied_response_round_trips_error_code() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({
            "status": "DENIED",
            "error_code": "SIGIL_BASH_BLOCKED",
            "message": "blocked",
        })),
        delay: Duration::ZERO,
    })
    .await;
    let client = SigilClient::builder("sk_fixture")
        .api_url(server.base_url.clone())
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(result.error_code.as_deref(), Some("SIGIL_BASH_BLOCKED"));
}

#[tokio::test]
async fn pending_response_round_trips_hold_id() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({
            "status": "PENDING",
            "holdId": "hold_123",
            "message": "approval required",
        })),
        delay: Duration::ZERO,
    })
    .await;
    let client = SigilClient::builder("sk_fixture")
        .api_url(server.base_url.clone())
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Pending);
    assert_eq!(result.hold_id.as_deref(), Some("hold_123"));
}

#[tokio::test]
async fn auth_failures_are_not_classified_as_unreachable() {
    let server = spawn_server(MockResponse {
        status: StatusCode::UNAUTHORIZED,
        body: MockBody::Json(serde_json::json!({ "status": "DENIED" })),
        delay: Duration::ZERO,
    })
    .await;
    let client = SigilClient::builder("sk_fixture")
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
async fn server_errors_are_unreachable_in_closed_mode() {
    let server = spawn_server(MockResponse {
        status: StatusCode::BAD_GATEWAY,
        body: MockBody::Json(serde_json::json!({ "status": "DENIED" })),
        delay: Duration::ZERO,
    })
    .await;
    let client = SigilClient::builder("sk_fixture")
        .api_url(server.base_url.clone())
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
async fn non_json_response_is_unreachable_in_closed_mode() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Text("<html>bad gateway</html>".to_string()),
        delay: Duration::ZERO,
    })
    .await;
    let client = SigilClient::builder("sk_fixture")
        .api_url(server.base_url.clone())
        .fail_mode(FailMode::Closed)
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(result.error_code.as_deref(), Some(SIGIL_UNREACHABLE));
}

#[tokio::test]
async fn timeout_is_unreachable_in_closed_mode() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({ "status": "APPROVED" })),
        delay: Duration::from_millis(100),
    })
    .await;
    let client = SigilClient::builder("sk_fixture")
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
async fn open_mode_sets_fail_open_on_unreachable() {
    let client = SigilClient::builder("sk_fixture")
        .api_url("http://127.0.0.1:9")
        .fail_mode(FailMode::Open)
        .request_timeout(Duration::from_millis(25))
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Approved);
    assert!(result.fail_open);
}

#[tokio::test]
async fn custom_framework_serializes_as_a_bare_string() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Json(serde_json::json!({ "status": "APPROVED" })),
        delay: Duration::ZERO,
    })
    .await;
    let client = SigilClient::builder("sk_fixture")
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
    let client = SigilClient::builder("sk_fixture")
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
async fn oversized_json_response_is_unreachable() {
    let server = spawn_server(MockResponse {
        status: StatusCode::OK,
        body: MockBody::Text(format!(
            "{{\"status\":\"APPROVED\",\"message\":\"{}\"}}",
            "x".repeat(70_000)
        )),
        delay: Duration::ZERO,
    })
    .await;
    let client = SigilClient::builder("sk_fixture")
        .api_url(server.base_url.clone())
        .fail_mode(FailMode::Closed)
        .build()
        .expect("client should build");

    let result = client
        .check_intent(&fixture_bash_intent())
        .await
        .expect("check should succeed");

    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(result.error_code.as_deref(), Some(SIGIL_UNREACHABLE));
    assert!(
        result
            .message
            .as_deref()
            .expect("message")
            .contains("exceeded 65536 bytes")
    );
}

#[test]
fn builder_rejects_invalid_api_url() {
    let err = SigilClient::builder("sk_fixture")
        .api_url("not a url")
        .build()
        .expect_err("invalid url should fail");

    assert!(err.to_string().contains("invalid api_url"));
}

#[test]
fn builder_rejects_zero_timeout() {
    let err = SigilClient::builder("sk_fixture")
        .request_timeout(Duration::ZERO)
        .build()
        .expect_err("zero timeout should fail");

    assert!(err.to_string().contains("request_timeout"));
}
