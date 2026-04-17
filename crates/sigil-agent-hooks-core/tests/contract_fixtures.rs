use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use sha2::{Digest, Sha256};
use sigil_agent_hooks_core::{FrameworkId, SigilClient, SigilIntent};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, sync::oneshot};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contract-fixtures/v1")
}

fn fixture_text(name: &str) -> String {
    fs::read_to_string(fixture_root().join(name)).expect("fixture must exist")
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
    let body = String::from_utf8(body.to_vec()).expect("utf8 body");
    state.captures.lock().expect("capture lock").push(body);
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

fn captured_body(server: &TestServer) -> String {
    server
        .captures
        .lock()
        .expect("capture lock")
        .first()
        .expect("captured body")
        .clone()
}

#[test]
fn fixture_hashes_match_sha256sums_file() {
    let checksums = fixture_text("SHA256SUMS");
    for line in checksums.lines().filter(|line| !line.trim().is_empty()) {
        let (expected, file_name) = line.split_once("  ").expect("valid checksum line");
        let bytes = fs::read(fixture_root().join(file_name)).expect("fixture bytes must exist");
        let actual = format!("{:x}", Sha256::digest(bytes));
        assert_eq!(actual, expected, "checksum mismatch for {file_name}");
    }
}

#[tokio::test]
async fn bash_fixture_matches_http_wire_body() {
    let server = spawn().await;
    let client = SigilClient::builder("sk_fixture")
        .api_url(server.base_url.clone())
        .agent_id("fixture-agent")
        .framework(FrameworkId::AgentHooks)
        .build()
        .expect("client should build");

    let intent = SigilIntent {
        action: "bash".to_string(),
        command: Some("ls -la".to_string()),
        tx_commit: Some(
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        ),
        ..SigilIntent::default()
    };

    let _ = client
        .check_intent(&intent)
        .await
        .expect("request should succeed");
    assert_eq!(captured_body(&server), fixture_text("bash.json"));
}

#[tokio::test]
async fn web_fetch_fixture_matches_http_wire_body() {
    let server = spawn().await;
    let client = SigilClient::builder("sk_fixture")
        .api_url(server.base_url.clone())
        .agent_id("fixture-agent")
        .framework(FrameworkId::AgentHooks)
        .build()
        .expect("client should build");

    let intent = SigilIntent {
        action: "web_fetch".to_string(),
        url: Some("https://example.com/policy".to_string()),
        tx_commit: Some(
            "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        ),
        ..SigilIntent::default()
    };

    let _ = client
        .check_intent(&intent)
        .await
        .expect("request should succeed");
    assert_eq!(captured_body(&server), fixture_text("web_fetch.json"));
}

#[tokio::test]
async fn wallet_transfer_fixture_matches_http_wire_body() {
    let server = spawn().await;
    let client = SigilClient::builder("sk_fixture")
        .api_url(server.base_url.clone())
        .agent_id("fixture-agent")
        .framework(FrameworkId::AgentHooks)
        .build()
        .expect("client should build");

    let intent = SigilIntent {
        action: "wallet.transfer".to_string(),
        chain_id: Some(1),
        to: Some("0xabc".to_string()),
        amount: Some("1000000000000000000".to_string()),
        tx_commit: Some(
            "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        ),
        ..SigilIntent::default()
    };

    let _ = client
        .check_intent(&intent)
        .await
        .expect("request should succeed");
    assert_eq!(captured_body(&server), fixture_text("wallet.transfer.json"));
}

#[tokio::test]
async fn intent_agent_override_fixture_matches_http_wire_body() {
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
        tx_commit: Some(
            "6fd4947d41a7b08df3fede4821f93f9c92176a828b7fd9669772577a415e0f9d".to_string(),
        ),
        ..SigilIntent::default()
    };

    let _ = client
        .check_intent(&intent)
        .await
        .expect("request should succeed");
    assert_eq!(
        captured_body(&server),
        fixture_text("intent_agent_override.json")
    );
}
