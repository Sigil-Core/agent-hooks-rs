use async_trait::async_trait;
use ironclaw::hooks::{
    Hook, HookContext, HookError, HookEvent, HookFailureMode, HookOutcome, HookPoint,
};
use serde_json::Value;
use sigil_agent_hooks_core::{
    FrameworkId, SigilClient, SigilClientError, SigilDecision, SigilIntent, build_rejection_context,
};
use std::{sync::Arc, time::Duration};

static HOOK_POINTS: [HookPoint; 1] = [HookPoint::BeforeToolCall];

pub trait ToolIntentMapper: Send + Sync {
    fn map_intent(
        &self,
        tool_name: &str,
        parameters: &Value,
        user_id: &str,
        context: &str,
    ) -> SigilIntent;
}

#[derive(Default)]
pub struct DefaultToolIntentMapper;

impl DefaultToolIntentMapper {
    fn mapped_action(tool_name: &str) -> String {
        match tool_name.to_ascii_lowercase().as_str() {
            "exec" | "process" | "code_execution" => "bash".to_string(),
            "write" | "edit" | "apply_patch" => "file_write".to_string(),
            "web_fetch" | "web_search" | "x_search" | "browser" | "http" => "web_fetch".to_string(),
            "wallet_transfer" | "wallet.transfer" => "wallet.transfer".to_string(),
            "wallet_sign" => "wallet_sign".to_string(),
            other => other.to_string(),
        }
    }
}

impl ToolIntentMapper for DefaultToolIntentMapper {
    fn map_intent(
        &self,
        tool_name: &str,
        parameters: &Value,
        _user_id: &str,
        _context: &str,
    ) -> SigilIntent {
        let action = Self::mapped_action(tool_name);
        SigilIntent {
            action,
            command: parameters
                .get("command")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            url: parameters
                .get("url")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            path: parameters
                .get("path")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            to: parameters
                .get("to")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            amount: parameters
                .get("amount")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            chain_id: parameters.get("chainId").and_then(Value::as_u64),
            metadata: Some(parameters.clone()),
            ..SigilIntent::default()
        }
    }
}

pub struct IronclawSigilHook {
    name: String,
    client: SigilClient,
    mapper: Arc<dyn ToolIntentMapper>,
}

pub struct IronclawSigilHookBuilder {
    name: String,
    client: SigilClient,
    mapper: Arc<dyn ToolIntentMapper>,
}

impl IronclawSigilHook {
    pub fn builder(client: SigilClient) -> IronclawSigilHookBuilder {
        IronclawSigilHookBuilder {
            name: "sigil_ironclaw".to_string(),
            client,
            mapper: Arc::new(DefaultToolIntentMapper),
        }
    }
}

impl IronclawSigilHookBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn mapper<M>(mut self, mapper: M) -> Self
    where
        M: ToolIntentMapper + 'static,
    {
        self.mapper = Arc::new(mapper);
        self
    }

    pub fn build(mut self) -> Result<IronclawSigilHook, SigilClientError> {
        if matches!(self.client.config().framework, FrameworkId::AgentHooks) {
            let rebuilt = SigilClient::builder(self.client.config().api_key.clone())
                .api_url(self.client.config().api_url.clone())
                .framework(FrameworkId::Ironclaw)
                .fail_mode(self.client.config().fail_mode)
                .request_timeout(self.client.config().request_timeout);

            let rebuilt = match &self.client.config().agent_id {
                Some(agent_id) => rebuilt.agent_id(agent_id.clone()),
                None => rebuilt,
            };

            self.client = rebuilt.build()?;
        }

        Ok(IronclawSigilHook {
            name: self.name,
            client: self.client,
            mapper: self.mapper,
        })
    }
}

#[async_trait]
impl Hook for IronclawSigilHook {
    fn name(&self) -> &str {
        &self.name
    }

    fn hook_points(&self) -> &[HookPoint] {
        &HOOK_POINTS
    }

    fn failure_mode(&self) -> HookFailureMode {
        HookFailureMode::FailClosed
    }

    fn timeout(&self) -> Duration {
        self.client.config().request_timeout
    }

    async fn execute(
        &self,
        event: &HookEvent,
        _ctx: &HookContext,
    ) -> Result<HookOutcome, HookError> {
        let HookEvent::ToolCall {
            tool_name,
            parameters,
            user_id,
            context,
        } = event
        else {
            return Ok(HookOutcome::ok());
        };

        let intent = self
            .mapper
            .map_intent(tool_name, parameters, user_id, context);
        let action = intent.action.clone();
        let result =
            self.client
                .check_intent(&intent)
                .await
                .map_err(|err| HookError::ExecutionFailed {
                    reason: err.to_string(),
                })?;

        match result.decision {
            SigilDecision::Approved => Ok(HookOutcome::ok()),
            SigilDecision::Denied | SigilDecision::Pending => {
                let rejection = build_rejection_context(&result, &action);
                let reason = serde_json::to_string(&rejection).map_err(|err| {
                    HookError::ExecutionFailed {
                        reason: err.to_string(),
                    }
                })?;
                Ok(HookOutcome::reject(reason))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::{Json, State},
        http::StatusCode,
        routing::post,
    };
    use std::sync::{Mutex, MutexGuard};
    use tokio::{net::TcpListener, sync::oneshot};

    #[derive(Clone)]
    struct MockState {
        response: serde_json::Value,
        status: StatusCode,
        captures: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    struct TestServer {
        base_url: String,
        captures: Arc<Mutex<Vec<serde_json::Value>>>,
        shutdown: Option<oneshot::Sender<()>>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
        }
    }

    async fn authorize(
        State(state): State<MockState>,
        Json(payload): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        state.captures.lock().expect("capture lock").push(payload);
        (state.status, Json(state.response))
    }

    async fn spawn(response: serde_json::Value, status: StatusCode) -> TestServer {
        let captures = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            response,
            status,
            captures: Arc::clone(&captures),
        };
        let app = Router::new()
            .route("/v1/authorize", post(authorize))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener bind");
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

    fn captures(server: &TestServer) -> MutexGuard<'_, Vec<serde_json::Value>> {
        server.captures.lock().expect("capture lock")
    }

    fn tool_event(tool_name: &str, parameters: serde_json::Value) -> HookEvent {
        HookEvent::ToolCall {
            tool_name: tool_name.to_string(),
            parameters,
            user_id: "fixture-user".to_string(),
            context: "chat".to_string(),
        }
    }

    #[tokio::test]
    async fn non_tool_events_pass_through() {
        let client = SigilClient::builder("sk_fixture")
            .build()
            .expect("client build");
        let hook = IronclawSigilHook::builder(client)
            .build()
            .expect("hook build");

        let outcome = hook
            .execute(
                &HookEvent::SessionStart {
                    user_id: "user".to_string(),
                    session_id: "session".to_string(),
                },
                &HookContext::default(),
            )
            .await
            .expect("execute ok");

        assert!(matches!(outcome, HookOutcome::Continue { modified: None }));
    }

    #[tokio::test]
    async fn approved_tool_calls_continue() {
        let server = spawn(serde_json::json!({ "status": "APPROVED" }), StatusCode::OK).await;
        let client = SigilClient::builder("sk_fixture")
            .api_url(server.base_url.clone())
            .build()
            .expect("client build");
        let hook = IronclawSigilHook::builder(client)
            .build()
            .expect("hook build");

        let outcome = hook
            .execute(
                &tool_event("exec", serde_json::json!({ "command": "echo hi" })),
                &HookContext::default(),
            )
            .await
            .expect("execute ok");

        assert!(matches!(outcome, HookOutcome::Continue { modified: None }));
    }

    #[tokio::test]
    async fn denied_tool_calls_reject_with_sigil_metadata() {
        let server = spawn(
            serde_json::json!({
                "status": "DENIED",
                "error_code": "SIGIL_BASH_BLOCKED",
                "message": "blocked"
            }),
            StatusCode::OK,
        )
        .await;
        let client = SigilClient::builder("sk_fixture")
            .api_url(server.base_url.clone())
            .build()
            .expect("client build");
        let hook = IronclawSigilHook::builder(client)
            .build()
            .expect("hook build");

        let outcome = hook
            .execute(
                &tool_event("exec", serde_json::json!({ "command": "echo hi" })),
                &HookContext::default(),
            )
            .await
            .expect("execute ok");

        match outcome {
            HookOutcome::Reject { reason } => {
                let payload: serde_json::Value =
                    serde_json::from_str(&reason).expect("reason JSON");
                assert_eq!(payload["sigil_error_code"], "SIGIL_BASH_BLOCKED");
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn pending_tool_calls_reject_with_hold_guidance() {
        let server = spawn(
            serde_json::json!({
                "status": "PENDING",
                "holdId": "hold_123",
                "message": "approval required"
            }),
            StatusCode::OK,
        )
        .await;
        let client = SigilClient::builder("sk_fixture")
            .api_url(server.base_url.clone())
            .build()
            .expect("client build");
        let hook = IronclawSigilHook::builder(client)
            .build()
            .expect("hook build");

        let outcome = hook
            .execute(
                &tool_event(
                    "wallet.transfer",
                    serde_json::json!({ "to": "0xabc", "amount": "1" }),
                ),
                &HookContext::default(),
            )
            .await
            .expect("execute ok");

        match outcome {
            HookOutcome::Reject { reason } => {
                let payload: serde_json::Value =
                    serde_json::from_str(&reason).expect("reason JSON");
                assert_eq!(payload["sigil_hold_id"], "hold_123");
                assert!(
                    payload["sigil_next_steps"]
                        .as_str()
                        .expect("next steps string")
                        .contains("approve")
                );
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unreachable_in_closed_mode_rejects_with_sigil_unreachable() {
        let client = SigilClient::builder("sk_fixture")
            .api_url("http://127.0.0.1:9")
            .build()
            .expect("client build");
        let hook = IronclawSigilHook::builder(client)
            .build()
            .expect("hook build");

        let outcome = hook
            .execute(
                &tool_event("exec", serde_json::json!({ "command": "echo hi" })),
                &HookContext::default(),
            )
            .await
            .expect("execute ok");

        match outcome {
            HookOutcome::Reject { reason } => {
                let payload: serde_json::Value =
                    serde_json::from_str(&reason).expect("reason JSON");
                assert_eq!(payload["sigil_error_code"], "SIGIL_UNREACHABLE");
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    struct CustomMapper;

    impl ToolIntentMapper for CustomMapper {
        fn map_intent(
            &self,
            _tool_name: &str,
            _parameters: &Value,
            _user_id: &str,
            _context: &str,
        ) -> SigilIntent {
            SigilIntent {
                action: "custom.action".to_string(),
                ..SigilIntent::default()
            }
        }
    }

    #[tokio::test]
    async fn custom_mapper_overrides_default_action_mapping() {
        let server = spawn(serde_json::json!({ "status": "APPROVED" }), StatusCode::OK).await;
        let client = SigilClient::builder("sk_fixture")
            .api_url(server.base_url.clone())
            .build()
            .expect("client build");
        let hook = IronclawSigilHook::builder(client)
            .mapper(CustomMapper)
            .build()
            .expect("hook build");

        let _ = hook
            .execute(
                &tool_event("exec", serde_json::json!({ "command": "echo hi" })),
                &HookContext::default(),
            )
            .await
            .expect("execute ok");

        let body = captures(&server);
        assert_eq!(body[0]["framework"], "ironclaw");
        assert_eq!(body[0]["intent"]["action"], "custom.action");
    }

    #[tokio::test]
    async fn unknown_tools_lowercase_passthrough() {
        let server = spawn(serde_json::json!({ "status": "APPROVED" }), StatusCode::OK).await;
        let client = SigilClient::builder("sk_fixture")
            .api_url(server.base_url.clone())
            .build()
            .expect("client build");
        let hook = IronclawSigilHook::builder(client)
            .build()
            .expect("hook build");

        let _ = hook
            .execute(
                &tool_event("Sessions_List", serde_json::json!({})),
                &HookContext::default(),
            )
            .await
            .expect("execute ok");

        let body = captures(&server);
        assert_eq!(body[0]["intent"]["action"], "sessions_list");
    }

    #[tokio::test]
    async fn default_mapper_sends_expected_bash_action() {
        let server = spawn(serde_json::json!({ "status": "APPROVED" }), StatusCode::OK).await;
        let client = SigilClient::builder("sk_fixture")
            .api_url(server.base_url.clone())
            .build()
            .expect("client build");
        let hook = IronclawSigilHook::builder(client)
            .build()
            .expect("hook build");

        let _ = hook
            .execute(
                &tool_event("exec", serde_json::json!({ "command": "echo hi" })),
                &HookContext::default(),
            )
            .await
            .expect("execute ok");

        let body = captures(&server);
        assert_eq!(body[0]["intent"]["action"], "bash");
        assert_eq!(body[0]["intent"]["command"], "echo hi");
    }
}
