use crate::types::{
    SigilClient, SigilClientError, SigilIntent, SigilModelUsage, SigilModelUsageError,
    SigilModelUsageReport, SigilResult,
};
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, OnceLock},
    time::{Duration, Instant},
};

const MODEL_USAGE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone)]
struct ModelUsageEntry {
    report: SigilModelUsageReport,
    updated_at: Instant,
}

static USAGE_BY_TASK: OnceLock<Mutex<HashMap<String, ModelUsageEntry>>> = OnceLock::new();

fn usage_by_task() -> &'static Mutex<HashMap<String, ModelUsageEntry>> {
    USAGE_BY_TASK.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_usage_entries() -> MutexGuard<'static, HashMap<String, ModelUsageEntry>> {
    usage_by_task()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn evict_expired_model_usage(now: Instant, entries: &mut HashMap<String, ModelUsageEntry>) {
    entries.retain(|_, entry| now.duration_since(entry.updated_at) <= MODEL_USAGE_TTL);
}

pub fn normalize_model_usage(
    usage: SigilModelUsage,
) -> Result<SigilModelUsageReport, SigilModelUsageError> {
    let total_tokens = match usage.total_tokens {
        Some(value) => value,
        None => usage
            .input_tokens
            .unwrap_or(0)
            .checked_add(usage.output_tokens.unwrap_or(0))
            .ok_or(SigilModelUsageError::TokenOverflow {
                field: "total_tokens",
            })?,
    };

    Ok(SigilModelUsageReport {
        provider: usage.provider,
        model: usage.model,
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        total_tokens,
        estimated_spend_usd: match usage.estimated_spend_usd {
            Some(value) => Some(normalize_spend(&value)?),
            None => None,
        },
    })
}

pub fn record_model_usage(
    client: &SigilClient,
    usage: SigilModelUsage,
    task_id: Option<&str>,
) -> Result<SigilModelUsageReport, SigilModelUsageError> {
    let resolved_task_id = task_id
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| client.resolve_task_id(&model_inference_intent(None)));
    let next = normalize_model_usage(usage)?;
    let now = Instant::now();
    let mut entries = lock_usage_entries();
    evict_expired_model_usage(now, &mut entries);
    let previous = entries.get(&resolved_task_id).map(|entry| &entry.report);

    let input_tokens = previous
        .and_then(|report| report.input_tokens)
        .unwrap_or(0)
        .checked_add(next.input_tokens.unwrap_or(0))
        .ok_or(SigilModelUsageError::TokenOverflow {
            field: "input_tokens",
        })?;
    let output_tokens = previous
        .and_then(|report| report.output_tokens)
        .unwrap_or(0)
        .checked_add(next.output_tokens.unwrap_or(0))
        .ok_or(SigilModelUsageError::TokenOverflow {
            field: "output_tokens",
        })?;
    let total_tokens = previous
        .map(|report| report.total_tokens)
        .unwrap_or(0)
        .checked_add(next.total_tokens)
        .ok_or(SigilModelUsageError::TokenOverflow {
            field: "total_tokens",
        })?;

    let cumulative = SigilModelUsageReport {
        provider: next
            .provider
            .or_else(|| previous.and_then(|report| report.provider.clone())),
        model: next
            .model
            .or_else(|| previous.and_then(|report| report.model.clone())),
        input_tokens: Some(input_tokens),
        output_tokens: Some(output_tokens),
        total_tokens,
        estimated_spend_usd: add_decimal_strings(
            previous.and_then(|report| report.estimated_spend_usd.as_deref()),
            next.estimated_spend_usd.as_deref(),
        )?,
    };

    entries.insert(
        resolved_task_id,
        ModelUsageEntry {
            report: cumulative.clone(),
            updated_at: now,
        },
    );
    Ok(cumulative)
}

pub fn get_model_usage_report(
    client: &SigilClient,
    task_id: Option<&str>,
) -> Option<SigilModelUsageReport> {
    let resolved_task_id = task_id
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| client.resolve_task_id(&model_inference_intent(None)));
    let now = Instant::now();
    let mut entries = lock_usage_entries();
    evict_expired_model_usage(now, &mut entries);
    entries
        .get(&resolved_task_id)
        .map(|entry| entry.report.clone())
}

pub fn clear_model_usage(client: &SigilClient, task_id: Option<&str>) {
    let resolved_task_id = task_id
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| client.resolve_task_id(&model_inference_intent(None)));
    lock_usage_entries().remove(&resolved_task_id);
}

pub async fn check_model_budget(
    client: &SigilClient,
    task_id: Option<&str>,
) -> Result<SigilResult, SigilClientError> {
    let resolved_task_id = task_id
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| client.resolve_task_id(&model_inference_intent(None)));
    let report = get_model_usage_report(client, Some(&resolved_task_id));
    let intent = model_inference_intent(Some(&resolved_task_id)).with_model_usage(report)?;
    client.check_intent(&intent).await
}

trait WithModelUsage {
    fn with_model_usage(
        self,
        report: Option<SigilModelUsageReport>,
    ) -> Result<SigilIntent, SigilClientError>;
}

impl WithModelUsage for SigilIntent {
    fn with_model_usage(
        mut self,
        report: Option<SigilModelUsageReport>,
    ) -> Result<SigilIntent, SigilClientError> {
        self.metadata = report.map(|report| json!({ "model_usage": report }));
        Ok(self)
    }
}

fn model_inference_intent(task_id: Option<&str>) -> SigilIntent {
    SigilIntent {
        action: "model.inference".to_string(),
        chain_id: Some(1),
        task_id: task_id.map(ToOwned::to_owned),
        ..SigilIntent::default()
    }
}

fn normalize_spend(value: &str) -> Result<String, SigilModelUsageError> {
    Ok(micros_to_decimal(decimal_to_micros(value)?))
}

fn add_decimal_strings(
    a: Option<&str>,
    b: Option<&str>,
) -> Result<Option<String>, SigilModelUsageError> {
    match (a, b) {
        (None, None) => Ok(None),
        (Some(value), None) | (None, Some(value)) => Ok(Some(normalize_spend(value)?)),
        (Some(a), Some(b)) => {
            let micros = decimal_to_micros(a)?
                .checked_add(decimal_to_micros(b)?)
                .ok_or(SigilModelUsageError::SpendOverflow)?;
            Ok(Some(micros_to_decimal(micros)))
        }
    }
}

fn decimal_to_micros(value: &str) -> Result<u128, SigilModelUsageError> {
    let (whole, fraction) = value
        .split_once('.')
        .map_or((value, ""), |(whole, fraction)| (whole, fraction));
    if whole.is_empty()
        || !whole.chars().all(|ch| ch.is_ascii_digit())
        || (whole.len() > 1 && whole.starts_with('0'))
        || fraction.len() > 6
        || !fraction.chars().all(|ch| ch.is_ascii_digit())
    {
        return Err(SigilModelUsageError::InvalidSpend);
    }
    let whole = whole
        .parse::<u128>()
        .map_err(|_| SigilModelUsageError::InvalidSpend)?;
    let fraction = format!("{fraction:0<6}")
        .parse::<u128>()
        .map_err(|_| SigilModelUsageError::InvalidSpend)?;
    whole
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(fraction))
        .ok_or(SigilModelUsageError::SpendOverflow)
}

fn micros_to_decimal(micros: u128) -> String {
    let whole = micros / 1_000_000;
    let fraction = micros % 1_000_000;
    if fraction == 0 {
        return whole.to_string();
    }
    format!("{whole}.{fraction:06}")
        .trim_end_matches('0')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FailMode;
    use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
    use std::sync::Arc;
    use tokio::{net::TcpListener, sync::oneshot};

    #[derive(Clone)]
    struct MockState {
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

    async fn authorize(State(state): State<MockState>, body: Bytes) -> (StatusCode, &'static str) {
        let payload: serde_json::Value =
            serde_json::from_slice(&body).expect("authorize request json");
        state.captures.lock().expect("capture lock").push(payload);
        (
            StatusCode::OK,
            "{\"status\":\"APPROVED\",\"policyHash\":\"hash_123\"}",
        )
    }

    async fn spawn() -> TestServer {
        let captures = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/v1/authorize", post(authorize))
            .with_state(MockState {
                captures: Arc::clone(&captures),
            });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
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

    fn client_with_task(task_id: &str) -> SigilClient {
        SigilClient::builder("sk_fixture")
            .api_url("http://127.0.0.1:9")
            .task_id(task_id)
            .fail_mode(FailMode::Closed)
            .build()
            .expect("client")
    }

    #[test]
    fn normalizes_provider_usage_into_sigil_shape() {
        let report = normalize_model_usage(SigilModelUsage {
            provider: Some("anthropic".to_string()),
            model: Some("claude-sonnet-4-20260601".to_string()),
            input_tokens: Some(12),
            output_tokens: Some(3),
            estimated_spend_usd: Some("0.142500".to_string()),
            ..SigilModelUsage::default()
        })
        .expect("usage");

        assert_eq!(report.provider.as_deref(), Some("anthropic"));
        assert_eq!(report.model.as_deref(), Some("claude-sonnet-4-20260601"));
        assert_eq!(report.input_tokens, Some(12));
        assert_eq!(report.output_tokens, Some(3));
        assert_eq!(report.total_tokens, 15);
        assert_eq!(report.estimated_spend_usd.as_deref(), Some("0.1425"));
    }

    #[test]
    fn accumulates_task_local_token_and_spend_usage() {
        let client = client_with_task("task-model-accumulate");
        clear_model_usage(&client, None);

        record_model_usage(
            &client,
            SigilModelUsage {
                provider: Some("anthropic".to_string()),
                model: Some("claude-sonnet-4-20260601".to_string()),
                input_tokens: Some(100),
                output_tokens: Some(50),
                estimated_spend_usd: Some("0.100001".to_string()),
                ..SigilModelUsage::default()
            },
            None,
        )
        .expect("record");

        let report = record_model_usage(
            &client,
            SigilModelUsage {
                input_tokens: Some(10),
                output_tokens: Some(5),
                estimated_spend_usd: Some("0.000009".to_string()),
                ..SigilModelUsage::default()
            },
            None,
        )
        .expect("record");

        assert_eq!(report.provider.as_deref(), Some("anthropic"));
        assert_eq!(report.model.as_deref(), Some("claude-sonnet-4-20260601"));
        assert_eq!(report.input_tokens, Some(110));
        assert_eq!(report.output_tokens, Some(55));
        assert_eq!(report.total_tokens, 165);
        assert_eq!(report.estimated_spend_usd.as_deref(), Some("0.10001"));
        assert_eq!(get_model_usage_report(&client, None), Some(report));
    }

    #[test]
    fn clear_removes_task_usage() {
        let client = client_with_task("task-model-clear");
        record_model_usage(
            &client,
            SigilModelUsage {
                input_tokens: Some(1),
                output_tokens: Some(2),
                ..SigilModelUsage::default()
            },
            None,
        )
        .expect("record");

        clear_model_usage(&client, None);
        assert_eq!(get_model_usage_report(&client, None), None);
    }

    #[test]
    fn rejects_invalid_spend() {
        let error = normalize_model_usage(SigilModelUsage {
            estimated_spend_usd: Some("01.1234567".to_string()),
            ..SigilModelUsage::default()
        })
        .expect_err("invalid spend");

        assert_eq!(error, SigilModelUsageError::InvalidSpend);
    }

    #[tokio::test]
    async fn check_model_budget_sends_cumulative_model_usage() {
        let server = spawn().await;
        let client = SigilClient::builder("sk_fixture")
            .api_url(server.base_url.clone())
            .task_id("task-model-budget")
            .build()
            .expect("client");
        clear_model_usage(&client, None);
        record_model_usage(
            &client,
            SigilModelUsage {
                provider: Some("anthropic".to_string()),
                model: Some("claude-sonnet-4-20260601".to_string()),
                input_tokens: Some(100),
                output_tokens: Some(25),
                estimated_spend_usd: Some("0.25".to_string()),
                ..SigilModelUsage::default()
            },
            None,
        )
        .expect("record");

        let result = check_model_budget(&client, None).await.expect("budget");
        assert_eq!(result.policy_hash.as_deref(), Some("hash_123"));

        let captures = server.captures.lock().expect("captures");
        let body = captures.first().expect("capture");
        assert_eq!(body["chainId"], 1);
        assert_eq!(body["intent"]["action"], "model.inference");
        assert_eq!(body["intent"]["task_id"], "task-model-budget");
        assert_eq!(
            body["intent"]["metadata"]["model_usage"]["provider"],
            "anthropic"
        );
        assert_eq!(
            body["intent"]["metadata"]["model_usage"]["model"],
            "claude-sonnet-4-20260601"
        );
        assert_eq!(
            body["intent"]["metadata"]["model_usage"]["input_tokens"],
            100
        );
        assert_eq!(
            body["intent"]["metadata"]["model_usage"]["output_tokens"],
            25
        );
        assert_eq!(
            body["intent"]["metadata"]["model_usage"]["total_tokens"],
            125
        );
        assert_eq!(
            body["intent"]["metadata"]["model_usage"]["estimated_spend_usd"],
            "0.25"
        );
    }
}
