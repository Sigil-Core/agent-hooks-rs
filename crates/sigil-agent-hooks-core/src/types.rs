use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    sync::Arc,
    time::{Duration, SystemTimeError},
};
use thiserror::Error;

use crate::decision::{AuthorizationCapability, JwksCache};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailMode {
    Open,
    #[default]
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FrameworkId {
    #[default]
    AgentHooks,
    AnthropicSdk,
    Eliza,
    Langchain,
    Openclaw,
    Nemoclaw,
    Ironclaw,
    AgentPay,
    Custom(String),
}

impl FrameworkId {
    pub fn as_str(&self) -> &str {
        match self {
            Self::AgentHooks => "agent-hooks",
            Self::AnthropicSdk => "anthropic-sdk",
            Self::Eliza => "eliza",
            Self::Langchain => "langchain",
            Self::Openclaw => "openclaw",
            Self::Nemoclaw => "nemoclaw",
            Self::Ironclaw => "ironclaw",
            Self::AgentPay => "agentpay",
            Self::Custom(value) => value.as_str(),
        }
    }
}

impl Serialize for FrameworkId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FrameworkId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "agent-hooks" => Self::AgentHooks,
            "anthropic-sdk" => Self::AnthropicSdk,
            "eliza" => Self::Eliza,
            "langchain" => Self::Langchain,
            "openclaw" => Self::Openclaw,
            "nemoclaw" => Self::Nemoclaw,
            "ironclaw" => Self::Ironclaw,
            "agentpay" => Self::AgentPay,
            other => Self::Custom(other.to_string()),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
/// Canonical authorization decision. Legacy `APPROVED` input deserializes as
/// [`SigilDecision::Allowed`], and serialization always emits `ALLOWED`.
pub enum SigilDecision {
    #[default]
    #[serde(rename = "ALLOWED", alias = "APPROVED")]
    Allowed,
    #[serde(rename = "DENIED")]
    Denied,
    #[serde(rename = "PENDING")]
    Pending,
}

impl SigilDecision {
    /// Source-compatible spelling for callers compiled against versions that
    /// exposed `SigilDecision::Approved`. It is the canonical `Allowed` value
    /// and therefore serializes as `ALLOWED`.
    #[allow(non_upper_case_globals)]
    #[deprecated(note = "use SigilDecision::Allowed")]
    pub const Approved: Self = Self::Allowed;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// Controls whether a reached authorization response must be cryptographically
/// verified before it can authorize execution.
pub enum DecisionVerificationMode {
    /// Preserve legacy execution for an `ALLOWED` or `APPROVED` response that
    /// cannot be verified, but mark its authorization as legacy-unverified.
    Warn,
    /// Deny an `ALLOWED` or `APPROVED` response unless its decision record and
    /// execution attestation verify and bind to the current request.
    #[default]
    Enforce,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// An Ed25519 public JWK accepted by the decision verifier.
///
/// Verification requires `kty = "OKP"`, `crv = "Ed25519"`, a unique nonempty
/// `kid`, and an unpadded base64url `x`. Optional `use`, `key_ops`, and `alg`
/// values must permit signature verification when present.
pub struct DecisionJwk {
    pub kty: String,
    pub crv: String,
    pub kid: String,
    pub x: String,
    #[serde(default)]
    pub r#use: Option<String>,
    #[serde(default)]
    pub key_ops: Option<Vec<String>>,
    #[serde(default)]
    pub alg: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigilIntent {
    pub action: String,
    pub arguments: Option<serde_json::Value>,
    pub agent_id: Option<String>,
    pub chain_id: Option<u64>,
    pub command: Option<String>,
    pub url: Option<String>,
    pub method: Option<HttpMethod>,
    pub path: Option<String>,
    pub to: Option<String>,
    pub amount: Option<String>,
    pub calldata: Option<String>,
    pub tx_commit: Option<String>,
    pub task_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Options,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Debug, Clone)]
pub struct SigilConfig {
    pub api_key: String,
    pub api_url: String,
    pub agent_id: Option<String>,
    pub task_id: Option<String>,
    pub framework: FrameworkId,
    pub fail_mode: FailMode,
    pub request_timeout: Duration,
    /// Warn preserves legacy authorization; enforce requires verified records.
    pub decision_verification_mode: DecisionVerificationMode,
    /// Expected lowercase SHA-256 policy hash. Required in enforce mode and
    /// checked against both signed artifacts.
    pub expected_policy_hash: Option<String>,
    /// Optional pinned Ed25519 verification key. A matching pinned key takes
    /// precedence over the origin-bound JWKS cache.
    pub decision_record_jwk: Option<DecisionJwk>,
    /// Exact issuer required on the execution attestation.
    pub attestation_issuer: String,
    #[cfg(any(test, feature = "test-certificates"))]
    #[doc(hidden)]
    pub additional_root_certificate_pem: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SigilClientBuilder {
    pub(crate) api_key: String,
    pub(crate) api_url: String,
    pub(crate) agent_id: Option<String>,
    pub(crate) task_id: Option<String>,
    pub(crate) framework: FrameworkId,
    pub(crate) fail_mode: FailMode,
    pub(crate) request_timeout: Duration,
    pub(crate) decision_verification_mode: DecisionVerificationMode,
    pub(crate) expected_policy_hash: Option<String>,
    pub(crate) decision_record_jwk: Option<DecisionJwk>,
    pub(crate) attestation_issuer: String,
    #[cfg(any(test, feature = "test-certificates"))]
    pub(crate) additional_root_certificate_pem: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SigilClient {
    pub(crate) config: SigilConfig,
    pub(crate) http: Client,
    pub(crate) jwks_http: Client,
    pub(crate) jwks_cache: Arc<JwksCache>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SigilResult {
    pub decision: SigilDecision,
    pub hold_id: Option<String>,
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub policy_hash: Option<String>,
    pub fail_open: bool,
    /// Opaque execution authority owned by this result. It is neither cloneable
    /// nor serializable and is absent from serialized `SigilResult` values.
    #[serde(skip)]
    pub authorization: Option<AuthorizationCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigilRejectionContext {
    pub sigil_decision: String,
    pub sigil_error_code: String,
    pub sigil_message: String,
    pub sigil_hold_id: Option<String>,
    pub sigil_policy_hash: Option<String>,
    pub sigil_task_id: Option<String>,
    pub sigil_action_taken: String,
    pub sigil_next_steps: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
/// Raw model usage reported by a provider adapter before Sigil normalizes it.
pub struct SigilModelUsage {
    /// Provider name such as `openrouter`, `anthropic`, or `openai`.
    pub provider: Option<String>,
    /// Provider model identifier used for the inference call.
    pub model: Option<String>,
    /// Prompt, input, or context tokens reported by the provider.
    pub input_tokens: Option<u64>,
    /// Completion or output tokens reported by the provider.
    pub output_tokens: Option<u64>,
    /// Optional raw total from the provider. When omitted, Sigil derives it
    /// from `input_tokens + output_tokens` during normalization.
    pub total_tokens: Option<u64>,
    /// Decimal USD spend estimate, stored as a string with up to 6 fractional
    /// digits so integer microdollar accumulation stays deterministic.
    pub estimated_spend_usd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
/// Cumulative, task-local model usage submitted to Sigil for budget checks.
pub struct SigilModelUsageReport {
    /// Last known provider name for the task-local usage ledger.
    pub provider: Option<String>,
    /// Last known model identifier for the task-local usage ledger.
    pub model: Option<String>,
    /// Accumulated input tokens for the task.
    pub input_tokens: Option<u64>,
    /// Accumulated output tokens for the task.
    pub output_tokens: Option<u64>,
    /// Required accumulated total tokens. Missing provider totals are derived
    /// from input and output counts before they enter the ledger.
    pub total_tokens: u64,
    /// Accumulated decimal USD spend estimate with up to 6 fractional digits.
    pub estimated_spend_usd: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
/// Errors raised while normalizing or accumulating provider model usage.
pub enum SigilModelUsageError {
    #[error("{field} overflowed u64")]
    TokenOverflow { field: &'static str },
    #[error("estimated_spend_usd must be a decimal string with up to 6 fractional digits")]
    InvalidSpend,
    #[error("estimated_spend_usd overflowed microdollar accumulator")]
    SpendOverflow,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SigilClientError {
    #[error("invalid {field}: {message}")]
    InvalidConfig {
        field: &'static str,
        message: String,
    },
    #[error("failed to build HTTP client: {0}")]
    HttpClient(reqwest::Error),
    #[error("failed to serialize request body: {0}")]
    Serialize(serde_json::Error),
    #[error("system clock before unix epoch: {0}")]
    Clock(SystemTimeError),
    #[error("invalid model usage: {0}")]
    ModelUsage(#[from] SigilModelUsageError),
}
