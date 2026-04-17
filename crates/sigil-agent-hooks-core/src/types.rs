use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{Duration, SystemTimeError};
use thiserror::Error;

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
#[serde(rename_all = "UPPERCASE")]
pub enum SigilDecision {
    #[default]
    Approved,
    Denied,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigilIntent {
    pub action: String,
    pub agent_id: Option<String>,
    pub chain_id: Option<u64>,
    pub command: Option<String>,
    pub url: Option<String>,
    pub path: Option<String>,
    pub to: Option<String>,
    pub amount: Option<String>,
    pub tx_commit: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct SigilConfig {
    pub api_key: String,
    pub api_url: String,
    pub agent_id: Option<String>,
    pub framework: FrameworkId,
    pub fail_mode: FailMode,
    pub request_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct SigilClientBuilder {
    pub(crate) api_key: String,
    pub(crate) api_url: String,
    pub(crate) agent_id: Option<String>,
    pub(crate) framework: FrameworkId,
    pub(crate) fail_mode: FailMode,
    pub(crate) request_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct SigilClient {
    pub(crate) config: SigilConfig,
    pub(crate) http: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SigilResult {
    pub decision: SigilDecision,
    pub hold_id: Option<String>,
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub policy_hash: Option<String>,
    pub fail_open: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigilRejectionContext {
    pub sigil_decision: String,
    pub sigil_error_code: String,
    pub sigil_message: String,
    pub sigil_hold_id: Option<String>,
    pub sigil_policy_hash: Option<String>,
    pub sigil_action_taken: String,
    pub sigil_next_steps: String,
}

#[derive(Debug, Error)]
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
}
