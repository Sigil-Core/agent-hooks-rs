mod client;
mod model_usage;
mod rejection;
mod response_wire;
mod types;

pub use model_usage::{
    check_model_budget, clear_model_usage, get_model_usage_report, normalize_model_usage,
    record_model_usage,
};
pub use rejection::build_rejection_context;
pub use response_wire::{
    CompiledResponsePolicyBounds, CompiledResponsePolicyFormat1,
    CompiledResponsePolicyFormat1Policy, ResponseClass, ResponseDecisionReason, ResponseDecisionV1,
    ResponseDispositionV1, ResponseFinding, ResponseManifestBinding, ResponseWireError,
    parse_compiled_response_policy_format1, parse_response_decision_v1,
};
pub use types::{
    FailMode, FrameworkId, HttpMethod, SigilClient, SigilClientBuilder, SigilClientError,
    SigilConfig, SigilDecision, SigilIntent, SigilModelUsage, SigilModelUsageError,
    SigilModelUsageReport, SigilRejectionContext, SigilResult,
};

pub const SIGIL_UNREACHABLE: &str = "SIGIL_UNREACHABLE";
pub const SIGIL_MODEL_SPEND_LIMIT_EXCEEDED: &str = "SIGIL_MODEL_SPEND_LIMIT_EXCEEDED";
pub const SIGIL_MODEL_TOKEN_LIMIT_EXCEEDED: &str = "SIGIL_MODEL_TOKEN_LIMIT_EXCEEDED";
pub const SIGIL_MODEL_USAGE_UNAVAILABLE: &str = "SIGIL_MODEL_USAGE_UNAVAILABLE";
