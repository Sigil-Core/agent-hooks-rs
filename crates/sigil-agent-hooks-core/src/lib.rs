mod client;
mod rejection;
mod types;

pub use rejection::build_rejection_context;
pub use types::{
    FailMode, FrameworkId, SigilClient, SigilClientBuilder, SigilClientError, SigilConfig,
    SigilDecision, SigilIntent, SigilRejectionContext, SigilResult,
};

pub const SIGIL_UNREACHABLE: &str = "SIGIL_UNREACHABLE";
