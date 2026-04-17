use crate::types::{SigilRejectionContext, SigilResult};
use crate::{SIGIL_UNREACHABLE, SigilDecision};

pub fn build_rejection_context(result: &SigilResult, action: &str) -> SigilRejectionContext {
    match result.decision {
        SigilDecision::Pending => SigilRejectionContext {
            sigil_decision: "PENDING".to_string(),
            sigil_error_code: "SIGIL_CONSENSUS_HOLD_REQUIRED".to_string(),
            sigil_message: result
                .message
                .clone()
                .unwrap_or_else(|| "Action requires human approval.".to_string()),
            sigil_hold_id: result.hold_id.clone(),
            sigil_policy_hash: result.policy_hash.clone(),
            sigil_action_taken: "pending_approval".to_string(),
            sigil_next_steps: "This action is held in Sigil. An operator must approve it in Sigil before the exact same action is retried manually.".to_string(),
        },
        SigilDecision::Denied if result.error_code.as_deref() == Some(SIGIL_UNREACHABLE) => {
            SigilRejectionContext {
                sigil_decision: "DENIED".to_string(),
                sigil_error_code: SIGIL_UNREACHABLE.to_string(),
                sigil_message: result
                    .message
                    .clone()
                    .unwrap_or_else(|| "Sigil policy service unreachable.".to_string()),
                sigil_hold_id: None,
                sigil_policy_hash: result.policy_hash.clone(),
                sigil_action_taken: "halted".to_string(),
                sigil_next_steps: "Sigil is temporarily unreachable - this is a transient infrastructure failure, not a policy denial. Restore connectivity to Sigil and retry the same action.".to_string(),
            }
        }
        _ => SigilRejectionContext {
            sigil_decision: "DENIED".to_string(),
            sigil_error_code: result
                .error_code
                .clone()
                .unwrap_or_else(|| "SIGIL_POLICY_VIOLATION".to_string()),
            sigil_message: result
                .message
                .clone()
                .unwrap_or_else(|| "Action blocked by Sigil policy.".to_string()),
            sigil_hold_id: None,
            sigil_policy_hash: result.policy_hash.clone(),
            sigil_action_taken: "halted".to_string(),
            sigil_next_steps: format!(
                "The action \"{action}\" was blocked. Do not retry until the operator reviews the Sigil decision."
            ),
        },
    }
}
