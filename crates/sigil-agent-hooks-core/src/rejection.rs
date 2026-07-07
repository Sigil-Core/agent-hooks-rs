use crate::types::{SigilRejectionContext, SigilResult};
use crate::{
    SIGIL_MODEL_SPEND_LIMIT_EXCEEDED, SIGIL_MODEL_TOKEN_LIMIT_EXCEEDED,
    SIGIL_MODEL_USAGE_UNAVAILABLE, SIGIL_UNREACHABLE, SigilDecision,
};

pub fn build_rejection_context(
    result: &SigilResult,
    action: &str,
    task_id: Option<&str>,
) -> SigilRejectionContext {
    let sigil_task_id = task_id.map(ToOwned::to_owned);
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
            sigil_task_id: sigil_task_id.clone(),
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
                sigil_task_id: sigil_task_id.clone(),
                sigil_action_taken: "halted".to_string(),
                sigil_next_steps: "Sigil is temporarily unreachable - this is a transient infrastructure failure, not a policy denial. Restore connectivity to Sigil and retry the same action.".to_string(),
            }
        }
        SigilDecision::Denied
            if matches!(
                result.error_code.as_deref(),
                Some(SIGIL_MODEL_SPEND_LIMIT_EXCEEDED | SIGIL_MODEL_TOKEN_LIMIT_EXCEEDED)
            ) =>
        {
            SigilRejectionContext {
                sigil_decision: "DENIED".to_string(),
                sigil_error_code: result
                    .error_code
                    .clone()
                    .unwrap_or_else(|| SIGIL_MODEL_SPEND_LIMIT_EXCEEDED.to_string()),
                sigil_message: result
                    .message
                    .clone()
                    .unwrap_or_else(|| "Sigil hard-stopped this task after it exceeded a model budget.".to_string()),
                sigil_hold_id: None,
                sigil_policy_hash: result.policy_hash.clone(),
                sigil_task_id: sigil_task_id.clone(),
                sigil_action_taken: "halted".to_string(),
                sigil_next_steps:
                    "Hard-stop the current run. Do not start another model call in this task. Ask the operator to approve a new task or raise the signed budget."
                        .to_string(),
            }
        }
        SigilDecision::Denied
            if result.error_code.as_deref() == Some(SIGIL_MODEL_USAGE_UNAVAILABLE) =>
        {
            SigilRejectionContext {
                sigil_decision: "DENIED".to_string(),
                sigil_error_code: SIGIL_MODEL_USAGE_UNAVAILABLE.to_string(),
                sigil_message: result
                    .message
                    .clone()
                    .unwrap_or_else(|| "Sigil could not verify model usage for this budgeted task.".to_string()),
                sigil_hold_id: None,
                sigil_policy_hash: result.policy_hash.clone(),
                sigil_task_id: sigil_task_id.clone(),
                sigil_action_taken: "halted".to_string(),
                sigil_next_steps:
                    "Sigil failed closed because the signed policy requires model usage reporting. Do not continue until the adapter reports provider usage metadata for this task."
                        .to_string(),
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
            sigil_task_id,
            sigil_action_taken: "halted".to_string(),
            sigil_next_steps: format!(
                "The action \"{action}\" was blocked. Do not retry until the operator reviews the Sigil decision."
            ),
        },
    }
}
