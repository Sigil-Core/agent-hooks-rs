use sigil_agent_hooks_core::{
    SIGIL_MODEL_SPEND_LIMIT_EXCEEDED, SIGIL_MODEL_TOKEN_LIMIT_EXCEEDED,
    SIGIL_MODEL_USAGE_UNAVAILABLE, SIGIL_UNREACHABLE, SigilDecision, SigilResult,
    build_rejection_context,
};

#[test]
fn pending_rejection_context_includes_hold_guidance() {
    let result = SigilResult {
        decision: SigilDecision::Pending,
        hold_id: Some("hold_123".to_string()),
        message: Some("Requires approval".to_string()),
        ..SigilResult::default()
    };

    let rejection = build_rejection_context(&result, "email.send", Some("task-123"));
    assert_eq!(rejection.sigil_decision, "PENDING");
    assert_eq!(rejection.sigil_hold_id.as_deref(), Some("hold_123"));
    assert_eq!(rejection.sigil_task_id.as_deref(), Some("task-123"));
    assert!(rejection.sigil_next_steps.contains("approve"));
}

#[test]
fn unreachable_rejection_context_is_transient_not_policy() {
    let result = SigilResult {
        decision: SigilDecision::Denied,
        error_code: Some(SIGIL_UNREACHABLE.to_string()),
        message: Some("connection refused".to_string()),
        ..SigilResult::default()
    };

    let rejection = build_rejection_context(&result, "bash", None);
    assert_eq!(rejection.sigil_error_code, SIGIL_UNREACHABLE);
    assert!(rejection.sigil_next_steps.contains("transient"));
    assert!(rejection.sigil_next_steps.contains("retry"));
}

#[test]
fn model_budget_rejection_context_hard_stops_model_calls() {
    for error_code in [
        SIGIL_MODEL_SPEND_LIMIT_EXCEEDED,
        SIGIL_MODEL_TOKEN_LIMIT_EXCEEDED,
    ] {
        let result = SigilResult {
            decision: SigilDecision::Denied,
            error_code: Some(error_code.to_string()),
            message: Some("model budget exceeded".to_string()),
            ..SigilResult::default()
        };

        let rejection = build_rejection_context(&result, "model.inference", Some("model-task"));
        assert_eq!(rejection.sigil_error_code, error_code);
        assert_eq!(rejection.sigil_task_id.as_deref(), Some("model-task"));
        assert!(rejection.sigil_next_steps.contains("Hard-stop"));
        assert!(
            rejection
                .sigil_next_steps
                .contains("Do not start another model call")
        );
    }
}

#[test]
fn model_usage_unavailable_context_is_fail_closed() {
    let result = SigilResult {
        decision: SigilDecision::Denied,
        error_code: Some(SIGIL_MODEL_USAGE_UNAVAILABLE.to_string()),
        message: Some("model_usage missing".to_string()),
        ..SigilResult::default()
    };

    let rejection = build_rejection_context(&result, "model.inference", None);
    assert_eq!(rejection.sigil_error_code, SIGIL_MODEL_USAGE_UNAVAILABLE);
    assert!(rejection.sigil_next_steps.contains("failed closed"));
    assert!(
        rejection
            .sigil_next_steps
            .contains("provider usage metadata")
    );
}
