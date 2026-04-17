use sigil_agent_hooks_core::{
    SIGIL_UNREACHABLE, SigilDecision, SigilResult, build_rejection_context,
};

#[test]
fn pending_rejection_context_includes_hold_guidance() {
    let result = SigilResult {
        decision: SigilDecision::Pending,
        hold_id: Some("hold_123".to_string()),
        message: Some("Requires approval".to_string()),
        ..SigilResult::default()
    };

    let rejection = build_rejection_context(&result, "email.send");
    assert_eq!(rejection.sigil_decision, "PENDING");
    assert_eq!(rejection.sigil_hold_id.as_deref(), Some("hold_123"));
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

    let rejection = build_rejection_context(&result, "bash");
    assert_eq!(rejection.sigil_error_code, SIGIL_UNREACHABLE);
    assert!(rejection.sigil_next_steps.contains("transient"));
    assert!(rejection.sigil_next_steps.contains("retry"));
}
