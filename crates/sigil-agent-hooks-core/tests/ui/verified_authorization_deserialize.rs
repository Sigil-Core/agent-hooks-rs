use sigil_agent_hooks_core::VerifiedAuthorization;

fn main() {
    let _: VerifiedAuthorization = serde_json::from_str(
        r#"{"intent_hash":"00","policy_hash":"00"}"#,
    )
    .unwrap();
}
