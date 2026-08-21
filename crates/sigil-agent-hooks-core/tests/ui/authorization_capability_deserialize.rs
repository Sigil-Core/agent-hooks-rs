use sigil_agent_hooks_core::AuthorizationCapability;

fn main() {
    let _: AuthorizationCapability = serde_json::from_str(r#"{}"#).unwrap();
}
