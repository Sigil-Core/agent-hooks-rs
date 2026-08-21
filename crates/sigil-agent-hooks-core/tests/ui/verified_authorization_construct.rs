use sigil_agent_hooks_core::VerifiedAuthorization;

fn main() {
    let _forged = VerifiedAuthorization {
        intent_hash: "0".repeat(64),
        policy_hash: "0".repeat(64),
        _private: (),
    };
}
