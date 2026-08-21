use std::{path::PathBuf, process::Command};

#[test]
fn literal_gate_fails_on_planted_quoted_template_and_raw_string_literals() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = Command::new("node")
        .arg(root.join("scripts/decision-literal-gate.mjs"))
        .arg("--root")
        .arg(root.join("tests/gate-fixtures"))
        .arg("--blocking")
        .output()
        .expect("literal gate should run");

    assert_eq!(result.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("decision-literal-gate: 3 violation(s)"));
    assert!(stderr.contains("planted_violation.rs:1"));
    assert!(stderr.contains("planted_template_literal.rs:1"));
    assert!(stderr.contains("planted_raw_string_literal.rs:1"));
}

#[test]
fn architecture_gate_fails_on_a_forbidden_execution_import() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = Command::new("node")
        .arg(root.join("scripts/decision-architecture-gate.mjs"))
        .arg("--root")
        .arg(root.join("tests/architecture-fixtures"))
        .arg("--blocking")
        .output()
        .expect("architecture gate should run");

    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("forbidden_import.rs:1"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("forbidden_crypto.rs:1"));
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("decision-verifier-crypto-boundary:ed25519_dalek")
    );
}
