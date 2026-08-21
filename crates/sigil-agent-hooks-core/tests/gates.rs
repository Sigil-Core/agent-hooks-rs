use std::{fs, path::PathBuf, process::Command};

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
fn literal_gate_rejects_a_missing_flag_value() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = Command::new("node")
        .arg(root.join("scripts/decision-literal-gate.mjs"))
        .arg("--root")
        .arg("--blocking")
        .output()
        .expect("literal gate should run");

    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("--root requires a value"));
}

#[test]
fn literal_gate_ignores_explicit_non_rust_paths() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture_root = root.join("tests/gate-fixtures");
    let result = Command::new("node")
        .arg(root.join("scripts/decision-literal-gate.mjs"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--config")
        .arg("explicit-non-rust.json")
        .arg("--blocking")
        .output()
        .expect("literal gate should run");

    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&result.stdout).contains("0 violations"));
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

#[test]
fn architecture_gate_rejects_a_missing_flag_value() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = Command::new("node")
        .arg(root.join("scripts/decision-architecture-gate.mjs"))
        .arg("--root")
        .arg("--blocking")
        .output()
        .expect("architecture gate should run");

    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("--root requires a value"));
}

#[test]
fn architecture_gate_rejects_invalid_rule_set_shapes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture_root = root.join("tests/architecture-fixtures");
    for (config, expected) in [
        ("invalid-top-level.json", "configuration must be an object"),
        (
            "missing-paths.json",
            "executionPaths must be a non-empty string array",
        ),
        (
            "paths-not-array.json",
            "ruleSets[0].paths must be a non-empty string array",
        ),
    ] {
        let result = Command::new("node")
            .arg(root.join("scripts/decision-architecture-gate.mjs"))
            .arg("--root")
            .arg(&fixture_root)
            .arg("--config")
            .arg(config)
            .arg("--blocking")
            .output()
            .expect("architecture gate should run");

        assert_eq!(result.status.code(), Some(2), "config: {config}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(expected),
            "config: {config}"
        );
    }
}

#[test]
fn rust_ci_blocks_on_decision_gates_and_tracks_toolchain_configs() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workflow = fs::read_to_string(root.join(".github/workflows/rust-ci.yml"))
        .expect("Rust CI workflow should be readable");

    assert!(workflow.contains("decision-literal-gate.mjs --blocking"));
    assert!(workflow.contains("decision-architecture-gate.mjs --blocking"));
    for config in ["rust-toolchain\\.toml", "rustfmt\\.toml", "clippy\\.toml"] {
        assert!(
            workflow.contains(config),
            "missing change trigger: {config}"
        );
    }
}
