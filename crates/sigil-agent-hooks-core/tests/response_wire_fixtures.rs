use sha2::{Digest, Sha256};
use sigil_agent_hooks_core::{parse_compiled_response_policy_format1, parse_response_decision_v1};
use std::{fs, path::PathBuf};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contract-fixtures/response-v1")
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    fs::read(fixture_root().join(name)).expect("fixture must exist")
}

fn canonical_fixture_bytes(name: &str) -> Vec<u8> {
    let mut bytes = fixture_bytes(name);
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    bytes
}

#[test]
fn response_fixture_hashes_match_sha256sums_file() {
    let checksums = fs::read_to_string(fixture_root().join("SHA256SUMS"))
        .expect("checksum manifest must exist");
    for line in checksums.lines().filter(|line| !line.trim().is_empty()) {
        let (expected, file_name) = line.split_once("  ").expect("valid checksum line");
        let actual = format!("{:x}", Sha256::digest(fixture_bytes(file_name)));
        assert_eq!(actual, expected, "checksum mismatch for {file_name}");
    }
}

#[test]
fn upstream_phase_zero_receipts_are_pinned_exactly() {
    let pins = String::from_utf8(fixture_bytes("UPSTREAM_PINS")).expect("UTF-8 pins");
    assert!(pins.contains(
        "P0_FIXTURES_SHA256=550ba93f9628c133cbdbcd37be53e0f6e4d81f931d8d96c08bf70f257c376afe"
    ));
    assert!(pins.contains(
        "P0_ENVELOPE_SHA256=723a84d4ec24db45316503724eadf8e5fd67b77a75b086e1cabf8b143df9c5f2"
    ));
    assert!(pins.contains(
        "P0_INTENT_SHA256=a836e3d66b537937708a5891a9fa7d3d81aec6fa480b80aa012f06c63a104814"
    ));
}

#[test]
fn format1_payload_parses_and_reserializes_byte_identically() {
    let bytes = canonical_fixture_bytes("format1-payload.json");
    let payload = parse_compiled_response_policy_format1(&bytes).expect("valid format 1");
    assert_eq!(payload.canonical_bytes().expect("canonical bytes"), bytes);
}

#[test]
fn format1_decisions_parse_and_reserialize_byte_identically() {
    for name in ["format1-decision-allow.json", "format1-decision-block.json"] {
        let bytes = canonical_fixture_bytes(name);
        let decision = parse_response_decision_v1(&bytes).expect("valid decision v1");
        assert_eq!(
            decision.canonical_bytes().expect("canonical bytes"),
            bytes,
            "{name}"
        );
    }
}

#[test]
fn format2_and_unknown_members_fail_closed() {
    assert!(
        parse_compiled_response_policy_format1(&fixture_bytes("negative-format2-payload.json"))
            .is_err()
    );
    assert!(
        parse_compiled_response_policy_format1(&fixture_bytes(
            "negative-payload-unknown-member.json"
        ))
        .is_err()
    );
    assert!(
        parse_response_decision_v1(&fixture_bytes("negative-decision-unknown-member.json"))
            .is_err()
    );
}

#[test]
fn canonical_source_fixture_is_release_1_policy_22() {
    let source = String::from_utf8(fixture_bytes("policy-2.2-source.md")).expect("UTF-8 source");
    assert!(source.starts_with("version: 2.2.0\n"));
    assert!(source.contains("response.web_fetch_tools: example.fetch"));
    assert!(source.contains("response.deterministic_ruleset: sof-response-rules-v1"));
}
