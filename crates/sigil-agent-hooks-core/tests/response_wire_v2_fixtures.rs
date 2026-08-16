use sha2::{Digest, Sha256};
use sigil_agent_hooks_core::{
    ResponseClass, ResponseDecisionReasonV2, ResponseDispositionV2, ResponseFindingSourceV2,
    ScannerEvidenceFailed, ScannerEvidenceNoResult, ScannerEvidenceV1, ScannerFailedStatus,
    ScannerFailureReason, ScannerNoResultStatus, parse_compiled_response_policy_format1,
    parse_compiled_response_policy_format2, parse_response_decision_v1, parse_response_decision_v2,
};
use std::{fs, path::PathBuf};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contract-fixtures/response-v2")
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
fn response_v2_fixture_hashes_match_sha256sums_file() {
    let checksums = fs::read_to_string(fixture_root().join("SHA256SUMS"))
        .expect("checksum manifest must exist");
    for line in checksums.lines().filter(|line| !line.trim().is_empty()) {
        let (expected, file_name) = line.split_once("  ").expect("valid checksum line");
        let actual = format!("{:x}", Sha256::digest(fixture_bytes(file_name)));
        assert_eq!(actual, expected, "checksum mismatch for {file_name}");
    }
}

#[test]
fn release_2_candidate_inputs_are_pinned_exactly() {
    let pins = String::from_utf8(fixture_bytes("UPSTREAM_PINS")).expect("UTF-8 pins");
    for expected in [
        "R2_WARRANT_CORE_BASE_HEAD=3f04df5ea7c9585702133fbcc178f1d86bf042fb",
        "R2_WARRANT_CORE_DIFF_SHA256=f080e6d448a40c931cf56feac78e8f4782286ffb21403f49601edd32958cdd88",
        "R2_WARRANT_CORE_PACK_SHA256=d26f35f1c8873c46c8506cf28b59b006ec22097cadadd06ec0c0a9da3bd34d82",
        "R2_AGENT_HOOKS_BASE_HEAD=ad37b082da0370fbd600ddfbb369943a32beadea",
        "R2_AGENT_HOOKS_CANDIDATE_DIFF_SHA256=c28e4e65af81c8a1f40734d216354474dd5dfa0ae5d9b6350e3678976c1948a1",
    ] {
        assert!(pins.contains(expected), "missing exact pin {expected}");
    }
}

#[test]
fn format2_payload_parses_and_reserializes_byte_identically() {
    let bytes = canonical_fixture_bytes("format2-payload.json");
    let payload = parse_compiled_response_policy_format2(&bytes).expect("valid format 2");
    assert_eq!(payload.canonical_bytes().expect("canonical bytes"), bytes);
}

#[test]
fn format2_decisions_parse_and_reserialize_byte_identically() {
    for name in [
        "format2-decision-redact.json",
        "format2-decision-observe.json",
    ] {
        let bytes = canonical_fixture_bytes(name);
        let decision = parse_response_decision_v2(&bytes).expect("valid decision v2");
        assert_eq!(
            decision.canonical_bytes().expect("canonical bytes"),
            bytes,
            "{name}"
        );
    }
}

#[test]
fn format2_contract_preserves_scanner_redaction_and_observe_metadata() {
    let redact =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-redact.json"))
            .expect("valid redact decision");
    assert_eq!(redact.disposition, ResponseDispositionV2::Redact);
    assert_eq!(redact.reason, ResponseDecisionReasonV2::Redaction);
    assert_eq!(redact.redactions.len(), 1);
    assert!(matches!(
        redact.scanner_evidence,
        ScannerEvidenceV1::Verified(_)
    ));

    let observe =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-observe.json"))
            .expect("valid observe decision");
    assert_eq!(observe.disposition, ResponseDispositionV2::Allow);
    assert!(observe.observe.active);
    assert_eq!(observe.observe.finding_count, 1);
    assert!(observe.findings[0].observed);
}

#[test]
fn versions_and_unknown_members_fail_closed_without_downgrade() {
    assert!(
        parse_compiled_response_policy_format1(&fixture_bytes("format2-payload.json")).is_err()
    );
    assert!(
        parse_compiled_response_policy_format2(&fixture_bytes(
            "../response-v1/format1-payload.json"
        ))
        .is_err()
    );
    assert!(
        parse_compiled_response_policy_format2(&fixture_bytes(
            "negative-payload-unknown-member.json"
        ))
        .is_err()
    );
    assert!(parse_response_decision_v1(&fixture_bytes("format2-decision-observe.json")).is_err());
    assert!(
        parse_response_decision_v2(&fixture_bytes("negative-decision-unknown-member.json"))
            .is_err()
    );
}

#[test]
fn format2_rejects_hostile_schema_and_contradictory_decisions() {
    let mut policy =
        parse_compiled_response_policy_format2(&canonical_fixture_bytes("format2-payload.json"))
            .expect("valid policy");
    policy.format_version = 1;
    assert!(policy.canonical_bytes().is_err());

    let mut decision =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-redact.json"))
            .expect("valid decision");
    let mut overlap = decision.redactions[0].clone();
    overlap.start = decision.redactions[0].end - 1;
    overlap.end = decision.redactions[0].end + 4;
    decision.redactions.push(overlap);
    assert!(decision.canonical_bytes().is_err());
    decision.redactions.pop();
    decision.disposition = ResponseDispositionV2::Allow;
    assert!(decision.canonical_bytes().is_err());

    let mut block_redaction_reason =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-redact.json"))
            .expect("valid decision");
    block_redaction_reason.disposition = ResponseDispositionV2::Block;
    block_redaction_reason.redactions.clear();
    block_redaction_reason.redaction_plan_digest = None;
    assert!(block_redaction_reason.canonical_bytes().is_err());

    let mut required_scanner_failure =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-observe.json"))
            .expect("valid decision");
    required_scanner_failure.scanner_evidence = ScannerEvidenceV1::Failed(ScannerEvidenceFailed {
        status: ScannerFailedStatus::Failed,
        reason: ScannerFailureReason::Transport,
        required: true,
    });
    assert!(required_scanner_failure.canonical_bytes().is_err());
    required_scanner_failure.disposition = ResponseDispositionV2::Block;
    required_scanner_failure.reason = ResponseDecisionReasonV2::ScannerFailure;
    assert!(required_scanner_failure.canonical_bytes().is_err());
    required_scanner_failure.findings.clear();
    required_scanner_failure.observe.finding_count = 0;
    assert!(required_scanner_failure.canonical_bytes().is_ok());

    let mut unverified_scanner_finding =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-redact.json"))
            .expect("valid decision");
    unverified_scanner_finding.scanner_evidence =
        ScannerEvidenceV1::NoResult(ScannerEvidenceNoResult {
            status: ScannerNoResultStatus::SkippedTerminal,
        });
    assert!(unverified_scanner_finding.canonical_bytes().is_err());

    let mut mismatched_ruleset =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-redact.json"))
            .expect("valid decision");
    mismatched_ruleset.findings[0].ruleset_version = "different-ruleset".to_string();
    assert!(mismatched_ruleset.canonical_bytes().is_err());

    let mut deterministic_ruleset =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-observe.json"))
            .expect("valid decision");
    deterministic_ruleset.findings[0].source = ResponseFindingSourceV2::Deterministic;
    deterministic_ruleset.findings[0].confidence = None;
    assert!(deterministic_ruleset.canonical_bytes().is_err());

    let mut scanner_block =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-observe.json"))
            .expect("valid decision");
    scanner_block.disposition = ResponseDispositionV2::Block;
    scanner_block.reason = ResponseDecisionReasonV2::ScannerBlock;
    assert!(scanner_block.canonical_bytes().is_err());

    let mut observed_scanner_block = scanner_block.clone();
    observed_scanner_block.findings[0].qualified = true;
    assert!(observed_scanner_block.canonical_bytes().is_err());

    let mut scanner_failure = scanner_block.clone();
    scanner_failure.reason = ResponseDecisionReasonV2::ScannerFailure;
    assert!(scanner_failure.canonical_bytes().is_err());

    let mut arbitrary_redaction =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-redact.json"))
            .expect("valid decision");
    arbitrary_redaction.redactions[0].evidence_digests[0] = "d".repeat(64);
    assert!(arbitrary_redaction.canonical_bytes().is_err());

    let mut observed_redaction_evidence =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-redact.json"))
            .expect("valid decision");
    observed_redaction_evidence.findings[0].observed = true;
    observed_redaction_evidence.observe.classes =
        vec![ResponseClass::PromptInjection, ResponseClass::Secret];
    observed_redaction_evidence.observe.finding_count = 1;
    assert!(observed_redaction_evidence.canonical_bytes().is_err());

    let mut unsupported_redaction_class =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-redact.json"))
            .expect("valid decision");
    unsupported_redaction_class.redactions[0].classes =
        vec![ResponseClass::Pii, ResponseClass::Secret];
    assert!(unsupported_redaction_class.canonical_bytes().is_err());

    let mut partial_redaction =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-redact.json"))
            .expect("valid decision");
    partial_redaction.redactions[0].start += 1;
    partial_redaction.redactions[0].end -= 1;
    assert!(partial_redaction.canonical_bytes().is_err());

    let mut uncovered_redaction =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-redact.json"))
            .expect("valid decision");
    let mut uncovered_finding = uncovered_redaction.findings[0].clone();
    uncovered_finding.start = 32;
    uncovered_finding.end = 40;
    uncovered_finding.evidence_digest = "c".repeat(64);
    uncovered_finding.rule_id = "scanner:operator-scanner-1:1".to_string();
    uncovered_redaction.findings.push(uncovered_finding);
    if let ScannerEvidenceV1::Verified(evidence) = &mut uncovered_redaction.scanner_evidence {
        evidence.finding_count = 2;
    }
    assert!(uncovered_redaction.canonical_bytes().is_err());

    let mut inactive_observation =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-observe.json"))
            .expect("valid decision");
    inactive_observation.observe.active = false;
    assert!(inactive_observation.canonical_bytes().is_err());

    let mut unrelated_observation =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-observe.json"))
            .expect("valid decision");
    unrelated_observation.observe.classes = vec![ResponseClass::Secret];
    assert!(unrelated_observation.canonical_bytes().is_err());

    let mut skipped_allow =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-observe.json"))
            .expect("valid decision");
    skipped_allow.findings.clear();
    skipped_allow.observe.finding_count = 0;
    skipped_allow.scanner_evidence = ScannerEvidenceV1::NoResult(ScannerEvidenceNoResult {
        status: ScannerNoResultStatus::SkippedTerminal,
    });
    assert!(skipped_allow.canonical_bytes().is_err());

    let mut active_expired = skipped_allow.clone();
    active_expired.scanner_evidence = ScannerEvidenceV1::NoResult(ScannerEvidenceNoResult {
        status: ScannerNoResultStatus::NotConfigured,
    });
    active_expired.disposition = ResponseDispositionV2::Block;
    active_expired.reason = ResponseDecisionReasonV2::ObserveExpired;
    assert!(active_expired.canonical_bytes().is_err());
    active_expired.observe.active = false;
    assert!(active_expired.canonical_bytes().is_ok());

    let mut inactive_allow =
        parse_response_decision_v2(&canonical_fixture_bytes("format2-decision-observe.json"))
            .expect("valid decision");
    inactive_allow.observe.active = false;
    inactive_allow.observe.finding_count = 0;
    inactive_allow.findings[0].observed = false;
    assert!(inactive_allow.canonical_bytes().is_err());
}

#[test]
fn canonical_source_fixture_is_release_2_policy_23() {
    let source = String::from_utf8(fixture_bytes("policy-2.3-source.md")).expect("UTF-8 source");
    assert!(source.starts_with("version: 2.3.0\n"));
    assert!(source.contains("response.redact_classes: pii, secret"));
    assert!(source.contains("response.scanner.required: true"));
    assert!(source.contains("response.observe_classes: prompt_injection"));
}
