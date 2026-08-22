use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sigil_agent_hooks_core::{
    AuthorizationVerificationContext, DecisionJwk, DecisionSurface, DecisionVerificationMode,
    DecisionVerificationReason, SigilClient, SigilDecision, normalize_decision_literal,
};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureContext {
    sign_origin: String,
    tx_commit: String,
    request_nonce: String,
    expected_policy_hash: String,
    now_unix_seconds: i64,
    attestation_issuer: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureVector {
    id: String,
    status: String,
    decision_record: Option<String>,
    attestation: Option<String>,
    surface: Option<String>,
    execution: Option<bool>,
    key_set: Option<String>,
    expected: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MalformedJoseVector {
    id: String,
    source: String,
    mutation: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecisionFixture {
    minimum_vector_count: usize,
    minimum_malformed_jose_vector_count: usize,
    public_jwk: DecisionJwk,
    rotation_public_jwk: DecisionJwk,
    context: FixtureContext,
    tokens: HashMap<String, String>,
    malformed_jose_vectors: Vec<MalformedJoseVector>,
    vectors: Vec<FixtureVector>,
}

fn fixture() -> DecisionFixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contract-fixtures/v1/decision-records.json");
    serde_json::from_slice(&fs::read(path).expect("fixture bytes")).expect("fixture JSON")
}

fn surface(value: Option<&str>) -> DecisionSurface {
    match value.unwrap_or("authorize") {
        "authorize" => DecisionSurface::Authorize,
        "test_run" => DecisionSurface::TestRun,
        "hold_resolve" => DecisionSurface::HoldResolve,
        value => panic!("unknown fixture surface {value}"),
    }
}

fn body(fixture: &DecisionFixture, vector: &FixtureVector) -> Value {
    let mut body = Map::new();
    body.insert("status".to_string(), Value::String(vector.status.clone()));
    if let Some(token) = vector.decision_record.as_ref() {
        body.insert(
            "decision_record".to_string(),
            Value::String(fixture.tokens[token].clone()),
        );
    }
    if let Some(token) = vector.attestation.as_ref() {
        body.insert(
            "intent_attestation".to_string(),
            Value::String(fixture.tokens[token].clone()),
        );
    }
    if vector.status == "PENDING" {
        body.insert(
            "hold_id".to_string(),
            Value::String("hold-fixture-1".to_string()),
        );
    }
    Value::Object(body)
}

fn client(
    fixture: &DecisionFixture,
    mode: DecisionVerificationMode,
    rotation: bool,
) -> SigilClient {
    SigilClient::builder("sk_fixture")
        .api_url(&fixture.context.sign_origin)
        .decision_verification_mode(mode)
        .expected_policy_hash(&fixture.context.expected_policy_hash)
        .decision_record_jwk(if rotation {
            fixture.rotation_public_jwk.clone()
        } else {
            fixture.public_jwk.clone()
        })
        .attestation_issuer(&fixture.context.attestation_issuer)
        .build()
        .expect("fixture client")
}

fn client_without_policy_pin(
    fixture: &DecisionFixture,
    mode: DecisionVerificationMode,
) -> SigilClient {
    SigilClient::builder("sk_fixture")
        .api_url(&fixture.context.sign_origin)
        .decision_verification_mode(mode)
        .decision_record_jwk(fixture.public_jwk.clone())
        .attestation_issuer(&fixture.context.attestation_issuer)
        .build()
        .expect("fixture client without policy pin")
}

fn context(fixture: &DecisionFixture, vector: &FixtureVector) -> AuthorizationVerificationContext {
    AuthorizationVerificationContext {
        tx_commit: fixture.context.tx_commit.clone(),
        request_nonce: fixture.context.request_nonce.clone(),
        surface: surface(vector.surface.as_deref()),
        execution: vector.execution.unwrap_or(true),
        now_unix_seconds: Some(fixture.context.now_unix_seconds),
    }
}

fn expected_decision(value: &str) -> SigilDecision {
    normalize_decision_literal(value).expect("expected fixture decision")
}

#[test]
fn canonical_serializer_and_permanent_input_alias_are_distinct() {
    assert_eq!(
        serde_json::to_string(&SigilDecision::Allowed).expect("serialize"),
        "\"ALLOWED\""
    );
    assert_eq!(
        serde_json::from_str::<SigilDecision>("\"APPROVED\"").expect("alias"),
        SigilDecision::Allowed
    );
    #[allow(deprecated)]
    {
        assert_eq!(SigilDecision::Approved, SigilDecision::Allowed);
        assert_eq!(
            serde_json::to_string(&SigilDecision::Approved).expect("legacy source alias"),
            "\"ALLOWED\""
        );
    }
    assert!(serde_json::from_str::<SigilDecision>("\"ALLOW\"").is_err());
}

#[tokio::test]
async fn reports_advisory_median_verification_latency() {
    let fixture = fixture();
    let vector = fixture
        .vectors
        .iter()
        .find(|vector| vector.id == "valid_allowed")
        .expect("valid vector");
    let client = client(&fixture, DecisionVerificationMode::Enforce, false);
    let body = body(&fixture, vector);
    let context = context(&fixture, vector);
    let mut durations = Vec::with_capacity(1_000);

    for _ in 0..1_000 {
        let started = Instant::now();
        let result = client.verify_authorization_response(&body, &context).await;
        durations.push(started.elapsed());
        assert!(result.permits_execution());
    }
    durations.sort_unstable();
    let median = durations[durations.len() / 2];
    eprintln!(
        "decision_verification_median_ms={:.3} samples=1000 target_ms=5 advisory=true target_met={}",
        median.as_secs_f64() * 1_000.0,
        median < Duration::from_millis(5)
    );
}

#[tokio::test]
async fn warn_mode_verifies_a_valid_signed_response_without_an_optional_policy_pin() {
    let fixture = fixture();
    let vector = fixture
        .vectors
        .iter()
        .find(|vector| vector.id == "valid_allowed")
        .expect("valid vector");
    let result = client_without_policy_pin(&fixture, DecisionVerificationMode::Warn)
        .verify_authorization_response(&body(&fixture, vector), &context(&fixture, vector))
        .await;

    assert_eq!(result.reason, None);
    assert!(result.is_verified());
    assert!(result.permits_execution());
    assert_eq!(
        result.verified_policy_hash(),
        Some(fixture.context.expected_policy_hash.as_str())
    );
}

#[tokio::test]
async fn shared_decision_vectors_match_the_typescript_contract() {
    let fixture = fixture();
    assert!(fixture.vectors.len() >= fixture.minimum_vector_count);
    assert!(fixture.malformed_jose_vectors.len() >= fixture.minimum_malformed_jose_vector_count);
    for vector in fixture
        .vectors
        .iter()
        .filter(|vector| vector.expected.get("decision").is_some())
    {
        let result = client(
            &fixture,
            DecisionVerificationMode::Enforce,
            vector.key_set.as_deref() == Some("rotation_overlap"),
        )
        .verify_authorization_response(&body(&fixture, vector), &context(&fixture, vector))
        .await;
        let expected = vector.expected["decision"]
            .as_str()
            .expect("expected decision");
        assert_eq!(
            result.decision,
            expected_decision(expected),
            "decision vector {}",
            vector.id
        );
        assert_eq!(
            result.reason.map(DecisionVerificationReason::as_str),
            vector.expected.get("reason").and_then(Value::as_str),
            "reason vector {}",
            vector.id
        );
        assert_eq!(
            result.is_verified(),
            vector.expected.get("capability").and_then(Value::as_str) == Some("verified"),
            "capability vector {}",
            vector.id
        );
        let expected_policy_hash = result
            .is_verified()
            .then_some(fixture.context.expected_policy_hash.as_str());
        assert_eq!(
            result.verified_policy_hash(),
            expected_policy_hash,
            "verified policy hash vector {}",
            vector.id
        );
    }
}

#[tokio::test]
async fn shared_mode_specific_vectors_match_the_typescript_contract() {
    let fixture = fixture();
    for vector in fixture
        .vectors
        .iter()
        .filter(|vector| vector.expected.get("enforceDecision").is_some())
    {
        for (mode, decision_key, capability_key) in [
            (
                DecisionVerificationMode::Warn,
                "warnDecision",
                "warnCapability",
            ),
            (
                DecisionVerificationMode::Enforce,
                "enforceDecision",
                "enforceCapability",
            ),
        ] {
            let result = client(&fixture, mode, false)
                .verify_authorization_response(&body(&fixture, vector), &context(&fixture, vector))
                .await;
            let expected = vector.expected[decision_key]
                .as_str()
                .expect("expected mode-specific decision");
            assert_eq!(
                result.decision,
                expected_decision(expected),
                "{mode:?} decision vector {}",
                vector.id
            );
            assert_eq!(
                result.reason.map(DecisionVerificationReason::as_str),
                vector.expected.get("reason").and_then(Value::as_str),
                "{mode:?} reason vector {}",
                vector.id
            );
            assert_eq!(
                result.is_legacy_unverified(),
                vector.expected.get(capability_key).and_then(Value::as_str)
                    == Some("legacy-unverified"),
                "{mode:?} capability vector {}",
                vector.id
            );
            assert!(!result.is_verified(), "{mode:?} vector {}", vector.id);
        }
    }
}

#[tokio::test]
async fn warn_mode_never_counterfeits_the_verified_capability() {
    let fixture = fixture();
    for id in ["legacy_missing_record", "tampered_signature"] {
        let vector = fixture
            .vectors
            .iter()
            .find(|vector| vector.id == id)
            .expect("warn vector");
        let result = client(&fixture, DecisionVerificationMode::Warn, false)
            .verify_authorization_response(&body(&fixture, vector), &context(&fixture, vector))
            .await;
        assert_eq!(result.decision, SigilDecision::Allowed);
        assert!(result.permits_execution());
        assert!(result.is_legacy_unverified());
        assert!(!result.is_verified());
    }
}

#[tokio::test]
async fn enforce_mode_kills_the_unsigned_legacy_branch() {
    let fixture = fixture();
    let vector = fixture
        .vectors
        .iter()
        .find(|vector| vector.id == "legacy_missing_record")
        .expect("legacy vector");
    let result = client(&fixture, DecisionVerificationMode::Enforce, false)
        .verify_authorization_response(&body(&fixture, vector), &context(&fixture, vector))
        .await;
    assert_eq!(result.decision, SigilDecision::Denied);
    assert_eq!(
        result.reason,
        Some(DecisionVerificationReason::RecordMissing)
    );
    assert!(!result.permits_execution());
}

fn mutate_token(fixture: &DecisionFixture, vector: &MalformedJoseVector) -> String {
    let token = &fixture.tokens[&vector.source];
    let segments: Vec<&str> = token.split('.').collect();
    match vector.mutation.as_str() {
        "append_segment" => format!("{token}.extra"),
        "pad_header" => format!("{}=.{}.{}", segments[0], segments[1], segments[2]),
        "invalid_header_character" => format!("!{}", &token[1..]),
        "oversize" => format!("{token}{}", "x".repeat(8 * 1024)),
        "extra_header" => {
            let header = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({
                    "alg": "EdDSA",
                    "kid": fixture.public_jwk.kid,
                    "typ": "sof-decision+jws",
                    "crit": ["b64"]
                }))
                .expect("header JSON"),
            );
            format!("{header}.{}.{}", segments[1], segments[2])
        }
        "duplicate_header" => {
            let header = URL_SAFE_NO_PAD.encode(format!(
                "{{\"alg\":\"EdDSA\",\"alg\":\"none\",\"kid\":\"{}\",\"typ\":\"sof-decision+jws\"}}",
                fixture.public_jwk.kid
            ));
            format!("{header}.{}.{}", segments[1], segments[2])
        }
        mutation => panic!("unknown mutation {mutation}"),
    }
}

#[tokio::test]
async fn shared_malformed_jose_vectors_fail_closed() {
    let fixture = fixture();
    let valid = fixture
        .vectors
        .iter()
        .find(|vector| vector.id == "valid_allowed")
        .expect("valid vector");
    for vector in &fixture.malformed_jose_vectors {
        let body = json!({
            "status": "ALLOWED",
            "decision_record": mutate_token(&fixture, vector),
            "intent_attestation": fixture.tokens["attestation"],
        });
        let result = client(&fixture, DecisionVerificationMode::Enforce, false)
            .verify_authorization_response(&body, &context(&fixture, valid))
            .await;
        assert_eq!(
            result.reason,
            Some(DecisionVerificationReason::Malformed),
            "malformed vector {}",
            vector.id
        );
        assert!(!result.permits_execution());
    }
}

#[tokio::test]
async fn wave3_enforce_batch_has_zero_unexpected_or_legacy_outcomes() {
    let fixture = fixture();
    let valid_ids = [
        "valid_allowed",
        "alias_approved_input",
        "valid_denied",
        "valid_pending",
        "valid_test_run",
        "valid_hold_resolve",
        "valid_rotation_overlap",
    ];
    let mut unexpected_verification_failures = 0usize;
    let mut tamper_accepts = 0usize;
    let mut legacy_path_fallbacks = 0usize;
    let mut reason_code_mismatches = 0usize;
    let mut negative_decision_mismatches = 0usize;

    for vector in &fixture.vectors {
        let is_valid = valid_ids.contains(&vector.id.as_str());
        let result = client(
            &fixture,
            DecisionVerificationMode::Enforce,
            vector.key_set.as_deref() == Some("rotation_overlap"),
        )
        .verify_authorization_response(&body(&fixture, vector), &context(&fixture, vector))
        .await;
        let expected = vector
            .expected
            .get("decision")
            .or_else(|| vector.expected.get("enforceDecision"))
            .and_then(Value::as_str)
            .expect("enforce decision expectation");
        let expected_reason = vector.expected.get("reason").and_then(Value::as_str);

        if is_valid && (result.decision != expected_decision(expected) || result.reason.is_some()) {
            unexpected_verification_failures += 1;
        }
        if !is_valid && result.permits_execution() {
            tamper_accepts += 1;
        }
        if result.is_legacy_unverified() {
            legacy_path_fallbacks += 1;
        }
        if result.reason.map(DecisionVerificationReason::as_str) != expected_reason {
            reason_code_mismatches += 1;
        }
        if !is_valid && result.decision != SigilDecision::Denied {
            negative_decision_mismatches += 1;
        }
    }

    let valid = fixture
        .vectors
        .iter()
        .find(|vector| vector.id == "valid_allowed")
        .expect("valid vector");
    for vector in &fixture.malformed_jose_vectors {
        let malformed_body = json!({
            "status": "ALLOWED",
            "decision_record": mutate_token(&fixture, vector),
            "intent_attestation": fixture.tokens["attestation"],
        });
        let result = client(&fixture, DecisionVerificationMode::Enforce, false)
            .verify_authorization_response(&malformed_body, &context(&fixture, valid))
            .await;
        if result.permits_execution() {
            tamper_accepts += 1;
        }
        if result.is_legacy_unverified() {
            legacy_path_fallbacks += 1;
        }
        if result.reason != Some(DecisionVerificationReason::Malformed) {
            reason_code_mismatches += 1;
        }
        if result.decision != SigilDecision::Denied {
            negative_decision_mismatches += 1;
        }
    }

    let receipt = json!({
        "schema": "sigil-agent-hooks-rs-enforcement-batch/v1",
        "consumerVersion": "0.5.0",
        "mode": "enforce",
        "totalCases": fixture.vectors.len() + fixture.malformed_jose_vectors.len(),
        "validCases": valid_ids.len(),
        "negativeCases": fixture.vectors.len() + fixture.malformed_jose_vectors.len() - valid_ids.len(),
        "unexpectedVerificationFailures": unexpected_verification_failures,
        "tamperAccepts": tamper_accepts,
        "legacyPathFallbacks": legacy_path_fallbacks,
        "reasonCodeMismatches": reason_code_mismatches,
        "negativeDecisionMismatches": negative_decision_mismatches,
    });
    eprintln!("{receipt}");

    assert_eq!(fixture.vectors.len(), 23);
    assert_eq!(fixture.malformed_jose_vectors.len(), 6);
    assert_eq!(unexpected_verification_failures, 0);
    assert_eq!(tamper_accepts, 0);
    assert_eq!(legacy_path_fallbacks, 0);
    assert_eq!(reason_code_mismatches, 0);
    assert_eq!(negative_decision_mismatches, 0);
}

#[tokio::test]
async fn wave3_clock_skew_drill_accepts_thirty_seconds_and_rejects_thirty_one() {
    let fixture = fixture();
    let vector = fixture
        .vectors
        .iter()
        .find(|vector| vector.id == "valid_allowed")
        .expect("valid vector");
    let client = client(&fixture, DecisionVerificationMode::Enforce, false);
    let response = body(&fixture, vector);

    for now in [1_999_999_970, 2_000_000_090] {
        let mut verification_context = context(&fixture, vector);
        verification_context.now_unix_seconds = Some(now);
        let result = client
            .verify_authorization_response(&response, &verification_context)
            .await;
        assert_eq!(result.reason, None, "boundary now={now}");
        assert!(result.permits_execution(), "boundary now={now}");
    }

    for now in [1_999_999_969, 2_000_000_091] {
        let mut verification_context = context(&fixture, vector);
        verification_context.now_unix_seconds = Some(now);
        let result = client
            .verify_authorization_response(&response, &verification_context)
            .await;
        assert_eq!(
            result.reason,
            Some(DecisionVerificationReason::Expired),
            "outside boundary now={now}"
        );
        assert!(!result.permits_execution(), "outside boundary now={now}");
    }
}

#[tokio::test]
async fn wave3_tamper_and_oversize_token_drill_fails_closed() {
    let fixture = fixture();
    let valid = fixture
        .vectors
        .iter()
        .find(|vector| vector.id == "valid_allowed")
        .expect("valid vector");
    let tampered = fixture
        .vectors
        .iter()
        .find(|vector| vector.id == "tampered_signature")
        .expect("tamper vector");
    let tampered_result = client(&fixture, DecisionVerificationMode::Enforce, false)
        .verify_authorization_response(&body(&fixture, tampered), &context(&fixture, tampered))
        .await;
    assert_eq!(
        tampered_result.reason,
        Some(DecisionVerificationReason::Signature)
    );
    assert!(!tampered_result.permits_execution());

    let oversized = fixture
        .malformed_jose_vectors
        .iter()
        .find(|vector| vector.mutation == "oversize")
        .expect("oversize vector");
    let oversized_body = json!({
        "status": "ALLOWED",
        "decision_record": mutate_token(&fixture, oversized),
        "intent_attestation": fixture.tokens["attestation"],
    });
    let oversized_result = client(&fixture, DecisionVerificationMode::Enforce, false)
        .verify_authorization_response(&oversized_body, &context(&fixture, valid))
        .await;
    assert_eq!(
        oversized_result.reason,
        Some(DecisionVerificationReason::Malformed)
    );
    assert!(!oversized_result.permits_execution());
}
