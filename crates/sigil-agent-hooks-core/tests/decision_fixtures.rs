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
