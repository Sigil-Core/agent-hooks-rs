use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::{Client, Url};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{DecisionJwk, DecisionVerificationMode, SigilClient, SigilDecision, SigilResult};

const TOKEN_MAX_BYTES: usize = 8 * 1024;
const JWKS_MAX_BYTES: usize = 64 * 1024;
const JWKS_MAX_KEYS: usize = 16;
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);
const CLOCK_SKEW_SECONDS: i64 = 30;
const CONSUMER_VERSION: &str = "0.5.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Authoritative Sign endpoint surface bound into a decision record.
pub enum DecisionSurface {
    /// The authorization endpoint that evaluates a tool intent.
    Authorize,
    /// The test-run endpoint used to evaluate a policy without execution.
    TestRun,
    /// The hold-resolution endpoint that finalizes a pending decision.
    HoldResolve,
}

impl DecisionSurface {
    /// Returns the canonical signed-record literal for this surface.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorize => "authorize",
            Self::TestRun => "test_run",
            Self::HoldResolve => "hold_resolve",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Stable reason why signed authorization verification did not succeed.
pub enum DecisionVerificationReason {
    /// The decision-record or attestation signature did not verify.
    Signature,
    /// The token validity window is outside the accepted clock skew.
    Expired,
    /// The issuer, audience, or trusted origin did not match.
    Audience,
    /// The signed endpoint surface did not match the request.
    Surface,
    /// The signed intent digest did not match the request commitment.
    IntentBinding,
    /// The signed policy digest did not match the configured policy.
    PolicyBinding,
    /// The signed nonce did not match the in-flight request.
    Nonce,
    /// The response decision literal did not match the signed decision.
    LiteralMismatch,
    /// The response did not contain a signed decision record.
    RecordMissing,
    /// No trusted verification key was available.
    KeyUnavailable,
    /// An allowed execution response omitted its intent attestation.
    AttestationMissing,
    /// The intent attestation did not match the verified decision record.
    AttestationMismatch,
    /// The response or signed token was not structurally valid.
    Malformed,
}

impl DecisionVerificationReason {
    /// Returns the stable diagnostic literal for this reason.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Expired => "expired",
            Self::Audience => "audience",
            Self::Surface => "surface",
            Self::IntentBinding => "intent_binding",
            Self::PolicyBinding => "policy_binding",
            Self::Nonce => "nonce",
            Self::LiteralMismatch => "literal_mismatch",
            Self::RecordMissing => "record_missing",
            Self::KeyUnavailable => "key_unavailable",
            Self::AttestationMissing => "attestation_missing",
            Self::AttestationMismatch => "attestation_mismatch",
            Self::Malformed => "malformed",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
/// Verified bindings carried by a non-forgeable authorization capability.
///
/// The type cannot be constructed, cloned, or deserialized by consumers.
///
/// ```compile_fail
/// use sigil_agent_hooks_core::VerifiedAuthorization;
/// let _forged = VerifiedAuthorization {
///     intent_hash: String::new(),
///     policy_hash: String::new(),
///     _private: (),
/// };
/// ```
///
/// ```compile_fail
/// use sigil_agent_hooks_core::VerifiedAuthorization;
/// fn require_clone<T: Clone>() {}
/// require_clone::<VerifiedAuthorization>();
/// ```
///
/// ```compile_fail
/// use sigil_agent_hooks_core::VerifiedAuthorization;
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<VerifiedAuthorization>();
/// ```
pub struct VerifiedAuthorization {
    intent_hash: String,
    policy_hash: String,
    _private: (),
}

impl VerifiedAuthorization {
    /// Returns the SHA-256 intent binding from the verified record.
    pub fn intent_hash(&self) -> &str {
        &self.intent_hash
    }

    /// Returns the SHA-256 policy binding from the verified record.
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LegacyUnverifiedAuthorization {
    _private: (),
}

#[derive(Debug, PartialEq, Eq)]
enum AuthorizationKind {
    Verified(VerifiedAuthorization),
    Legacy(LegacyUnverifiedAuthorization),
}

#[derive(Debug, PartialEq, Eq)]
/// Opaque authority that an execution adapter must possess before continuing.
///
/// The type cannot be constructed, cloned, or deserialized by consumers.
///
/// ```compile_fail
/// use sigil_agent_hooks_core::AuthorizationCapability;
/// let _forged = AuthorizationCapability {};
/// ```
///
/// ```compile_fail
/// use sigil_agent_hooks_core::AuthorizationCapability;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AuthorizationCapability>();
/// ```
///
/// ```compile_fail
/// use sigil_agent_hooks_core::AuthorizationCapability;
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<AuthorizationCapability>();
/// ```
pub struct AuthorizationCapability {
    kind: AuthorizationKind,
}

#[derive(Debug)]
struct CachedJwks {
    expires_at: Instant,
    keys: HashMap<String, DecisionJwk>,
}

#[derive(Debug, Default)]
pub(crate) struct JwksCache(Mutex<HashMap<String, CachedJwks>>);

#[derive(Debug, Clone, PartialEq, Eq)]
/// In-flight request data that a signed decision must match exactly.
pub struct AuthorizationVerificationContext {
    /// Exact transaction commitment whose SHA-256 digest binds the decision to
    /// this request.
    pub tx_commit: String,
    /// Consumer-generated nonce that prevents reuse on another in-flight
    /// request.
    pub request_nonce: String,
    /// Authoritative endpoint surface expected in the signed record.
    pub surface: DecisionSurface,
    /// Whether this verification can grant execution authority.
    pub execution: bool,
    /// Optional pinned Unix time used only for deterministic verification
    /// tests; production verification uses the system clock.
    pub now_unix_seconds: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
/// Decision, diagnostic, and opaque capability produced by record verification.
pub struct AuthorizationVerificationResult {
    /// Canonical decision after applying the configured verification mode.
    pub decision: SigilDecision,
    /// Verification failure reason, or `None` after successful verification.
    pub reason: Option<DecisionVerificationReason>,
    pub(crate) authorization: Option<AuthorizationCapability>,
}

impl AuthorizationVerificationResult {
    /// Returns whether this result carries execution authority.
    pub fn permits_execution(&self) -> bool {
        self.decision == SigilDecision::Allowed && self.authorization.is_some()
    }

    /// Returns whether execution authority came from verified signed artifacts.
    pub fn is_verified(&self) -> bool {
        matches!(
            self.authorization,
            Some(AuthorizationCapability {
                kind: AuthorizationKind::Verified(_),
            })
        )
    }

    /// Returns whether warn mode retained legacy, unverified authority.
    pub fn is_legacy_unverified(&self) -> bool {
        matches!(
            self.authorization,
            Some(AuthorizationCapability {
                kind: AuthorizationKind::Legacy(_),
            })
        )
    }

    /// Returns the verified policy hash without exposing the capability token.
    pub fn verified_policy_hash(&self) -> Option<&str> {
        match self.authorization.as_ref() {
            Some(AuthorizationCapability {
                kind: AuthorizationKind::Verified(capability),
            }) => Some(capability.policy_hash()),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct VerificationFailure(DecisionVerificationReason);

type VerificationResult<T> = Result<T, VerificationFailure>;

#[derive(Debug)]
struct ParsedJws {
    claims: Map<String, Value>,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
    kid: String,
}

#[derive(Debug)]
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("valid JSON without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Number::from_f64(value)
                    .map(Value::Number)
                    .map(StrictValue)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value.to_string())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                StrictValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut keys = HashSet::new();
                let mut values = Map::new();
                while let Some(key) = object.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
                    }
                    let value = object.next_value::<StrictValue>()?;
                    values.insert(key, value.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

/// Parses the frozen input decision vocabulary into the canonical Rust enum.
pub fn normalize_decision_literal(
    value: &str,
) -> Result<SigilDecision, DecisionVerificationReason> {
    match value {
        "APPROVED" | "ALLOWED" => Ok(SigilDecision::Allowed),
        "DENIED" => Ok(SigilDecision::Denied),
        "PENDING" => Ok(SigilDecision::Pending),
        _ => Err(DecisionVerificationReason::Malformed),
    }
}

/// Returns whether a result carries both an allowed decision and opaque authority.
pub fn authorization_permits_execution(result: &SigilResult) -> bool {
    result.decision == SigilDecision::Allowed && result.authorization.is_some()
}

/// Returns verified signed bindings when the result carries verified authority.
pub fn verified_authorization(result: &SigilResult) -> Option<&VerifiedAuthorization> {
    match result.authorization.as_ref() {
        Some(AuthorizationCapability {
            kind: AuthorizationKind::Verified(capability),
        }) => Some(capability),
        _ => None,
    }
}

pub(crate) fn legacy_authorization() -> AuthorizationCapability {
    AuthorizationCapability {
        kind: AuthorizationKind::Legacy(LegacyUnverifiedAuthorization { _private: () }),
    }
}

fn verified_capability(intent_hash: String, policy_hash: String) -> AuthorizationCapability {
    AuthorizationCapability {
        kind: AuthorizationKind::Verified(VerifiedAuthorization {
            intent_hash,
            policy_hash,
            _private: (),
        }),
    }
}

pub(crate) fn strict_json_value(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<Value, DecisionVerificationReason> {
    if bytes.len() > max_bytes {
        return Err(DecisionVerificationReason::Malformed);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|_| DecisionVerificationReason::Malformed)?;
    deserializer
        .end()
        .map_err(|_| DecisionVerificationReason::Malformed)?;
    Ok(value.0)
}

fn decode_segment(segment: &str) -> VerificationResult<Vec<u8>> {
    if segment.is_empty()
        || segment.contains('=')
        || !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(VerificationFailure(DecisionVerificationReason::Malformed));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| VerificationFailure(DecisionVerificationReason::Malformed))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != segment {
        return Err(VerificationFailure(DecisionVerificationReason::Malformed));
    }
    Ok(bytes)
}

fn object(value: Value) -> VerificationResult<Map<String, Value>> {
    value
        .as_object()
        .cloned()
        .ok_or(VerificationFailure(DecisionVerificationReason::Malformed))
}

fn parse_compact_jws(token: &str, profile: TokenProfile) -> VerificationResult<ParsedJws> {
    if token.len() > TOKEN_MAX_BYTES {
        return Err(VerificationFailure(DecisionVerificationReason::Malformed));
    }
    let mut segments = token.split('.');
    let encoded_header = segments
        .next()
        .ok_or(VerificationFailure(DecisionVerificationReason::Malformed))?;
    let encoded_claims = segments
        .next()
        .ok_or(VerificationFailure(DecisionVerificationReason::Malformed))?;
    let encoded_signature = segments
        .next()
        .ok_or(VerificationFailure(DecisionVerificationReason::Malformed))?;
    if segments.next().is_some() {
        return Err(VerificationFailure(DecisionVerificationReason::Malformed));
    }
    let header = object(
        strict_json_value(&decode_segment(encoded_header)?, TOKEN_MAX_BYTES)
            .map_err(VerificationFailure)?,
    )?;
    let claims = object(
        strict_json_value(&decode_segment(encoded_claims)?, TOKEN_MAX_BYTES)
            .map_err(VerificationFailure)?,
    )?;
    let expected_keys: &[&str] = match profile {
        TokenProfile::Decision => &["alg", "kid", "typ"],
        TokenProfile::Attestation => &["alg", "kid"],
    };
    if header.len() != expected_keys.len()
        || !expected_keys.iter().all(|key| header.contains_key(*key))
        || header.get("alg").and_then(Value::as_str) != Some("EdDSA")
        || (profile == TokenProfile::Decision
            && header.get("typ").and_then(Value::as_str) != Some("sof-decision+jws"))
    {
        return Err(VerificationFailure(DecisionVerificationReason::Malformed));
    }
    let kid = required_string(&header, "kid")?.to_string();
    Ok(ParsedJws {
        claims,
        signing_input: format!("{encoded_header}.{encoded_claims}").into_bytes(),
        signature: decode_segment(encoded_signature)?,
        kid,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenProfile {
    Decision,
    Attestation,
}

fn canonical_origin(input: &str) -> VerificationResult<String> {
    let url =
        Url::parse(input).map_err(|_| VerificationFailure(DecisionVerificationReason::Audience))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(VerificationFailure(DecisionVerificationReason::Audience));
    }
    Ok(url.origin().ascii_serialization())
}

pub(crate) fn validate_canonical_origin(input: &str) -> Result<String, DecisionVerificationReason> {
    canonical_origin(input).map_err(|failure| failure.0)
}

fn validate_jwk(jwk: &DecisionJwk) -> VerificationResult<()> {
    if jwk.kty != "OKP"
        || jwk.crv != "Ed25519"
        || jwk.kid.is_empty()
        || jwk.x.is_empty()
        || jwk.r#use.as_deref().is_some_and(|value| value != "sig")
        || jwk
            .key_ops
            .as_ref()
            .is_some_and(|values| !values.iter().any(|value| value == "verify"))
    {
        return Err(VerificationFailure(
            DecisionVerificationReason::KeyUnavailable,
        ));
    }
    Ok(())
}

fn parse_jwks(value: Value) -> VerificationResult<HashMap<String, DecisionJwk>> {
    let values = value
        .as_object()
        .and_then(|object| object.get("keys"))
        .and_then(Value::as_array)
        .ok_or(VerificationFailure(
            DecisionVerificationReason::KeyUnavailable,
        ))?;
    if values.is_empty() || values.len() > JWKS_MAX_KEYS {
        return Err(VerificationFailure(
            DecisionVerificationReason::KeyUnavailable,
        ));
    }
    let mut keys = HashMap::new();
    for value in values {
        let jwk: DecisionJwk = serde_json::from_value(value.clone())
            .map_err(|_| VerificationFailure(DecisionVerificationReason::KeyUnavailable))?;
        validate_jwk(&jwk)?;
        if keys.insert(jwk.kid.clone(), jwk).is_some() {
            return Err(VerificationFailure(
                DecisionVerificationReason::KeyUnavailable,
            ));
        }
    }
    Ok(keys)
}

async fn read_bounded_response(mut response: reqwest::Response) -> VerificationResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > JWKS_MAX_BYTES as u64)
    {
        return Err(VerificationFailure(
            DecisionVerificationReason::KeyUnavailable,
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| VerificationFailure(DecisionVerificationReason::KeyUnavailable))?
    {
        if bytes.len() + chunk.len() > JWKS_MAX_BYTES {
            return Err(VerificationFailure(
                DecisionVerificationReason::KeyUnavailable,
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn fetch_jwks(
    http: &Client,
    cache: &JwksCache,
    origin: &str,
    force: bool,
) -> VerificationResult<HashMap<String, DecisionJwk>> {
    if !force {
        let cache = cache
            .0
            .lock()
            .map_err(|_| VerificationFailure(DecisionVerificationReason::KeyUnavailable))?;
        if let Some(entry) = cache.get(origin)
            && entry.expires_at > Instant::now()
        {
            return Ok(entry.keys.clone());
        }
    }
    let jwks_url = format!("{origin}/.well-known/jwks.json");
    let response = http
        .get(&jwks_url)
        .send()
        .await
        .map_err(|_| VerificationFailure(DecisionVerificationReason::KeyUnavailable))?;
    if !response.status().is_success() || response.url().as_str() != jwks_url {
        return Err(VerificationFailure(
            DecisionVerificationReason::KeyUnavailable,
        ));
    }
    let bytes = read_bounded_response(response).await?;
    let value = strict_json_value(&bytes, JWKS_MAX_BYTES)
        .map_err(|_| VerificationFailure(DecisionVerificationReason::KeyUnavailable))?;
    let keys = parse_jwks(value)?;
    cache
        .0
        .lock()
        .map_err(|_| VerificationFailure(DecisionVerificationReason::KeyUnavailable))?
        .insert(
            origin.to_string(),
            CachedJwks {
                expires_at: Instant::now() + JWKS_CACHE_TTL,
                keys: keys.clone(),
            },
        );
    Ok(keys)
}

async fn resolve_jwk(
    client: &SigilClient,
    origin: &str,
    kid: &str,
) -> VerificationResult<DecisionJwk> {
    if let Some(jwk) = client.config.decision_record_jwk.as_ref() {
        validate_jwk(jwk)?;
        return (jwk.kid == kid)
            .then(|| jwk.clone())
            .ok_or(VerificationFailure(
                DecisionVerificationReason::KeyUnavailable,
            ));
    }
    let mut keys = fetch_jwks(&client.jwks_http, &client.jwks_cache, origin, false).await?;
    if let Some(jwk) = keys.remove(kid) {
        return Ok(jwk);
    }
    let mut keys = fetch_jwks(&client.jwks_http, &client.jwks_cache, origin, true).await?;
    keys.remove(kid).ok_or(VerificationFailure(
        DecisionVerificationReason::KeyUnavailable,
    ))
}

async fn verify_token(
    client: &SigilClient,
    origin: &str,
    token: &str,
    profile: TokenProfile,
) -> VerificationResult<ParsedJws> {
    let parsed = parse_compact_jws(token, profile)?;
    let jwk = resolve_jwk(client, origin, &parsed.kid).await?;
    let key_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|_| VerificationFailure(DecisionVerificationReason::KeyUnavailable))?
        .try_into()
        .map_err(|_| VerificationFailure(DecisionVerificationReason::KeyUnavailable))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| VerificationFailure(DecisionVerificationReason::KeyUnavailable))?;
    let signature = Signature::from_slice(&parsed.signature)
        .map_err(|_| VerificationFailure(DecisionVerificationReason::Signature))?;
    key.verify_strict(&parsed.signing_input, &signature)
        .map_err(|_| VerificationFailure(DecisionVerificationReason::Signature))?;
    Ok(parsed)
}

fn required_string<'a>(claims: &'a Map<String, Value>, name: &str) -> VerificationResult<&'a str> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(VerificationFailure(DecisionVerificationReason::Malformed))
}

fn validate_times(claims: &Map<String, Value>, now: i64) -> VerificationResult<()> {
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(VerificationFailure(DecisionVerificationReason::Expired))?;
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(VerificationFailure(DecisionVerificationReason::Expired))?;
    let expected_exp = iat
        .checked_add(60)
        .ok_or(VerificationFailure(DecisionVerificationReason::Expired))?;
    let latest_iat = now.saturating_add(CLOCK_SKEW_SECONDS);
    let earliest_exp = now.saturating_sub(CLOCK_SKEW_SECONDS);
    if exp != expected_exp || iat > latest_iat || exp < earliest_exp {
        return Err(VerificationFailure(DecisionVerificationReason::Expired));
    }
    Ok(())
}

fn sha256_hex(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn validate_decision_identity(
    claims: &Map<String, Value>,
    origin: &str,
    surface: DecisionSurface,
) -> VerificationResult<()> {
    if required_string(claims, "iss")? != origin || required_string(claims, "aud")? != origin {
        return Err(VerificationFailure(DecisionVerificationReason::Audience));
    }
    if required_string(claims, "surface")? != surface.as_str() {
        return Err(VerificationFailure(DecisionVerificationReason::Surface));
    }
    Ok(())
}

fn validate_signed_decision(
    claims: &Map<String, Value>,
    body_decision: &SigilDecision,
) -> VerificationResult<()> {
    let signed_literal = required_string(claims, "decision")?;
    let signed_decision =
        normalize_decision_literal(signed_literal).map_err(VerificationFailure)?;
    if signed_literal == "APPROVED" {
        return Err(VerificationFailure(DecisionVerificationReason::Malformed));
    }
    if signed_decision != *body_decision {
        return Err(VerificationFailure(
            DecisionVerificationReason::LiteralMismatch,
        ));
    }
    Ok(())
}

fn validate_decision_bindings(
    claims: &Map<String, Value>,
    context: &AuthorizationVerificationContext,
) -> VerificationResult<(String, String)> {
    let intent_hash = required_string(claims, "intentHash")?;
    if !is_hex_64(intent_hash) || intent_hash != sha256_hex(&context.tx_commit) {
        return Err(VerificationFailure(
            DecisionVerificationReason::IntentBinding,
        ));
    }
    let policy_hash = required_string(claims, "policyHash")?;
    if !is_hex_64(policy_hash) {
        return Err(VerificationFailure(
            DecisionVerificationReason::PolicyBinding,
        ));
    }
    if claims.get("requestNonce").and_then(Value::as_str) != Some(context.request_nonce.as_str()) {
        return Err(VerificationFailure(DecisionVerificationReason::Nonce));
    }
    Ok((intent_hash.to_string(), policy_hash.to_string()))
}

fn validate_decision_surface_claims(
    claims: &Map<String, Value>,
    context: &AuthorizationVerificationContext,
    body: &Map<String, Value>,
    body_decision: &SigilDecision,
) -> VerificationResult<()> {
    if context.surface == DecisionSurface::TestRun
        && claims.get("test_run").and_then(Value::as_bool) != Some(true)
    {
        return Err(VerificationFailure(DecisionVerificationReason::Surface));
    }
    if *body_decision == SigilDecision::Pending {
        let body_hold = body
            .get("hold_id")
            .or_else(|| body.get("holdId"))
            .and_then(Value::as_str);
        if body_hold.is_none() || claims.get("holdId").and_then(Value::as_str) != body_hold {
            return Err(VerificationFailure(DecisionVerificationReason::Surface));
        }
    }
    if context.surface == DecisionSurface::HoldResolve
        && (claims
            .get("holdId")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || claims.get("resolvedAt").and_then(Value::as_i64).is_none())
    {
        return Err(VerificationFailure(DecisionVerificationReason::Surface));
    }
    Ok(())
}

fn validate_decision_claims(
    token: &ParsedJws,
    origin: &str,
    context: &AuthorizationVerificationContext,
    body: &Map<String, Value>,
    body_decision: SigilDecision,
) -> VerificationResult<(String, String)> {
    let claims = &token.claims;
    validate_times(
        claims,
        context.now_unix_seconds.unwrap_or_else(now_unix_seconds),
    )?;
    validate_decision_identity(claims, origin, context.surface)?;
    validate_signed_decision(claims, &body_decision)?;
    let bindings = validate_decision_bindings(claims, context)?;
    validate_decision_surface_claims(claims, context, body, &body_decision)?;
    Ok(bindings)
}

fn validate_attestation_claims(
    token: &ParsedJws,
    record: &ParsedJws,
    intent_hash: &str,
    policy_hash: &str,
    issuer: &str,
    now: i64,
) -> VerificationResult<()> {
    let claims = &token.claims;
    validate_times(claims, now)?;
    if claims.get("iss").and_then(Value::as_str) != Some(issuer)
        || claims.get("aud").and_then(Value::as_str) != Some("sigil-sign")
    {
        return Err(VerificationFailure(DecisionVerificationReason::Audience));
    }
    if claims.get("decision").and_then(Value::as_str) != Some("ALLOWED")
        || claims.get("intentHash").and_then(Value::as_str) != Some(intent_hash)
        || claims.get("policyHash").and_then(Value::as_str) != Some(policy_hash)
        || claims.get("kid").and_then(Value::as_str) != Some(token.kid.as_str())
        || token.kid != record.kid
    {
        return Err(VerificationFailure(
            DecisionVerificationReason::AttestationMismatch,
        ));
    }
    Ok(())
}

impl SigilClient {
    /// Verifies a raw authorization response against its exact request bindings.
    pub async fn verify_authorization_response(
        &self,
        body: &Value,
        context: &AuthorizationVerificationContext,
    ) -> AuthorizationVerificationResult {
        let Some(body) = body.as_object() else {
            return denied(DecisionVerificationReason::Malformed);
        };
        let Some(raw_status) = body.get("status").and_then(Value::as_str) else {
            return denied(DecisionVerificationReason::Malformed);
        };
        let body_decision = match normalize_decision_literal(raw_status) {
            Ok(decision) => decision,
            Err(reason) => return denied(reason),
        };
        if self.config.decision_verification_mode == DecisionVerificationMode::Enforce
            && self.config.expected_policy_hash.is_none()
        {
            return denied(DecisionVerificationReason::PolicyBinding);
        }
        let Some(record_value) = body.get("decision_record") else {
            return fallback(
                self.config.decision_verification_mode,
                body_decision,
                DecisionVerificationReason::RecordMissing,
            );
        };
        let result = async {
            let origin = canonical_origin(&self.config.api_url)?;
            let record = verify_token(
                self,
                &origin,
                record_value
                    .as_str()
                    .ok_or(VerificationFailure(DecisionVerificationReason::Malformed))?,
                TokenProfile::Decision,
            )
            .await?;
            let (intent_hash, policy_hash) =
                validate_decision_claims(&record, &origin, context, body, body_decision.clone())?;
            if let Some(expected_policy_hash) = self.config.expected_policy_hash.as_deref()
                && policy_hash != expected_policy_hash
            {
                return Err(VerificationFailure(
                    DecisionVerificationReason::PolicyBinding,
                ));
            }
            if body_decision != SigilDecision::Allowed || !context.execution {
                return Ok(AuthorizationVerificationResult {
                    decision: body_decision.clone(),
                    reason: None,
                    authorization: None,
                });
            }
            let attestation = body
                .get("intent_attestation")
                .or_else(|| body.get("intentAttestation"))
                .and_then(Value::as_str)
                .ok_or(VerificationFailure(
                    DecisionVerificationReason::AttestationMissing,
                ))?;
            let attestation =
                verify_token(self, &origin, attestation, TokenProfile::Attestation).await?;
            validate_attestation_claims(
                &attestation,
                &record,
                &intent_hash,
                &policy_hash,
                &self.config.attestation_issuer,
                context.now_unix_seconds.unwrap_or_else(now_unix_seconds),
            )?;
            Ok(AuthorizationVerificationResult {
                decision: SigilDecision::Allowed,
                reason: None,
                authorization: Some(verified_capability(intent_hash, policy_hash)),
            })
        }
        .await;
        match result {
            Ok(result) => result,
            Err(failure) => fallback(
                self.config.decision_verification_mode,
                body_decision,
                failure.0,
            ),
        }
    }
}

fn denied(reason: DecisionVerificationReason) -> AuthorizationVerificationResult {
    AuthorizationVerificationResult {
        decision: SigilDecision::Denied,
        reason: Some(reason),
        authorization: None,
    }
}

fn fallback(
    mode: DecisionVerificationMode,
    decision: SigilDecision,
    reason: DecisionVerificationReason,
) -> AuthorizationVerificationResult {
    let authorization = (mode == DecisionVerificationMode::Warn
        && decision == SigilDecision::Allowed)
        .then(legacy_authorization);
    let decision =
        if mode == DecisionVerificationMode::Enforce && decision == SigilDecision::Allowed {
            SigilDecision::Denied
        } else {
            decision
        };
    AuthorizationVerificationResult {
        decision,
        reason: Some(reason),
        authorization,
    }
}

pub(crate) fn log_decision_verification(
    reason: DecisionVerificationReason,
    mode: DecisionVerificationMode,
    surface: DecisionSurface,
) {
    eprintln!(
        "{}",
        serde_json::json!({
            "level": "warn",
            "event": "decision.verification_failed",
            "reason": reason.as_str(),
            "mode": match mode {
                DecisionVerificationMode::Warn => "warn",
                DecisionVerificationMode::Enforce => "enforce",
            },
            "consumer_version": CONSUMER_VERSION,
            "surface": surface.as_str(),
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::{net::TcpListener, task::JoinHandle};

    fn fixture_jwk(kid: &str) -> Value {
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": kid,
            "x": "9cmOxyWpijRUJpHhB022ZExZE7QnNmiagGPZ9O0ZB8o",
            "use": "sig",
            "key_ops": ["verify"]
        })
    }

    async fn spawn_server(app: Router) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener");
        let address = listener.local_addr().expect("test listener address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });
        (format!("http://{address}"), task)
    }

    fn jwks_client() -> Client {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("JWKS client")
    }

    #[test]
    fn trust_origin_is_https_and_root_only() {
        assert_eq!(
            canonical_origin("https://sign-test.sigilcore.com/").expect("canonical fixture origin"),
            "https://sign-test.sigilcore.com"
        );
        for rejected in [
            "http://sign-test.sigilcore.com",
            "https://user@sign-test.sigilcore.com",
            "https://sign-test.sigilcore.com/v1",
            "https://sign-test.sigilcore.com/?jwks=elsewhere",
            "https://sign-test.sigilcore.com/#fragment",
        ] {
            assert_eq!(
                canonical_origin(rejected)
                    .expect_err("unsafe origin must fail")
                    .0,
                DecisionVerificationReason::Audience
            );
        }
    }

    #[test]
    fn jwks_rejects_bad_shapes_duplicates_and_oversized_sets() {
        assert_eq!(
            parse_jwks(serde_json::json!({"keys": []}))
                .expect_err("empty JWKS must fail")
                .0,
            DecisionVerificationReason::KeyUnavailable
        );

        let duplicate = serde_json::json!({"keys": [fixture_jwk("one"), fixture_jwk("one")]});
        assert_eq!(
            parse_jwks(duplicate)
                .expect_err("duplicate kid must fail")
                .0,
            DecisionVerificationReason::KeyUnavailable
        );

        let oversized = (0..=JWKS_MAX_KEYS)
            .map(|index| fixture_jwk(&format!("key-{index}")))
            .collect::<Vec<_>>();
        assert_eq!(
            parse_jwks(serde_json::json!({"keys": oversized}))
                .expect_err("oversized JWKS must fail")
                .0,
            DecisionVerificationReason::KeyUnavailable
        );

        for invalid in [
            serde_json::json!({"keys": [{
                "kty": "RSA", "crv": "Ed25519", "kid": "bad-kty", "x": "x"
            }]}),
            serde_json::json!({"keys": [{
                "kty": "OKP", "crv": "Ed25519", "kid": "bad-use", "x": "x",
                "use": "enc"
            }]}),
            serde_json::json!({"keys": [{
                "kty": "OKP", "crv": "Ed25519", "kid": "bad-ops", "x": "x",
                "key_ops": ["sign"]
            }]}),
        ] {
            assert_eq!(
                parse_jwks(invalid).expect_err("invalid JWK must fail").0,
                DecisionVerificationReason::KeyUnavailable
            );
        }
    }

    #[test]
    fn clock_skew_boundaries_are_inclusive() {
        let claims = |iat: i64, exp: i64| {
            serde_json::json!({"iat": iat, "exp": exp})
                .as_object()
                .expect("claims object")
                .clone()
        };
        assert!(validate_times(&claims(1_030, 1_090), 1_000).is_ok());
        assert!(validate_times(&claims(910, 970), 1_000).is_ok());
        assert_eq!(
            validate_times(&claims(1_031, 1_091), 1_000)
                .expect_err("future skew beyond boundary must fail")
                .0,
            DecisionVerificationReason::Expired
        );
        assert_eq!(
            validate_times(&claims(909, 969), 1_000)
                .expect_err("expiry skew beyond boundary must fail")
                .0,
            DecisionVerificationReason::Expired
        );
        assert_eq!(
            validate_times(&claims(1_000, 1_061), 1_000)
                .expect_err("fixed lifetime must be exact")
                .0,
            DecisionVerificationReason::Expired
        );
        assert_eq!(
            validate_times(&claims(i64::MAX, i64::MAX), 1_000)
                .expect_err("overflowing lifetime must fail")
                .0,
            DecisionVerificationReason::Expired
        );
    }

    #[tokio::test]
    async fn pinned_key_precedes_network_resolution() {
        let pinned: DecisionJwk =
            serde_json::from_value(fixture_jwk("pinned")).expect("fixture JWK");
        let client = SigilClient::builder("sk_fixture")
            .decision_verification_mode(DecisionVerificationMode::Warn)
            .decision_record_jwk(pinned.clone())
            .build()
            .expect("pinned client");
        let resolved = resolve_jwk(&client, "https://unreachable.invalid", "pinned")
            .await
            .expect("pinned key must not fetch");
        assert_eq!(resolved, pinned);
    }

    #[tokio::test]
    async fn wave3_cold_cache_jwks_outage_drill_returns_key_unavailable() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve unused address");
        let origin = format!(
            "http://{}",
            listener.local_addr().expect("reserved address")
        );
        drop(listener);
        let result = fetch_jwks(&jwks_client(), &JwksCache::default(), &origin, false).await;
        assert_eq!(
            result.expect_err("cold-cache outage must fail").0,
            DecisionVerificationReason::KeyUnavailable
        );
    }

    #[tokio::test]
    async fn jwks_cache_has_a_five_minute_ttl_and_refreshes_after_expiry() {
        assert_eq!(JWKS_CACHE_TTL, Duration::from_secs(300));
        let requests = Arc::new(AtomicUsize::new(0));
        let route_requests = Arc::clone(&requests);
        let app = Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let route_requests = Arc::clone(&route_requests);
                async move {
                    route_requests.fetch_add(1, Ordering::SeqCst);
                    serde_json::json!({"keys": [fixture_jwk("one")]}).to_string()
                }
            }),
        );
        let (origin, server) = spawn_server(app).await;
        let cache = JwksCache::default();
        let http = jwks_client();

        fetch_jwks(&http, &cache, &origin, false)
            .await
            .expect("cold JWKS fetch");
        fetch_jwks(&http, &cache, &origin, false)
            .await
            .expect("warm JWKS fetch");
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        cache
            .0
            .lock()
            .expect("cache lock")
            .get_mut(&origin)
            .expect("cache entry")
            .expires_at = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("one second before now");
        fetch_jwks(&http, &cache, &origin, false)
            .await
            .expect("expired JWKS refresh");
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn wave3_jwks_redirect_and_oversize_drill_fails_closed() {
        let redirect_app = Router::new().route(
            "/.well-known/jwks.json",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [("location", "https://attacker.invalid/jwks.json")],
                    "",
                )
                    .into_response()
            }),
        );
        let (redirect_origin, redirect_server) = spawn_server(redirect_app).await;
        let redirect_result = fetch_jwks(
            &jwks_client(),
            &JwksCache::default(),
            &redirect_origin,
            false,
        )
        .await;
        assert_eq!(
            redirect_result.expect_err("redirect must fail").0,
            DecisionVerificationReason::KeyUnavailable
        );
        redirect_server.abort();

        let oversized_app = Router::new().route(
            "/.well-known/jwks.json",
            get(|| async { "x".repeat(JWKS_MAX_BYTES + 1) }),
        );
        let (oversized_origin, oversized_server) = spawn_server(oversized_app).await;
        let oversized_result = fetch_jwks(
            &jwks_client(),
            &JwksCache::default(),
            &oversized_origin,
            false,
        )
        .await;
        assert_eq!(
            oversized_result.expect_err("oversized JWKS must fail").0,
            DecisionVerificationReason::KeyUnavailable
        );
        oversized_server.abort();
    }

    #[tokio::test]
    async fn wave3_two_kid_rotation_overlap_drill_uses_one_cached_set() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../contract-fixtures/v1/decision-records.json"
        ))
        .expect("decision fixture");
        let origin = fixture["context"]["signOrigin"]
            .as_str()
            .expect("fixture origin");
        let policy_hash = fixture["context"]["expectedPolicyHash"]
            .as_str()
            .expect("fixture policy hash");
        let client = SigilClient::builder("sk_fixture")
            .api_url(origin)
            .decision_verification_mode(DecisionVerificationMode::Enforce)
            .expected_policy_hash(policy_hash)
            .build()
            .expect("fixture client");
        let primary: DecisionJwk =
            serde_json::from_value(fixture["publicJwk"].clone()).expect("primary fixture JWK");
        let rotation: DecisionJwk = serde_json::from_value(fixture["rotationPublicJwk"].clone())
            .expect("rotation fixture JWK");
        client.jwks_cache.0.lock().expect("cache lock").insert(
            origin.to_string(),
            CachedJwks {
                expires_at: Instant::now() + JWKS_CACHE_TTL,
                keys: HashMap::from([
                    (primary.kid.clone(), primary),
                    (rotation.kid.clone(), rotation),
                ]),
            },
        );

        let primary_response = serde_json::json!({
            "status": "ALLOWED",
            "decision_record": fixture["tokens"]["allowed"],
        });
        let rotation_response = serde_json::json!({
            "status": "ALLOWED",
            "decision_record": fixture["tokens"]["rotation_allowed"],
            "jwks_uri": "https://attacker.invalid/jwks.json"
        });
        let context = AuthorizationVerificationContext {
            tx_commit: fixture["context"]["txCommit"]
                .as_str()
                .expect("fixture txCommit")
                .to_string(),
            request_nonce: fixture["context"]["requestNonce"]
                .as_str()
                .expect("fixture requestNonce")
                .to_string(),
            surface: DecisionSurface::Authorize,
            execution: false,
            now_unix_seconds: fixture["context"]["nowUnixSeconds"].as_i64(),
        };

        let primary_result = client
            .verify_authorization_response(&primary_response, &context)
            .await;
        assert_eq!(primary_result.decision, SigilDecision::Allowed);
        assert_eq!(primary_result.reason, None);

        let rotation_result = client
            .verify_authorization_response(&rotation_response, &context)
            .await;
        assert_eq!(rotation_result.decision, SigilDecision::Allowed);
        assert_eq!(rotation_result.reason, None);
    }
}
