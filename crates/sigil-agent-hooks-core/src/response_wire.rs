use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use thiserror::Error;

const HEX_32_LEN: usize = 32;
const HEX_64_LEN: usize = 64;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseClass {
    MaliciousUrl,
    Pii,
    PromptInjection,
    Secret,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledResponsePolicyBounds {
    pub max_projection_bytes: u64,
    pub max_nesting_depth: u64,
    pub max_findings: u64,
    pub max_scanner_response_bytes: u64,
    pub scanner_deadline_ms: u64,
    pub max_envelope_lifetime_seconds: u64,
    pub clock_skew_seconds: u64,
    pub max_observe_window_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseManifestBinding {
    pub id: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledResponsePolicyFormat1Policy {
    pub deterministic_ruleset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_fetch_tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_classes: Option<Vec<ResponseClass>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_strings: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledResponsePolicyFormat1 {
    pub kind: String,
    pub format_version: u8,
    pub issuer: String,
    pub key_id: String,
    pub audience: String,
    pub scope: String,
    pub tenant_id: String,
    pub task_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub covered_tools: Vec<String>,
    pub deterministic_ruleset: ResponseManifestBinding,
    pub class_catalog: ResponseManifestBinding,
    pub bounds: CompiledResponsePolicyBounds,
    pub policy: CompiledResponsePolicyFormat1Policy,
}

impl CompiledResponsePolicyFormat1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ResponseWireError> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        canonical_json_bytes(&value)
    }

    pub fn validate(&self) -> Result<(), ResponseWireError> {
        require(self.kind == "CompiledResponsePolicy", "kind")?;
        require(self.format_version == 1, "formatVersion")?;
        require(!self.issuer.is_empty(), "issuer")?;
        require(!self.key_id.is_empty(), "keyId")?;
        require(self.audience == "sigil-agent-hooks", "audience")?;
        require(self.scope == "mcp:result-inspect", "scope")?;
        require(!self.tenant_id.is_empty(), "tenantId")?;
        require(!self.task_id.is_empty(), "taskId")?;
        require(is_policy_22(&self.policy_version), "policyVersion")?;
        require(is_lower_hex(&self.policy_hash, HEX_64_LEN), "policyHash")?;
        require(
            self.issued_at <= MAX_SAFE_INTEGER
                && self.expires_at <= MAX_SAFE_INTEGER
                && self.revocation_epoch <= MAX_SAFE_INTEGER,
            "safe integer fields",
        )?;
        require(
            self.expires_at > self.issued_at && self.expires_at - self.issued_at <= 300,
            "expiresAt",
        )?;
        require_sorted_unique_nonempty(&self.covered_tools, "coveredTools")?;
        require(
            self.deterministic_ruleset.id == "sof-response-rules-v1"
                && is_lower_hex(&self.deterministic_ruleset.digest, HEX_64_LEN),
            "deterministicRuleset",
        )?;
        require(
            self.class_catalog.id == "sof-response-classes-v1"
                && is_lower_hex(&self.class_catalog.digest, HEX_64_LEN),
            "classCatalog",
        )?;
        require(
            self.bounds
                == (CompiledResponsePolicyBounds {
                    max_projection_bytes: 16_777_216,
                    max_nesting_depth: 16,
                    max_findings: 256,
                    max_scanner_response_bytes: 1_048_576,
                    scanner_deadline_ms: 2_000,
                    max_envelope_lifetime_seconds: 300,
                    clock_skew_seconds: 30,
                    max_observe_window_seconds: 2_592_000,
                }),
            "bounds",
        )?;
        require(
            self.policy.deterministic_ruleset == "sof-response-rules-v1",
            "policy.deterministicRuleset",
        )?;
        if let Some(values) = &self.policy.web_fetch_tools {
            require_sorted_unique_nonempty(values, "policy.webFetchTools")?;
        }
        if let Some(values) = &self.policy.http_tools {
            require_sorted_unique_nonempty(values, "policy.httpTools")?;
        }
        require(
            self.policy.web_fetch_tools.is_some() || self.policy.http_tools.is_some(),
            "policy coverage",
        )?;
        if let Some(values) = &self.policy.block_classes {
            require(!values.is_empty(), "policy.blockClasses")?;
            require(
                values
                    .windows(2)
                    .all(|pair| class_name(&pair[0]) < class_name(&pair[1])),
                "policy.blockClasses",
            )?;
        }
        if let Some(values) = &self.policy.deny_strings {
            require(
                !values.is_empty()
                    && values.iter().all(|value| !value.is_empty())
                    && all_unique(values),
                "policy.denyStrings",
            )?;
        }
        let mut union = self.policy.web_fetch_tools.clone().unwrap_or_default();
        union.extend(self.policy.http_tools.clone().unwrap_or_default());
        union.sort_by(|left, right| utf16_cmp(left, right));
        union.dedup();
        require(union == self.covered_tools, "coveredTools")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ResponseDispositionV1 {
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDecisionReason {
    None,
    DeterministicBlock,
    ResponseLiteral,
    UnsupportedBinaryResult,
    ProjectionLimit,
    NestingLimit,
    EvaluatorFailure,
    BindingMismatch,
    LegacyUnsupported,
    EnvelopeInvalid,
    Replay,
    Duplicate,
    Cancelled,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseFinding {
    pub class: ResponseClass,
    pub start: u64,
    pub end: u64,
    pub evidence_digest: String,
    pub ruleset_version: String,
    pub rule_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseDecisionV1 {
    pub schema: String,
    pub format_version: u8,
    pub execution_id: String,
    pub request_id_digest: String,
    pub tenant_id: String,
    pub task_id: String,
    pub tool: String,
    pub policy_hash: String,
    pub compiled_policy_digest: String,
    pub authorization_binding: String,
    pub request_digest: String,
    pub result_digest: String,
    pub projection_digest: String,
    pub content_type: String,
    pub disposition: ResponseDispositionV1,
    pub reason: ResponseDecisionReason,
    pub findings: Vec<ResponseFinding>,
}

impl ResponseDecisionV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ResponseWireError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(ResponseWireError::Json)
    }

    pub fn validate(&self) -> Result<(), ResponseWireError> {
        require(self.schema == "sof-response-decision/v1", "schema")?;
        require(self.format_version == 1, "formatVersion")?;
        require(is_lower_hex(&self.execution_id, HEX_32_LEN), "executionId")?;
        for (name, value) in [
            ("requestIdDigest", self.request_id_digest.as_str()),
            ("policyHash", self.policy_hash.as_str()),
            ("compiledPolicyDigest", self.compiled_policy_digest.as_str()),
            ("authorizationBinding", self.authorization_binding.as_str()),
            ("requestDigest", self.request_digest.as_str()),
            ("resultDigest", self.result_digest.as_str()),
            ("projectionDigest", self.projection_digest.as_str()),
        ] {
            require(is_lower_hex(value, HEX_64_LEN), name)?;
        }
        require(!self.tenant_id.is_empty(), "tenantId")?;
        require(!self.task_id.is_empty(), "taskId")?;
        require(!self.tool.is_empty(), "tool")?;
        require(
            self.content_type == "application/vnd.modelcontextprotocol.call-tool-result+json",
            "contentType",
        )?;
        require(self.findings.len() <= 256, "findings")?;
        for finding in &self.findings {
            require(finding.start < finding.end, "finding offsets")?;
            require(
                is_lower_hex(&finding.evidence_digest, HEX_64_LEN),
                "finding evidenceDigest",
            )?;
            require(
                finding.ruleset_version == "sof-response-rules-v1",
                "finding rulesetVersion",
            )?;
            require(!finding.rule_id.is_empty(), "finding ruleId")?;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ResponseWireError {
    #[error("invalid format-1 response wire field: {0}")]
    Invalid(&'static str),
    #[error("invalid format-1 response JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn parse_compiled_response_policy_format1(
    bytes: &[u8],
) -> Result<CompiledResponsePolicyFormat1, ResponseWireError> {
    let value: CompiledResponsePolicyFormat1 = serde_json::from_slice(bytes)?;
    value.validate()?;
    Ok(value)
}

pub fn parse_response_decision_v1(bytes: &[u8]) -> Result<ResponseDecisionV1, ResponseWireError> {
    let value: ResponseDecisionV1 = serde_json::from_slice(bytes)?;
    value.validate()?;
    Ok(value)
}

fn require(condition: bool, field: &'static str) -> Result<(), ResponseWireError> {
    condition
        .then_some(())
        .ok_or(ResponseWireError::Invalid(field))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_policy_22(value: &str) -> bool {
    let Some(patch_and_suffix) = value.strip_prefix("2.2.") else {
        return false;
    };
    let (patch, suffix) = match patch_and_suffix.split_once('-') {
        Some((patch, suffix)) => (patch, Some(suffix)),
        None => (patch_and_suffix, None),
    };
    !patch.is_empty()
        && patch.bytes().all(|byte| byte.is_ascii_digit())
        && suffix.is_none_or(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        })
}

fn require_sorted_unique_nonempty(
    values: &[String],
    field: &'static str,
) -> Result<(), ResponseWireError> {
    require(
        !values.is_empty()
            && values.iter().all(|value| !value.is_empty())
            && values
                .windows(2)
                .all(|pair| utf16_cmp(&pair[0], &pair[1]) == Ordering::Less),
        field,
    )
}

fn all_unique(values: &[String]) -> bool {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted.len() == values.len()
}

fn class_name(value: &ResponseClass) -> &'static str {
    match value {
        ResponseClass::MaliciousUrl => "malicious_url",
        ResponseClass::Pii => "pii",
        ResponseClass::PromptInjection => "prompt_injection",
        ResponseClass::Secret => "secret",
    }
}

fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, ResponseWireError> {
    fn write_value(
        output: &mut Vec<u8>,
        value: &serde_json::Value,
    ) -> Result<(), serde_json::Error> {
        match value {
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => serde_json::to_writer(output, value),
            serde_json::Value::Array(items) => {
                output.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write_value(output, item)?;
                }
                output.push(b']');
                Ok(())
            }
            serde_json::Value::Object(object) => {
                let mut entries = object.iter().collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| utf16_cmp(left, right));
                output.push(b'{');
                for (index, (key, item)) in entries.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    serde_json::to_writer(&mut *output, key)?;
                    output.push(b':');
                    write_value(output, item)?;
                }
                output.push(b'}');
                Ok(())
            }
        }
    }

    let mut output = Vec::new();
    write_value(&mut output, value)?;
    Ok(output)
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}
