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
pub struct CompiledResponsePolicyFormat2Scanner {
    pub required: bool,
    pub profile: String,
    pub classes: Vec<ResponseClass>,
    pub min_confidence: serde_json::Number,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledResponsePolicyFormat2Observe {
    pub classes: Vec<ResponseClass>,
    pub until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledResponsePolicyFormat2Policy {
    pub deterministic_ruleset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_fetch_tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_classes: Option<Vec<ResponseClass>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_strings: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redact_classes: Option<Vec<ResponseClass>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner: Option<CompiledResponsePolicyFormat2Scanner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observe: Option<CompiledResponsePolicyFormat2Observe>,
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

    // skipcq: RS-R1000 - Format-1 envelope invariants remain one ordered fail-closed wire-validation boundary.
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
                    && values
                        .windows(2)
                        .all(|pair| utf16_cmp(&pair[0], &pair[1]) == Ordering::Less),
                "policy.denyStrings",
            )?;
        }
        let mut union = self.policy.web_fetch_tools.clone().unwrap_or_default();
        let coverage_count = union.len()
            + self
                .policy
                .http_tools
                .as_ref()
                .map_or(0, std::vec::Vec::len);
        union.extend(self.policy.http_tools.clone().unwrap_or_default());
        union.sort_by(|left, right| utf16_cmp(left, right));
        union.dedup();
        require(union.len() == coverage_count, "policy coverage")?;
        require(union == self.covered_tools, "coveredTools")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledResponsePolicyFormat2 {
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
    pub policy: CompiledResponsePolicyFormat2Policy,
}

impl CompiledResponsePolicyFormat2 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ResponseWireError> {
        self.validate()?;
        canonical_json_bytes(&serde_json::to_value(self)?)
    }

    // skipcq: RS-R1000 - Format-2 envelope invariants remain one ordered fail-closed wire-validation boundary.
    pub fn validate(&self) -> Result<(), ResponseWireError> {
        require(self.kind == "CompiledResponsePolicy", "kind")?;
        require(self.format_version == 2, "formatVersion")?;
        require(!self.issuer.is_empty(), "issuer")?;
        require(!self.key_id.is_empty(), "keyId")?;
        require(self.audience == "sigil-agent-hooks", "audience")?;
        require(self.scope == "mcp:result-inspect", "scope")?;
        require(!self.tenant_id.is_empty(), "tenantId")?;
        require(!self.task_id.is_empty(), "taskId")?;
        require(is_policy_23(&self.policy_version), "policyVersion")?;
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
        for (values, field) in [
            (&self.policy.block_classes, "policy.blockClasses"),
            (&self.policy.redact_classes, "policy.redactClasses"),
        ] {
            if let Some(values) = values {
                require_sorted_unique_classes(values, field)?;
            }
        }
        if let Some(values) = &self.policy.deny_strings {
            require_sorted_unique_nonempty(values, "policy.denyStrings")?;
        }
        if let Some(scanner) = &self.policy.scanner {
            require(
                !scanner.profile.is_empty()
                    && scanner.profile.len() <= 128
                    && scanner.profile.bytes().enumerate().all(|(index, byte)| {
                        byte.is_ascii_alphanumeric()
                            || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
                    }),
                "policy.scanner.profile",
            )?;
            require_sorted_unique_classes(&scanner.classes, "policy.scanner.classes")?;
            let confidence = scanner.min_confidence.to_string();
            require(
                valid_confidence(&confidence),
                "policy.scanner.minConfidence",
            )?;
        }
        if let Some(observe) = &self.policy.observe {
            require_sorted_unique_classes(&observe.classes, "policy.observe.classes")?;
            require(
                canonical_utc_seconds(&observe.until),
                "policy.observe.until",
            )?;
            let until = utc_seconds(&observe.until)
                .ok_or(ResponseWireError::Invalid("policy.observe.until"))?;
            require(
                until > self.issued_at
                    && until - self.issued_at <= self.bounds.max_observe_window_seconds,
                "policy.observe.until",
            )?;
        }
        let mut union = self.policy.web_fetch_tools.clone().unwrap_or_default();
        let coverage_count = union.len()
            + self
                .policy
                .http_tools
                .as_ref()
                .map_or(0, std::vec::Vec::len);
        union.extend(self.policy.http_tools.clone().unwrap_or_default());
        union.sort_by(|left, right| utf16_cmp(left, right));
        union.dedup();
        require(union.len() == coverage_count, "policy coverage")?;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ResponseDispositionV2 {
    Allow,
    Block,
    Redact,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDecisionReasonV2 {
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
    ScannerFailure,
    ScannerBlock,
    Redaction,
    ObserveExpired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFindingSourceV2 {
    Deterministic,
    Scanner,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseFindingV2 {
    pub class: ResponseClass,
    pub start: u64,
    pub end: u64,
    pub evidence_digest: String,
    pub source: ResponseFindingSourceV2,
    pub ruleset_version: String,
    pub rule_id: String,
    pub confidence: Option<String>,
    pub qualified: bool,
    pub observed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseRedactionSpanV1 {
    pub start: u64,
    pub end: u64,
    pub classes: Vec<ResponseClass>,
    pub evidence_digests: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScannerFailureReason {
    Authentication,
    Deadline,
    Transport,
    Schema,
    Binding,
    Oversize,
    FindingsLimit,
    Class,
    Confidence,
    Offset,
    EvidenceDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScannerNoResultStatus {
    NotConfigured,
    SkippedTerminal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScannerEvidenceNoResult {
    pub status: ScannerNoResultStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScannerEvidenceFailed {
    pub status: ScannerFailedStatus,
    pub reason: ScannerFailureReason,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScannerFailedStatus {
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScannerEvidenceVerified {
    pub status: ScannerVerifiedStatus,
    pub scanner_id: String,
    pub ruleset_version: String,
    pub response_digest: String,
    pub finding_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScannerVerifiedStatus {
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ScannerEvidenceV1 {
    NoResult(ScannerEvidenceNoResult),
    Failed(ScannerEvidenceFailed),
    Verified(ScannerEvidenceVerified),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseObserveMetadataV1 {
    pub active: bool,
    pub until: Option<String>,
    pub classes: Vec<ResponseClass>,
    pub finding_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseDecisionV2 {
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
    pub disposition: ResponseDispositionV2,
    pub reason: ResponseDecisionReasonV2,
    pub findings: Vec<ResponseFindingV2>,
    pub redactions: Vec<ResponseRedactionSpanV1>,
    pub redaction_plan_digest: Option<String>,
    pub scanner_evidence: ScannerEvidenceV1,
    pub observe: ResponseObserveMetadataV1,
}

impl ResponseDecisionV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ResponseWireError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(ResponseWireError::Json)
    }

    // skipcq: RS-R1000 - Response-decision bindings and precedence remain one ordered fail-closed wire-validation boundary.
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
        let disposition_reason_valid = match (&self.disposition, &self.reason) {
            (ResponseDispositionV1::Allow, ResponseDecisionReason::None) => true,
            (ResponseDispositionV1::Block, ResponseDecisionReason::None)
            | (ResponseDispositionV1::Allow, _) => false,
            (ResponseDispositionV1::Block, _) => true,
        };
        require(disposition_reason_valid, "disposition/reason")?;
        for finding in &self.findings {
            require(
                finding.start < finding.end && finding.end <= MAX_SAFE_INTEGER,
                "finding offsets",
            )?;
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

impl ResponseDecisionV2 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ResponseWireError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(ResponseWireError::Json)
    }

    // skipcq: RS-R1000 - Format-2 decision bindings and precedence remain one ordered fail-closed wire-validation boundary.
    pub fn validate(&self) -> Result<(), ResponseWireError> {
        require(self.schema == "sof-response-decision/v2", "schema")?;
        require(self.format_version == 2, "formatVersion")?;
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
            require(
                finding.start < finding.end && finding.end <= MAX_SAFE_INTEGER,
                "finding offsets",
            )?;
            require(
                is_lower_hex(&finding.evidence_digest, HEX_64_LEN),
                "finding evidenceDigest",
            )?;
            require(
                !finding.ruleset_version.is_empty(),
                "finding rulesetVersion",
            )?;
            require(!finding.rule_id.is_empty(), "finding ruleId")?;
            match (&finding.source, &finding.confidence) {
                (ResponseFindingSourceV2::Deterministic, None) => {}
                (ResponseFindingSourceV2::Scanner, Some(value)) if valid_confidence(value) => {}
                _ => return Err(ResponseWireError::Invalid("finding source/confidence")),
            }
        }
        for redaction in &self.redactions {
            require(
                redaction.start < redaction.end && redaction.end <= MAX_SAFE_INTEGER,
                "redaction offsets",
            )?;
            require_sorted_unique_classes(&redaction.classes, "redaction classes")?;
            require(
                !redaction.evidence_digests.is_empty()
                    && redaction
                        .evidence_digests
                        .iter()
                        .all(|value| is_lower_hex(value, HEX_64_LEN))
                    && redaction
                        .evidence_digests
                        .windows(2)
                        .all(|pair| pair[0] < pair[1]),
                "redaction evidenceDigests",
            )?;
        }
        require(
            self.redactions
                .windows(2)
                .all(|pair| pair[0].end <= pair[1].start),
            "redaction overlap",
        )?;
        match (&self.disposition, &self.reason) {
            (ResponseDispositionV2::Allow, ResponseDecisionReasonV2::None) => require(
                self.redactions.is_empty() && self.redaction_plan_digest.is_none(),
                "allow redactions",
            )?,
            (ResponseDispositionV2::Redact, ResponseDecisionReasonV2::Redaction) => require(
                !self.redactions.is_empty()
                    && self
                        .redaction_plan_digest
                        .as_ref()
                        .is_some_and(|value| is_lower_hex(value, HEX_64_LEN)),
                "redact plan",
            )?,
            (ResponseDispositionV2::Block, reason)
                if !matches!(
                    reason,
                    ResponseDecisionReasonV2::None | ResponseDecisionReasonV2::Redaction
                ) =>
            {
                require(
                    self.redactions.is_empty() && self.redaction_plan_digest.is_none(),
                    "block redactions",
                )?
            }
            _ => return Err(ResponseWireError::Invalid("disposition/reason")),
        }
        let scanner_findings = self
            .findings
            .iter()
            .filter(|finding| matches!(finding.source, ResponseFindingSourceV2::Scanner))
            .collect::<Vec<_>>();
        match &self.scanner_evidence {
            ScannerEvidenceV1::NoResult(_) => {
                require(scanner_findings.is_empty(), "scannerEvidence findings")?;
            }
            ScannerEvidenceV1::Failed(value) => {
                require(scanner_findings.is_empty(), "scannerEvidence findings")?;
                if value.required {
                    require(
                        matches!(self.disposition, ResponseDispositionV2::Block)
                            && matches!(self.reason, ResponseDecisionReasonV2::ScannerFailure),
                        "required scanner failure decision",
                    )?;
                }
            }
            ScannerEvidenceV1::Verified(value) => {
                require(!value.scanner_id.is_empty(), "scannerEvidence.scannerId")?;
                require(
                    !value.ruleset_version.is_empty(),
                    "scannerEvidence.rulesetVersion",
                )?;
                require(
                    is_lower_hex(&value.response_digest, HEX_64_LEN),
                    "scannerEvidence.responseDigest",
                )?;
                require(
                    value.finding_count <= 256
                        && value.finding_count as usize == scanner_findings.len(),
                    "scannerEvidence.findingCount",
                )?;
                require(
                    scanner_findings
                        .iter()
                        .all(|finding| finding.ruleset_version == value.ruleset_version),
                    "scannerEvidence.rulesetVersion",
                )?;
            }
        }
        require_classes_sorted_unique_allow_empty(&self.observe.classes, "observe.classes")?;
        require(self.observe.finding_count <= 256, "observe.findingCount")?;
        require(
            self.observe.finding_count as usize
                == self
                    .findings
                    .iter()
                    .filter(|finding| finding.observed)
                    .count(),
            "observe.findingCount",
        )?;
        match (&self.observe.until, self.observe.active) {
            (Some(value), _) => require(canonical_utc_seconds(value), "observe.until")?,
            (None, false) => {}
            (None, true) => return Err(ResponseWireError::Invalid("observe.active")),
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ResponseWireError {
    #[error("invalid response wire field: {0}")]
    Invalid(&'static str),
    #[error("invalid response wire JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn parse_compiled_response_policy_format1(
    bytes: &[u8],
) -> Result<CompiledResponsePolicyFormat1, ResponseWireError> {
    let value: CompiledResponsePolicyFormat1 = serde_json::from_slice(bytes)?;
    value.validate()?;
    Ok(value)
}

pub fn parse_compiled_response_policy_format2(
    bytes: &[u8],
) -> Result<CompiledResponsePolicyFormat2, ResponseWireError> {
    let value: CompiledResponsePolicyFormat2 = serde_json::from_slice(bytes)?;
    value.validate()?;
    Ok(value)
}

pub fn parse_response_decision_v1(bytes: &[u8]) -> Result<ResponseDecisionV1, ResponseWireError> {
    let value: ResponseDecisionV1 = serde_json::from_slice(bytes)?;
    value.validate()?;
    Ok(value)
}

pub fn parse_response_decision_v2(bytes: &[u8]) -> Result<ResponseDecisionV2, ResponseWireError> {
    let value: ResponseDecisionV2 = serde_json::from_slice(bytes)?;
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

fn is_policy_23(value: &str) -> bool {
    let Some(patch_and_suffix) = value.strip_prefix("2.3.") else {
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

fn valid_confidence(value: &str) -> bool {
    if value == "0" || value == "1" {
        return true;
    }
    let Some(fraction) = value.strip_prefix("0.") else {
        return false;
    };
    !fraction.is_empty()
        && fraction.len() <= 4
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
        && !fraction.ends_with('0')
}

fn canonical_utc_seconds(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |start: usize, end: usize| value[start..end].parse::<u32>().ok();
    let Some(year) = number(0, 4) else {
        return false;
    };
    let Some(month @ 1..=12) = number(5, 7) else {
        return false;
    };
    let Some(day) = number(8, 10) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days).contains(&day)
        && matches!(number(11, 13), Some(0..=23))
        && matches!(number(14, 16), Some(0..=59))
        && matches!(number(17, 19), Some(0..=59))
}

fn utc_seconds(value: &str) -> Option<u64> {
    if !canonical_utc_seconds(value) {
        return None;
    }
    let parse = |start: usize, end: usize| value[start..end].parse::<i64>().ok();
    let year = parse(0, 4)?;
    let month = parse(5, 7)?;
    let day = parse(8, 10)?;
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days_since_epoch = era * 146_097 + day_of_era - 719_468;
    let seconds =
        days_since_epoch * 86_400 + parse(11, 13)? * 3_600 + parse(14, 16)? * 60 + parse(17, 19)?;
    u64::try_from(seconds).ok()
}

fn require_sorted_unique_classes(
    values: &[ResponseClass],
    field: &'static str,
) -> Result<(), ResponseWireError> {
    require(
        !values.is_empty()
            && values
                .windows(2)
                .all(|pair| class_name(&pair[0]) < class_name(&pair[1])),
        field,
    )
}

fn require_classes_sorted_unique_allow_empty(
    values: &[ResponseClass],
    field: &'static str,
) -> Result<(), ResponseWireError> {
    require(
        values
            .windows(2)
            .all(|pair| class_name(&pair[0]) < class_name(&pair[1])),
        field,
    )
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
