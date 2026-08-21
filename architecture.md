# Architecture

`agent-hooks-rs` is a Cargo workspace containing two crates that provide Rust-native pre-tool authorization against the Sigil Sign `/v1/authorize` API.

## Workspace layout

```
agent-hooks-rs/
  Cargo.toml                          # workspace root
  contract-fixtures/v1/               # shared wire-format fixtures
  contract-fixtures/response-v1/      # format-1 source/payload/decision fixtures
  contract-fixtures/response-v2/      # format-2 scanner/redaction/observe fixtures
  crates/
    sigil-agent-hooks-core/           # generic Sigil client
    sigil-agent-hooks-ironclaw/       # IronClaw Hook trait adapter
  .github/workflows/
    rust-ci.yml                       # fmt, clippy, test, deny, audit
    publish-rust.yml                  # crates.io publish on rs-v* tags
```

## Crate responsibilities

### sigil-agent-hooks-core

Framework-agnostic Rust client for Sigil Sign. Owns the full authorization lifecycle:

1. Build the `/v1/authorize` request body (action, agent ID, framework, optional chain/tx fields).
2. Generate an intent commit (SHA-256 of the canonical intent preimage with a timestamp) when the caller does not provide an explicit `tx_commit`.
3. Send the request to Sigil Sign over HTTPS (reqwest + rustls).
4. Parse the response into a typed `SigilResult` (`Allowed`, `Denied`, or `Pending`) through the atomic signed-response verifier.
5. Apply the configured `FailMode` only when the request receives no response
   (for example, DNS, connection, or pre-response timeout failure). Every reached
   response, including a non-success status other than a valid 403 denial,
   malformed JSON, body-protocol failure, or an oversized body, denies without
   an executable legacy capability.
6. Build structured rejection context (`build_rejection_context`) that agents can consume without parsing free text. Three distinct paths: policy denial, consensus hold (PENDING), and transient unreachability.
7. Track task-local model usage with `record_model_usage`, `get_model_usage_report`, `clear_model_usage`, and `check_model_budget`. The helper serializes cumulative provider usage under `metadata.model_usage` on `action: "model.inference"` checks.
8. Parse and serialize the schema-closed compiled response-policy format-1
   payload and `sof-response-decision/v1` record against checksum-pinned Phase
   0 fixtures.
9. Parse and serialize schema-closed format-2 policy and decision records,
   including scanner evidence, mapped redactions, and observe metadata, against
   checksum-pinned Release 2 candidate fixtures.

Items 8 and 9 are response-policy wire boundaries only. The core crate verifies
authorization decision records and Intent Attestations, but it does not verify
the separate response-policy compact JWS, project a tool result, run
deterministic response rules, or return a runtime response disposition.

HTTP 401 and malformed or non-`DENIED` HTTP 403 responses are classified as
`SIGIL_AUTH_FAILURE`. A valid HTTP 403 `DENIED` response is parsed as a policy
result and its decision record is verified when present.

The client is constructed through a builder (`SigilClient::builder`) that
validates config at build time, including an exact HTTPS root origin and an
exact lowercase 64-hex policy pin whenever one is supplied. The pin is mandatory
in enforce mode. The builder produces a reusable client with separate
authorization and no-redirect JWKS HTTP clients. Warn mode without a pin emits
a policy-binding diagnostic on every authorization call.

### sigil-agent-hooks-ironclaw

Implements IronClaw's `Hook` trait using `sigil-agent-hooks-core` as the authorization backend. Hooks into `BeforeToolCall` only.

Key components:

**`ToolIntentMapper` trait** -- translates IronClaw tool names and parameters into `SigilIntent`. The default mapper covers common tool-name aliases (`exec`/`process`/`code_execution` to `bash`, `write`/`edit`/`apply_patch` to `file_write`, wallet actions, web fetch variants). Unknown tools pass through as lowercase strings so Sigil policies can address them without adapter changes.

**`IronclawSigilHook`** -- the `Hook` implementation. Built via `IronclawSigilHook::builder(client)`. If the client was constructed with the default `FrameworkId::AgentHooks`, the builder silently rebinds it to `FrameworkId::Ironclaw` so the authorize request carries the correct framework identifier. Non-tool events (e.g. `SessionStart`) pass through without an authorization call.

**Decision routing:** only a verifier-minted authorization capability returns
`HookOutcome::ok()`. Both `DENIED` and `PENDING`, plus any raw allow literal
without an acceptable capability for the configured rollout mode, return
`HookOutcome::reject()` with a JSON-serialized `SigilRejectionContext` as the
reason string. `PENDING` is not authorization, and the current task must not
retry or execute it. It is deliberately not surfaced as a local approval
prompt. If Sign supports a Class 3 resolution, only an authenticated
out-of-band decision may permit an exact-intent reauthorization; any
attestation issued then is new and separate from the pending result.

**Model budgets:** IronClaw currently exposes `BeforeToolCall` to this adapter.
It does not expose provider usage before model steps in this crate. Hosts that
own the IronClaw model loop should wrap provider calls with
`sigil-agent-hooks-core` model-budget helpers and keep the native hook focused
on tool-call authorization.

**No native response enforcement:** this crate has no after-tool result hook.
It does not consume the format-1 or format-2 response types at runtime and does
not claim response-policy evaluation, scanner, redaction, or enforcement parity
with the TypeScript package.

## Wire parity with agent-hooks (TypeScript)

Both repositories share a set of contract fixtures (`contract-fixtures/v1/`) that pin the exact JSON wire format of `/v1/authorize` request bodies. The fixture files are checked into both repos and protected by SHA-256 checksums (`SHA256SUMS`).

The parity mechanism works as follows:

1. The Rust crate's `contract_fixtures.rs` tests build a `SigilClient`, call `check_intent` against a local mock server, capture the raw request body, and assert byte-equality against each fixture file.
2. The TypeScript package's `contract-fixtures.test.ts` does the same thing with `buildAuthorizeRequestBody`.
3. `SHA256SUMS` is verified independently in both test suites before any body comparison, so a corrupted fixture fails fast.
4. The TypeScript repo pins the upstream Rust commit in `tests/UPSTREAM_AGENT_HOOKS_RS_COMMIT`, and this repo pins the merged TypeScript fixture source in `contract-fixtures/UPSTREAM_AGENT_HOOKS_TS_COMMIT`, so drift is traceable in either direction.

This guarantees that both implementations produce identical authorize requests for the same inputs, which is the minimum bar for cross-language interoperability under a single Sigil policy.

The separate `contract-fixtures/response-v1/` corpus pins the immutable Phase
0 receipt digests plus canonical Policy 2.2 source, compiled payload, decision,
and negative vectors. Rust parses and reserializes the positive format-1
payload and decision records byte for byte and rejects format 2 or undeclared
members. This demonstrates wire parity, not native policy evaluation.

The `contract-fixtures/response-v2/` corpus pins the exact Release 2 Warrant
Core and Agent Hooks candidates. Rust parses and reserializes the canonical
format-2 payload plus redact and observe decisions byte for byte, preserves
scanner evidence and mapped redaction metadata, and rejects format downgrade
or undeclared members. This remains schema parity only.

## CI pipeline

**rust-ci.yml** runs on every push to `main` and `session/**` branches, and on all pull requests:

- `cargo fmt --check` -- formatting gate
- `node scripts/decision-literal-gate.mjs` -- advisory runtime literal hygiene
- `node scripts/decision-architecture-gate.mjs` -- advisory adapter boundary
- `cargo clippy --workspace --all-features --all-targets -- -D warnings` -- lint gate
- `cargo test --workspace --all-features` -- unit + contract fixture tests
- `cargo deny check` -- license and dependency policy (see `deny.toml`)
- `cargo audit` -- advisory database scan

**publish-rust.yml** publishes to crates.io on `rs-v*` tags and on manual dispatch. It validates the tag version against `workspace.package.version` in Cargo.toml, then runs the dependency-ordered publisher. The publisher skips an exact crate version that is already available, publishes `sigil-agent-hooks-core` when needed, waits until Cargo can resolve that exact version from crates.io, and only then publishes `sigil-agent-hooks-ironclaw`. A rerun after a partial release therefore resumes instead of failing on the already-published core version.

## Design decisions

**Default fail mode is Closed.** The TypeScript package defaults to `Open` for backward compatibility with v0.1.0. The Rust crate starts fresh with no legacy behavior to preserve, so it defaults to `Closed` -- the safer posture for production use.

**No runtime TLS certificate bundling.** The crate uses `rustls-tls-native-roots` (reqwest feature) so it picks up the host system's certificate store. No vendored root certificates.

**Builder validation, not runtime panics.** Invalid config (non-HTTPS or non-root
origin, malformed policy pin, zero timeout) fails at
`SigilClientBuilder::build()` with a typed `SigilClientError::InvalidConfig`.
The constructed `SigilClient` is guaranteed valid.

**Response size cap.** Responses are streamed in chunks with a 64 KiB hard cap.
An oversized response is a reached invalid response: it is not parsed and can
never activate transport fail-open.

**IronClaw advisory ignores are scoped.** `ironclaw` 0.24.0 is the latest
published crates.io release and pulls optional assistant/runtime dependencies
into the lockfile. `deny.toml` and `.cargo/audit.toml` ignore specific RustSec
advisories only because `sigil-agent-hooks-ironclaw` imports hook traits and
does not instantiate IronClaw model runners, PDF parsing, terminal rendering,
QUIC endpoints, or Wasmtime engines. Revisit the ignores as soon as a newer
IronClaw crate is published.
