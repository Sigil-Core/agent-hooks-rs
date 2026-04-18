# Architecture

`agent-hooks-rs` is a Cargo workspace containing two crates that provide Rust-native pre-tool authorization against the Sigil Sign `/v1/authorize` API.

## Workspace layout

```
agent-hooks-rs/
  Cargo.toml                          # workspace root
  contract-fixtures/v1/               # shared wire-format fixtures
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
4. Parse the response into a typed `SigilResult` (`Approved`, `Denied`, or `Pending`).
5. Classify unreachability (network error, timeout, 5xx, non-JSON body, oversized response) through the configured `FailMode` -- `Closed` returns `DENIED` + `SIGIL_UNREACHABLE`; `Open` returns `APPROVED` + `fail_open: true`.
6. Build structured rejection context (`build_rejection_context`) that agents can consume without parsing free text. Three distinct paths: policy denial, consensus hold (PENDING), and transient unreachability.

Authentication failures (401/403) are classified as `SIGIL_AUTH_FAILURE`, not unreachability, so operators can distinguish credential issues from infrastructure failures in telemetry.

The client is constructed through a builder (`SigilClient::builder`) that validates config at build time (URL parsing, non-zero timeout) and produces a reusable `SigilClient` with an internal `reqwest::Client`.

### sigil-agent-hooks-ironclaw

Implements IronClaw's `Hook` trait using `sigil-agent-hooks-core` as the authorization backend. Hooks into `BeforeToolCall` only.

Key components:

**`ToolIntentMapper` trait** -- translates IronClaw tool names and parameters into `SigilIntent`. The default mapper covers common tool-name aliases (`exec`/`process`/`code_execution` to `bash`, `write`/`edit`/`apply_patch` to `file_write`, wallet actions, web fetch variants). Unknown tools pass through as lowercase strings so Sigil policies can address them without adapter changes.

**`IronclawSigilHook`** -- the `Hook` implementation. Built via `IronclawSigilHook::builder(client)`. If the client was constructed with the default `FrameworkId::AgentHooks`, the builder silently rebinds it to `FrameworkId::Ironclaw` so the authorize request carries the correct framework identifier. Non-tool events (e.g. `SessionStart`) pass through without an authorization call.

**Decision routing:** `APPROVED` returns `HookOutcome::ok()`. Both `DENIED` and `PENDING` return `HookOutcome::reject()` with a JSON-serialized `SigilRejectionContext` as the reason string. PENDING is deliberately not surfaced as a local approval prompt -- the hold must be resolved through Sigil Command.

## Wire parity with agent-hooks (TypeScript)

Both repositories share a set of contract fixtures (`contract-fixtures/v1/`) that pin the exact JSON wire format of `/v1/authorize` request bodies. The fixture files are checked into both repos and protected by SHA-256 checksums (`SHA256SUMS`).

The parity mechanism works as follows:

1. The Rust crate's `contract_fixtures.rs` tests build a `SigilClient`, call `check_intent` against a local mock server, capture the raw request body, and assert byte-equality against each fixture file.
2. The TypeScript package's `contract-fixtures.test.ts` does the same thing with `buildAuthorizeRequestBody`.
3. `SHA256SUMS` is verified independently in both test suites before any body comparison, so a corrupted fixture fails fast.
4. The TypeScript repo pins the upstream Rust commit in `tests/UPSTREAM_AGENT_HOOKS_RS_COMMIT` so a fixture drift is traceable.

This guarantees that both implementations produce identical authorize requests for the same inputs, which is the minimum bar for cross-language interoperability under a single Sigil policy.

## CI pipeline

**rust-ci.yml** runs on every push to `main` and `session/**` branches, and on all pull requests:

- `cargo fmt --check` -- formatting gate
- `cargo clippy --workspace --all-features --all-targets -- -D warnings` -- lint gate
- `cargo test --workspace --all-features` -- unit + contract fixture tests
- `cargo deny check` -- license and dependency policy (see `deny.toml`)
- `cargo audit` -- advisory database scan

**publish-rust.yml** publishes to crates.io on `rs-v*` tags and on manual dispatch. It validates the tag version against `workspace.package.version` in Cargo.toml, then publishes `sigil-agent-hooks-core` first (with a 30-second wait for crates.io index propagation) followed by `sigil-agent-hooks-ironclaw`.

## Design decisions

**Default fail mode is Closed.** The TypeScript package defaults to `Open` for backward compatibility with v0.1.0. The Rust crate starts fresh with no legacy behavior to preserve, so it defaults to `Closed` -- the safer posture for production use.

**No runtime TLS certificate bundling.** The crate uses `rustls-tls-native-roots` (reqwest feature) so it picks up the host system's certificate store. No vendored root certificates.

**Builder validation, not runtime panics.** Invalid config (bad URL, zero timeout) fails at `SigilClientBuilder::build()` with a typed `SigilClientError::InvalidConfig`. The constructed `SigilClient` is guaranteed valid.

**Response size cap.** Responses are streamed in chunks with a 64 KiB hard cap. An oversized response is classified as unreachable, not parsed.
