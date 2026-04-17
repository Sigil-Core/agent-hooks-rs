# `agent-hooks-rs` v0.1.0 Design

**Status:** Approved design, implementation in progress  
**Date:** 2026-04-17  
**Target release:** `rs-v0.1.0`

## Problem

`@sigilcore/agent-hooks` currently exists only as a TypeScript package. That covers Claude/Anthropic, ELIZA, LangChain, and future OpenClaw-style adapters, but it leaves Rust-native agent hosts without an in-process Sigil client.

IronClaw is the most important immediate gap. It already exposes a first-class Rust `Hook` trait and publishes a canonical crate on crates.io, but Sigil has no Rust package that can:

- serialize the same `/v1/authorize` wire contract as the TypeScript package
- apply the same unreachable classification rules
- surface Sigil denials, holds, and transient failures in a Rust-native integration
- enforce fixture-level parity so Rust and TypeScript do not silently drift

This repo exists to close that gap without changing the scope of the current `agent-hooks` npm repository.

## Goals

- Ship a public Rust home for `@sigilcore/agent-hooks-rs` as a separate repo.
- Provide a reusable Rust core client for Sigil `/v1/authorize`.
- Provide a native IronClaw adapter built on the canonical published `ironclaw` crate.
- Keep the Rust wire contract byte-for-byte compatible with the TypeScript package through shared fixtures.
- Make Rust defaults explicit and security-oriented: fail closed by default, shorter default timeout, documented divergence from TypeScript.
- Publish two crates on crates.io with lockstep v1 versions and documented release tags.

## Non-goals

- Moving the TypeScript `agent-hooks` repo into a polyglot monorepo.
- Implementing OpenClaw or NemoClaw Rust adapters.
- Shipping N-API, WASM, Python, or FFI bindings.
- Adding automatic in-process approval resume for Sigil holds in IronClaw.
- Replacing the TypeScript package as the canonical JS integration surface.

## Open Source First Baseline

The v1 design is intentionally built as a thin Sigil-specific delta on top of existing open source components:

- `nearai/ironclaw` is public and dual-licensed `MIT OR Apache-2.0`.
- `openclaw/openclaw` is public and MIT-licensed.
- `ironclaw 0.24.0` is published on crates.io and is the canonical upstream Rust dependency for the adapter.
- The core crate uses `reqwest` directly; no middleware abstraction is introduced in v1.

No existing crate was found that already provides Sigil-specific pre-tool authorization for Rust hosts, so this repo implements only the missing Sigil layer.

## Repo Setup

### Repository shape

`agent-hooks-rs` is a new **public** sibling repo. It does not modify the repo identity of `agent-hooks`, which remains the npm package repo.

Root files:

- `Cargo.toml`
- `Cargo.lock`
- `LICENSE`
- `README.md`
- `docs/plans/2026-04-17-agent-hooks-rs-v0.1.0.md`
- `.github/workflows/rust-ci.yml`
- `.github/workflows/publish-rust.yml`
- `deny.toml`

Workspace members:

- `crates/sigil-agent-hooks-core`
- `crates/sigil-agent-hooks-ironclaw`

### MSRV

MSRV is pinned to **Rust 1.92**. This is deliberate, not aspirational: published `ironclaw 0.24.0` declares `rust-version = "1.92"` in its manifest, so the adapter cannot promise lower while directly depending on canonical IronClaw.

### Publishing

- Publish to crates.io via CI on tags matching `rs-v*`
- First release tag: `rs-v0.1.0`
- Both crates version together in v1
- `ironclaw` dependency is pinned to `^0.24`
- Future `0.25.x+` upgrades are deliberate human-reviewed dependency bumps, not auto-merged bot updates

### Documentation updates

As part of new-repo setup:

- add `agent-hooks-rs` to the Sigil repository index in `agents-global.md`
- run the Sigil documentation-sync process so repo copies remain aligned

## Design

### 1. Core crate: `sigil-agent-hooks-core`

The core crate is the single place that owns the Rust wire contract, default behavior, unreachable classification, and rejection-context generation.

#### Public API

- `SigilClientBuilder`
- `SigilClient`
- `SigilConfig`
- `SigilIntent`
- `SigilDecision`
- `SigilResult`
- `SigilRejectionContext`
- `FailMode`
- `FrameworkId`
- `SIGIL_UNREACHABLE`
- `build_rejection_context`

#### Wire contract

The serialized `/v1/authorize` body must match the TypeScript package exactly:

```json
{
  "framework": "agent-hooks",
  "agentId": "agent",
  "txCommit": "<sha256-hex>",
  "chainId": 1,
  "intent": {
    "action": "wallet.transfer",
    "targetAddress": "0xabc",
    "amount": "1000000000000000000"
  }
}
```

Absent optional fields are omitted from the JSON body and from the auto-generated `txCommit` preimage; they are not serialized as `null`.

Top-level fields:

- `framework`
- `agentId`
- `txCommit`
- `chainId`

Nested intent fields:

- `action`
- `command`
- `url`
- `path`
- `targetAddress`
- `amount`
- `metadata`

#### Defaults

- `FailMode::Closed`
- default request timeout: `5s`
- default framework: `"agent-hooks"`
- default agent id: `"agent"`

#### Unreachable classification

The core client treats the following as Sigil unreachability:

- transport failures
- refused connection / DNS failure
- timeout
- non-JSON response body
- HTTP `5xx`

The core client does **not** treat `401` or `403` as unreachable. Those return `DENIED` with `SIGIL_AUTH_FAILURE`.

#### Fail-mode behavior

If Sigil is unreachable:

- `FailMode::Open` returns `APPROVED` with `fail_open = true`
- `FailMode::Closed` returns `DENIED` with `error_code = SIGIL_UNREACHABLE`

#### `FrameworkId`

`FrameworkId` includes known named variants plus `Custom(String)`, but it serializes as a **bare string**, never a tagged Rust enum object. This preserves parity with the TypeScript `framework` field, which remains a free string at the wire level.

Examples:

- `FrameworkId::Ironclaw` -> `"ironclaw"`
- `FrameworkId::Custom("custom-host".into())` -> `"custom-host"`

#### Rejection context

`build_rejection_context` lives in the core crate so generic Rust hosts and the IronClaw adapter both use the same operator-facing text.

Special case:

- `SIGIL_UNREACHABLE` must describe a transient infrastructure failure, not a policy violation

### 2. IronClaw adapter crate: `sigil-agent-hooks-ironclaw`

The adapter crate provides a native IronClaw implementation on top of the shared core crate.

#### Dependency model

- depend on `ironclaw = ^0.24`
- use IronClaw’s exported `Hook` trait and `HookEvent` types

#### Hook scope

The adapter only intercepts `HookEvent::ToolCall`. All other IronClaw events return `HookOutcome::ok()`.

#### Adapter defaults

- framework id: `"ironclaw"`
- `failure_mode()` returns `FailClosed`
- `timeout()` returns the configured Sigil request timeout

#### Default tool-to-action map

- `exec`, `process`, `code_execution` -> `bash`
- `write`, `edit`, `apply_patch` -> `file_write`
- `web_fetch`, `web_search`, `x_search`, `browser`, `http` -> `web_fetch`
- `wallet_transfer`, `wallet.transfer` -> `wallet.transfer`
- `wallet_sign` -> `wallet_sign`
- unknown names -> lowercase passthrough

#### Parameter extraction

The adapter extracts and forwards:

- `command`
- `url`
- `path`
- `to`
- `amount`
- `chainId`

It also copies the full original tool parameters into `metadata`.

#### Customization

The adapter exposes a `ToolIntentMapper` trait or equivalent callback so hosts can override the default tool mapping without forking the crate.

#### `PENDING` behavior

IronClaw’s hook surface does not expose a native “approval required” outcome. In v1:

- Sigil `PENDING` returns `HookOutcome::Reject`
- the reject payload is structured JSON from `SigilRejectionContext`
- the payload includes `hold_id`
- operator workflow is explicit: approve in Sigil, then manually rerun the same action

No native approval UI or in-process resume is attempted in v1.

### 3. Contract safety

This repo is the canonical source of fixture truth for the Rust/TypeScript wire contract.

Canonical fixtures live under:

- `contract-fixtures/v1/bash.json`
- `contract-fixtures/v1/web_fetch.json`
- `contract-fixtures/v1/wallet.transfer.json`
- `contract-fixtures/v1/intent_agent_override.json`
- `contract-fixtures/v1/SHA256SUMS`

Rules:

- fixture files are pretty-printed in fixed format
- Rust tests compare actual HTTP request bodies byte-for-byte against those files
- the TypeScript repo vendors the same files under `tests/contract-fixtures/v1/`
- the TypeScript repo stores `UPSTREAM_AGENT_HOOKS_RS_COMMIT`
- TypeScript CI compares actual HTTP request bodies byte-for-byte against the vendored fixtures

Release gate:

- Rust `v0.1.0` cannot ship until the TypeScript fixture-parity PR is merged and both repos are green against the same fixture version

Any future wire-contract change requires:

- fixture update in `agent-hooks-rs`
- merged TypeScript parity PR updating vendored fixtures
- contract trace in both repos before release

## Divergences From TypeScript

| Area | TypeScript `@sigilcore/agent-hooks` | Rust `agent-hooks-rs` v0.1.0 | Rationale |
|---|---|---|---|
| Default fail mode | `open` | `closed` | Rust v1 targets security-sensitive in-process hosts first |
| Default timeout | `10_000ms` in the v0.2.0 design | `5s` | Align with IronClaw hook expectations and keep hook latency bounded |
| `PENDING` in host adapter | OpenClaw maps to native approval UI | IronClaw maps to structured reject | IronClaw has no native approval result surface |
| Framework typing | Free string in config | typed `FrameworkId` that serializes as a bare string | Stronger Rust API without changing wire format |

These are intentional product decisions, not accidental mismatches.

## Verification

### Rust CI

CI runs:

- `cargo fmt --check`
- `cargo clippy --workspace --all-features --all-targets`
- `cargo test --workspace --all-features`
- `cargo deny check`
- `cargo audit`

CI uses `Swatinem/rust-cache`.

### Core tests

- approved / denied / pending happy paths
- `401` / `403` auth failure classification
- network error, timeout, JSON parse error, and `5xx` as unreachable
- fail-open vs fail-closed branching
- `fail_open` only on open-mode unreachable approvals
- `FrameworkId::Custom(String)` serializes as a bare string
- fixture checks and SHA-256 checksum checks

### IronClaw adapter tests

- non-tool events pass through
- approved tool calls continue
- denied tool calls reject with Sigil metadata
- pending tool calls reject with `hold_id` and retry guidance
- unreachable in closed mode rejects with `SIGIL_UNREACHABLE`
- custom mapper overrides default map
- unknown tools lowercase-pass through

### Integration tests

- local mock Sigil server validates exact wire shape
- timeout and `5xx` behavior under both fail modes
- synthetic `HookEvent::ToolCall` round-trip through the IronClaw adapter

## Assumptions and Defaults

- This separate-repo strategy intentionally replaces the earlier monorepo sketch.
- The product-facing name can remain `@sigilcore/agent-hooks-rs`, while Cargo package names stay Rust-native.
- v1 does not include OpenClaw/NemoClaw Rust adapters.
- v1 does not include FFI or multi-language bindings.
- v1 does not implement automatic approval resumption for IronClaw holds.
- This is a public repo and must not contain internal infrastructure details, secret names, IPs, or hostnames.
