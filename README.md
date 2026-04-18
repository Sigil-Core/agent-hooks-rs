# agent-hooks-rs

Rust crates for Sigil pre-tool authorization. Intercepts an agent's intended tool call before it executes, submits it to the Sigil Sign `/v1/authorize` endpoint, and blocks or holds the action based on the policy decision.

This workspace provides two crates:

- `sigil-agent-hooks-core` -- generic Rust client for Sigil `/v1/authorize`
- `sigil-agent-hooks-ironclaw` -- native [IronClaw](https://github.com/nearai/ironclaw) `Hook` trait adapter

The companion TypeScript package lives at [`@sigilcore/agent-hooks`](https://github.com/Sigil-Core/agent-hooks). Both packages share contract fixtures that guarantee wire-format parity (see [architecture.md](./architecture.md)).

## Installation

```toml
# For direct Sigil client usage
cargo add sigil-agent-hooks-core

# For IronClaw integration
cargo add sigil-agent-hooks-ironclaw
```

Minimum supported Rust version: **1.92**.

## Prerequisites

You need a Sigil API key. Get one at [sigilcore.com/tools/keys](https://sigilcore.com/tools/keys).

## Quick Start

### sigil-agent-hooks-core

Use `SigilClient` directly when you want framework-agnostic pre-tool authorization in any Rust application.

```rust
use sigil_agent_hooks_core::{
    FailMode, SigilClient, SigilDecision, SigilIntent, build_rejection_context,
};

#[tokio::main]
async fn main() {
    let client = SigilClient::builder(std::env::var("SIGIL_API_KEY").unwrap())
        .agent_id("my-rust-agent")
        .fail_mode(FailMode::Closed)
        .build()
        .expect("valid config");

    let intent = SigilIntent {
        action: "bash".to_string(),
        command: Some("rm -rf /tmp/scratch".to_string()),
        ..SigilIntent::default()
    };

    let result = client.check_intent(&intent).await.expect("client error");

    match result.decision {
        SigilDecision::Approved => {
            // Proceed with tool execution
        }
        SigilDecision::Denied | SigilDecision::Pending => {
            let rejection = build_rejection_context(&result, &intent.action);
            eprintln!("Blocked: {}", rejection.sigil_message);
            // Feed rejection context back to the agent
        }
    }
}
```

### sigil-agent-hooks-ironclaw

For IronClaw agents, `IronclawSigilHook` implements the `Hook` trait and registers on `BeforeToolCall`. One line to wire it in:

```rust
use sigil_agent_hooks_core::{FailMode, SigilClient};
use sigil_agent_hooks_ironclaw::IronclawSigilHook;

let client = SigilClient::builder(std::env::var("SIGIL_API_KEY").unwrap())
    .agent_id("my-ironclaw-agent")
    .fail_mode(FailMode::Closed)
    .build()
    .expect("valid config");

let hook = IronclawSigilHook::builder(client)
    .build()
    .expect("hook build");

// Register with IronClaw:
// runtime.register_hook(hook);
```

The builder silently rebinds `FrameworkId::AgentHooks` to `FrameworkId::Ironclaw` so the authorize request carries the correct framework identifier.

#### Custom tool mapping

The default mapper covers common tool aliases (`exec`/`process`/`code_execution` to `bash`, `write`/`edit`/`apply_patch` to `file_write`, wallet and web fetch variants). Unknown tools pass through as lowercase strings.

To override mapping, implement `ToolIntentMapper`:

```rust
use sigil_agent_hooks_core::SigilIntent;
use sigil_agent_hooks_ironclaw::ToolIntentMapper;
use serde_json::Value;

struct MyMapper;

impl ToolIntentMapper for MyMapper {
    fn map_intent(
        &self,
        tool_name: &str,
        parameters: &Value,
        _user_id: &str,
        _context: &str,
    ) -> SigilIntent {
        SigilIntent {
            action: format!("custom.{tool_name}"),
            ..SigilIntent::default()
        }
    }
}

// Then:
// IronclawSigilHook::builder(client).mapper(MyMapper).build()
```

## Configuration

`SigilClient` is constructed through a builder that validates config at build time.

| Builder method | Type | Default | Description |
|---|---|---|---|
| `builder(api_key)` | `impl Into<String>` | (required) | Sigil API key (`sk_sigil_...`) |
| `.api_url(url)` | `impl Into<String>` | `https://sign.sigilcore.com` | Sigil Sign API URL |
| `.agent_id(id)` | `impl Into<String>` | `"agent"` | Identifier for this agent |
| `.framework(id)` | `FrameworkId` | `AgentHooks` | Framework identifier for the authorize request |
| `.fail_mode(mode)` | `FailMode` | `Closed` | Behavior when Sigil is unreachable |
| `.request_timeout(dur)` | `Duration` | `5s` | HTTP request timeout |

`SigilIntent` fields:

| Field | Type | Description |
|---|---|---|
| `action` | `String` | Tool action name (e.g. `bash`, `wallet.transfer`, `file_write`) |
| `agent_id` | `Option<String>` | Per-intent agent ID override (takes precedence over client config) |
| `chain_id` | `Option<u64>` | EVM chain ID for on-chain actions |
| `command` | `Option<String>` | Shell command (for `bash` actions) |
| `url` | `Option<String>` | Target URL (for `web_fetch` actions) |
| `path` | `Option<String>` | File path (for `file_write` actions) |
| `to` | `Option<String>` | Recipient address (for wallet actions) |
| `amount` | `Option<String>` | Transfer amount (for wallet actions) |
| `tx_commit` | `Option<String>` | Explicit intent commit hash; auto-generated if omitted |
| `metadata` | `Option<Value>` | Arbitrary JSON metadata forwarded to Sigil |

## Fail Modes

### `FailMode::Closed` (default)

Returns `SigilResult { decision: Denied, error_code: Some("SIGIL_UNREACHABLE"), .. }` when Sigil is unreachable. Use in production, for externally-visible actions, and for any on-chain or wallet action.

### `FailMode::Open`

Returns `SigilResult { decision: Approved, fail_open: true, .. }` when Sigil is unreachable. Use in development or non-financial workflows where a brief Sigil outage should not halt operations.

### What counts as unreachable

Network error, DNS failure, connection refused, request timeout, 5xx response, non-JSON response body, or response exceeding 64 KiB. Authentication failures (401/403) are classified as `SIGIL_AUTH_FAILURE`, not unreachability.

### Difference from the TypeScript package

The TypeScript package defaults to `FailMode::Open` for backward compatibility with v0.1.0. This crate defaults to `FailMode::Closed` because it has no legacy behavior to preserve.

## Graceful Agent Degradation

`build_rejection_context` produces a structured `SigilRejectionContext` that agents can consume without parsing free text. Three distinct paths:

**Policy denial:**
```json
{
  "sigil_decision": "DENIED",
  "sigil_error_code": "SIGIL_BASH_BLOCKED",
  "sigil_message": "rm -rf is not allowed by policy",
  "sigil_action_taken": "halted",
  "sigil_next_steps": "The action \"bash\" was blocked. Do not retry until the operator reviews the Sigil decision."
}
```

**Consensus hold (PENDING):**
```json
{
  "sigil_decision": "PENDING",
  "sigil_error_code": "SIGIL_CONSENSUS_HOLD_REQUIRED",
  "sigil_message": "Requires approval",
  "sigil_hold_id": "hold_123",
  "sigil_action_taken": "pending_approval",
  "sigil_next_steps": "This action is held in Sigil. An operator must approve it in Sigil before the exact same action is retried manually."
}
```

**Transient unreachability (FailMode::Closed only):**
```json
{
  "sigil_decision": "DENIED",
  "sigil_error_code": "SIGIL_UNREACHABLE",
  "sigil_message": "connection refused",
  "sigil_action_taken": "halted",
  "sigil_next_steps": "Sigil is temporarily unreachable - this is a transient infrastructure failure, not a policy denial. Restore connectivity to Sigil and retry the same action."
}
```

## Supported Frameworks

| Framework | Crate | Integration |
|---|---|---|
| Generic (any Rust host) | `sigil-agent-hooks-core` | Direct `check_intent` calls |
| IronClaw (nearai) | `sigil-agent-hooks-ironclaw` | Native `Hook` trait implementation |
| Claude Code / Anthropic SDK | [`@sigilcore/agent-hooks`](https://github.com/Sigil-Core/agent-hooks) | TypeScript adapter |
| ELIZA | [`@sigilcore/agent-hooks`](https://github.com/Sigil-Core/agent-hooks) | TypeScript adapter |
| LangChain | [`@sigilcore/agent-hooks`](https://github.com/Sigil-Core/agent-hooks) | TypeScript adapter |
| OpenClaw / NemoClaw | [`@sigilcore/agent-hooks`](https://github.com/Sigil-Core/agent-hooks) | TypeScript adapter |

## Wire Parity

Both this repo and `agent-hooks` (TypeScript) share contract fixtures in `contract-fixtures/v1/` that pin the exact JSON wire format of `/v1/authorize` request bodies. Fixture integrity is verified by SHA-256 checksums in both test suites. A mismatch in either language fails CI.

## Documentation

Full documentation: [docs.sigilcore.com](https://docs.sigilcore.com)

Get an API key: [sigilcore.com/tools/keys](https://sigilcore.com/tools/keys)

Architecture details: [architecture.md](./architecture.md)

## License

MIT
