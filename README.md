# agent-hooks-rs

Rust crates for Sigil pre-tool authorization.

This repository is the separate Rust home for `@sigilcore/agent-hooks-rs`. It
keeps the existing `agent-hooks` npm repository focused on the TypeScript
package while providing:

- `sigil-agent-hooks-core`: generic Rust client for Sigil `/v1/authorize`
- `sigil-agent-hooks-ironclaw`: native IronClaw hook adapter built on the core
  crate

The canonical design lives in
[docs/plans/2026-04-17-agent-hooks-rs-v0.1.0.md](docs/plans/2026-04-17-agent-hooks-rs-v0.1.0.md).
