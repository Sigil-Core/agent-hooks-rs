# Decision vocabulary Wave 0 evidence

Date: 2026-08-21

## Baseline and classification

- Repository: `sigilcore/agent-hooks-rs`
- Baseline commit: `54b37cc383513c3c78eb2b8d9136f7b7e21a30eb`
- Baseline branch state: local worktree and fetched `origin/main` matched exactly.
- Raw `APPROVED` inventory: 16 occurrences in 7 files.

| Classification | Files | Occurrences | Disposition |
| --- | ---: | ---: | --- |
| Runtime gate decision | 1 | 1 | Widen input to `APPROVED` or `ALLOWED`; serialize and route as `ALLOWED`. |
| Tests and fixtures, including tests embedded in runtime modules | 5 | 12 | Retain alias coverage; convert canonical output and normal cases to `ALLOWED`. |
| Current documentation | 1 | 2 | Convert to `ALLOWED`; keep one repository deprecation note in README. |
| Historical plan | 1 | 1 | Preserve as historical evidence. |

The category file counts overlap because `client.rs` contains one runtime
match and one test-only match. The baseline has seven unique matching files.

### Exact baseline artifact

Every baseline occurrence is classified below by its original line. The line
numbers bind the classification to commit
`54b37cc383513c3c78eb2b8d9136f7b7e21a30eb` and are not current-worktree line
numbers.

| Baseline file and line | Occurrences | Classification |
| --- | ---: | --- |
| `architecture.md:31,59` | 2 | Current documentation |
| `crates/sigil-agent-hooks-core/src/client.rs:307` | 1 | Runtime authorization decision |
| `crates/sigil-agent-hooks-core/src/client.rs:482` | 1 | Unit-test fixture embedded under `cfg(test)` |
| `crates/sigil-agent-hooks-core/src/model_usage.rs:290` | 1 | Unit-test fixture embedded under `cfg(test)` |
| `crates/sigil-agent-hooks-core/tests/client_behavior.rs:123,268,310,333,367` | 5 | Authorization test/fixture |
| `crates/sigil-agent-hooks-core/tests/contract_fixtures.rs:41` | 1 | Contract test/fixture |
| `crates/sigil-agent-hooks-ironclaw/src/lib.rs:310,460,485,508` | 4 | Adapter tests embedded under `cfg(test)` |
| `docs/plans/2026-04-17-agent-hooks-rs-v0.1.0.md:169` | 1 | Historical implementation plan |

Reconciliation: 7 unique files, 16 occurrences. Runtime authorization is 1,
tests and fixtures are 12, current documentation is 2, and the historical
implementation plan is 1. Foreign-domain count is zero.

## Release channel go/no-go

- `.github/workflows/publish-rust.yml` is the recorded crates.io channel.
- Release tags use `rs-v*` and must match `workspace.package.version`.
- The workflow publishes `sigil-agent-hooks-core`, waits 30 seconds for index
  propagation, then publishes `sigil-agent-hooks-ironclaw`.
- Both crates use the `CARGO_REGISTRY_TOKEN` environment variable backed by the
  workflow environment secret.
- Live `cargo search` on 2026-08-20 reported `0.2.0` for both crates.
- Repository main was version `0.3.0`; this compatibility release is `0.4.0`.
- Local `cargo owner --list` could not authenticate because no registry token is
  installed. The publish workflow owns release credentials, so authenticated
  owner and publish proof remain a release-time gate. No credential was created
  or modified locally.

Result: the channel and concrete publish steps are resolved. Publication remains
blocked until the coordinated Wave 1 release and its mandatory review gates.

## Shared fixture source

The fixture source is the merged TypeScript consumer change:

- Source repository: `https://github.com/Sigil-Core/agent-hooks`
- Merged source commit: `fdcd04f75be762827d84359c31cda1dbede9ded1`
- Machine-readable downstream pin:
  `contract-fixtures/UPSTREAM_AGENT_HOOKS_TS_COMMIT`
- `contract-fixtures/v1/decision-records.json` SHA-256:
  `f8abe5060f44ce5cbc83047f1513107a18d5e50c8695d40f48ea6c5bd52df28a`
- `diff -ru` between the TypeScript and Rust `contract-fixtures/v1` trees:
  zero differences.
- `sha256sum -c contract-fixtures/v1/SHA256SUMS`: all entries passed.
- The Rust test suite requires a 40-hex commit pin and the exact merged commit
  above, in addition to fixture checksums and behavior parity.

## Deployed-component by wave compatibility matrix

`sigil-agent-hooks-core` and `sigil-agent-hooks-ironclaw` are separately
published crates, so both appear even though IronClaw delegates verification
to core. "Wire only" means the build parses the response but is not an eligible
Wave 3 posture because it still permits the legacy path.

| Deployed component/build | Wave 0: legacy unsigned emitter | Wave 1: widened consumers | Wave 2: signed `ALLOWED` emitter | Wave 3: enforced consumers | Wave 4: cleanup |
| --- | --- | --- | --- | --- | --- |
| Published `sigil-agent-hooks-core@0.2.0` | Compatible | Compatible until replacement | Incompatible: `ALLOWED` is unknown | Incompatible | Incompatible |
| Published `sigil-agent-hooks-ironclaw@0.2.0` | Compatible through core `0.2.0` | Compatible until replacement | Incompatible through core `0.2.0` | Incompatible | Incompatible |
| Repository-baseline `sigil-agent-hooks-core@0.3.0` | Compatible | Compatible until replacement | Incompatible: `ALLOWED` is unknown | Incompatible | Incompatible |
| Repository-baseline `sigil-agent-hooks-ironclaw@0.3.0` | Compatible through core `0.3.0` | Compatible until replacement | Incompatible through core `0.3.0` | Incompatible | Incompatible |
| `sigil-agent-hooks-core@0.4.0`, warn mode | Compatible: normalize alias and issue only a legacy capability | Compatible, required deployment posture | Compatible: verify record and attestation and issue a verified capability | Wire only, prohibited as final Wave 3 posture | Wire only, prohibited as final posture |
| `sigil-agent-hooks-ironclaw@0.4.0`, warn mode | Compatible through core `0.4.0` | Compatible, required deployment posture | Compatible through verified core capability | Wire only, prohibited as final Wave 3 posture | Wire only, prohibited as final posture |
| `sigil-agent-hooks-core@0.4.0`, enforce mode | Incompatible by design: unsigned allow denies | Incompatible by design until the emitter signs | Compatible | Compatible, required deployment posture | Compatible |
| `sigil-agent-hooks-ironclaw@0.4.0`, enforce mode | Incompatible by design through core | Incompatible by design until the emitter signs | Compatible | Compatible, required deployment posture | Compatible |

### Phase 1 response contract

| Input or condition | Warn mode | Enforce mode |
| --- | --- | --- |
| Signed canonical `ALLOWED` with valid execution attestation | Canonical `ALLOWED`; verified capability | Canonical `ALLOWED`; verified capability |
| Signed deprecated `APPROVED` record literal | Reject literal mismatch | Reject literal mismatch |
| Unsigned body `APPROVED` or `ALLOWED` | Canonical `ALLOWED`; distinct legacy capability; `record_missing` log | `DENIED`; no capability; `record_missing` log |
| Invalid signature, binding, profile, nonce, or key | Preserve non-executing outcome; never mint verified capability | `DENIED`; no capability |
| No-response transport fail-open | Canonical `ALLOWED`; non-counterfeit `LegacyUnverifiedAuthorization`; `fail_open` records transport provenance | Unchanged transport policy; the same non-counterfeit legacy capability records transport provenance |
| Reached non-success status except valid 403 denial, malformed or oversized body, or body-protocol failure | `DENIED`; no capability; never transport fail-open | `DENIED`; no capability; never transport fail-open |
| Valid HTTP 403 `DENIED` | Parse policy denial and verify a decision record when present | Parse policy denial and require a valid record when present |
| HTTP 401 or malformed/non-`DENIED` HTTP 403 | `SIGIL_AUTH_FAILURE`; no capability | `SIGIL_AUTH_FAILURE`; no capability |
| `DENIED` or `PENDING` | Never executable | Never executable |

Execution adapters receive only the opaque authorization capability. They do not
branch on raw decision literals or call the verifier directly.

The finalized contract defines `VerifiedAuthorization` and one distinct
`LegacyUnverifiedAuthorization`; it does not define a third transport-specific
capability. Warn-mode verification fallback and documented transport fail-open
therefore share the legacy capability kind, while `fail_open` distinguishes the
transport path. Neither path can counterfeit the verified capability.

## Local gate evidence

- Shared decision vectors: 22 minimum enforced; all expected results pass.
- Shared-fixture time is fixed at `2000000000`. The `hold_resolve` record was
  issued at that second and records resolution at `2000000001`; the finalized
  contract requires `resolvedAt` on this surface but does not define an ordering
  constraint against `iat`. Rust preserves the exact upstream fixture bytes and
  does not regenerate the signed token downstream.
- Malformed JOSE vectors: 6 minimum enforced; all fail closed.
- Trust bootstrap: static TLS root origin, response-origin rejection, pinned-key
  precedence, redirect rejection, five-minute cache expiry, 64 KiB response and
  16-key limits, cold-cache outage, and rotation overlap are covered. Custom
  test roots require the non-default `test-certificates` feature and are absent
  from default production builds. The leaf certificate is valid from
  `2026-08-21T03:36:00Z`
  (`2026-08-20T23:36:00-04:00`) through `2036-08-18T03:36:00Z`; live TLS
  handshakes use the system clock, so the evidence date is inside that interval.
- Capability gate: external construction, deserialization, and cloning fail to
  compile through six cross-platform Rustdoc negative examples for both
  `VerifiedAuthorization` and the public execution-bearing
  `AuthorizationCapability` wrapper.
- Literal gate: zero runtime violations; a planted literal fixture proves the
  gate exits non-zero when blocking.
- Architecture gate: execution adapters contain no forbidden verifier or raw
  decision imports; raw Ed25519 and compact-JWS primitives are confined to
  `crates/sigil-agent-hooks-core/src/decision.rs`. Separate forbidden-import
  and forbidden-crypto fixtures prove both restrictions detect violations.
- Verification latency is reported over 1,000 iterations as advisory evidence
  and does not block a healthy build on a noisy runner.

Final full-workspace, clippy, dependency-policy, audit, packaging, and YAML checks
are recorded in the coordinated execution closeout rather than frozen here.

## Hosted-CI correction and review disposition

- The cross-version capability proof now uses six Rustdoc `compile_fail`
  examples instead of target-specific `trybuild` diagnostic snapshots. Rust
  1.92.0 and the current stable toolchain both prove that external code cannot
  construct, clone, or deserialize either execution-bearing capability without
  depending on compiler wording or platform-specific type paths.
- The architecture gate rejects missing flag values and malformed rule-set
  shapes with exit code 2 before scanning. Its negative suite covers a missing
  `--root` value, a null top-level configuration, absent legacy paths, and
  non-array rule-set paths.
- The literal gate also rejects missing flag values with exit code 2 and scans
  only Rust files, whether a configured runtime path names a directory or an
  individual file. A non-Rust file containing a planted decision token proves
  the explicit-file filter.
- Rust CI invokes both decision gates with `--blocking`. Its change detector
  includes `rust-toolchain.toml`, `rustfmt.toml`, and `clippy.toml`, so a
  toolchain-policy change cannot skip the Rust job.
- `sigil-agent-hooks-core` is exact-pinned to `=0.4.0` in both the IronClaw
  normal and test dependency tables. Live crates.io metadata still reports
  IronClaw 0.24.0 as the newest release, so no unavailable upgrade or
  unsupported Wasmtime override was added. The approved unreachable-advisory
  disposition remains unchanged.
- The request for an unknown-key refresh cooldown is incompatible with the
  finalized amendment, which deletes key-miss cooldown, negative caching, and
  stampede controls. Rust retains byte- and behavior-level parity with that
  upstream contract.
- Rust 1.92.0 and current-stable full workspace tests pass. Raw evidence is
  `/tmp/agent-hooks-rs-followup-final-msrv.txt` at SHA-256
  `28ba0c2280e8037125a6858bc9ac94495ac98241f3630952f3b342731309e246`
  and `/tmp/agent-hooks-rs-followup-final-current.txt` at SHA-256
  `f4ec1fe5e5b0497d53032715e640a15cc9b8dcede21a61dff096337abafdbd60`.
  Formatting, no-default checks, MSRV all-target/all-feature Clippy, current
  no-default Clippy, blocking gates, publisher matrix, dependency policy,
  audit, package verification/listing, YAML validation, and diff checks pass.

## Final-audit superseding evidence

- Builder validation rejects every non-HTTPS or non-root API URL before a
  request and requires every supplied policy pin to be exactly 64 lowercase
  hexadecimal characters. Enforce mode still requires the pin; warn mode
  without one emits the policy-binding diagnostic on every call.
- Only failure before any response enters configured transport fail mode.
  Live TLS seams prove HTTP 429 and 5xx, malformed JSON, a 64 KiB overflow, and
  a truncated body after headers deny under `FailMode::Open`, including enforce
  mode, without a capability or `fail_open` marker.
- Live HTTP 403 seams prove a valid unsigned `DENIED` policy result, a valid
  signed `DENIED` decision record under enforce mode, invalid record rejection,
  malformed-body authentication failure, and non-`DENIED` authentication
  failure. HTTP 401 remains an authentication failure.
- The complete workspace gate includes six independent external compile
  failures: construction, deserialization, and cloning for each of
  `VerifiedAuthorization` and `AuthorizationCapability`. Rustdoc checks only
  the required compilation failure, so compiler wording can differ by target
  and supported Rust version without weakening the negative proof.
- Formatting, advisory literal gate, blocking architecture gate, all-target and
  all-feature Clippy with warnings denied, dependency policy, audit, and
  `git diff --check` pass. Cargo audit reports zero vulnerabilities and the same
  seven repository-allowed transitive warnings.
