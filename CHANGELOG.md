# Changelog

## 0.5.0

- Make signed decision verification the default enforcement mode and require
  an exact policy-hash pin at build time.
- Keep explicit warn mode as the rollback compatibility path.
- Preserve the existing transport fail-mode contract independently of signed
  response verification.
- Add a deterministic 29-case enforcement batch and named verifier drills.
- Run decision literal and architecture gates in blocking mode.
- Treat `APPROVED` as a deprecated, deserialize-only input alias and never
  emit it.

The source batch is a prepublication check. Exact crates.io artifacts and the
fresh-install release harness remain required after publication.
