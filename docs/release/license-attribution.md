# Binary license attribution

`v0.1.0-alpha.1` publishes the `depguard` CLI for Linux x86_64, macOS arm64,
and macOS x86_64. `THIRD_PARTY_LICENSES.html` is the reproducible attribution
bundle for those binaries. It is not an SBOM and it does not replace
`Cargo.lock` or release metadata.

The notice intentionally includes runtime dependencies and target-specific
runtime dependencies only. `about.toml` excludes build dependencies and
development/test dependencies because they do not enter the distributed
binary. `deny.toml` checks the workspace policy independently and fails on an
unlicensed, unrecognized, unknown-registry, or unknown-git dependency.

## Regenerate and verify

Install the pinned tooling, then run these commands from the repository root:

```bash
cargo install --locked cargo-about --version 0.9.2 --features cli
cargo install --locked cargo-deny --version 0.20.2
cargo about generate --locked --fail \
  --manifest-path crates/depguard-cli/Cargo.toml \
  --config about.toml \
  licenses/third-party-licenses.hbs \
  --output-file THIRD_PARTY_LICENSES.html
cargo deny check licenses
```

For a no-write freshness check, generate to a temporary path with the same
command and compare it with `THIRD_PARTY_LICENSES.html`. CI performs that
comparison. If either tool reports an unrecognized or disallowed license, do
not add a broad allow rule: inspect the crate's published license material and
record a narrowly scoped, reviewable decision or flag it for human review.

The v0.1.0-alpha.1 release graph deliberately permits MIT-0 for
`borrow-or-share 0.2.4` and CDLA-Permissive-2.0 for the `webpki-roots` trust
store (`1.0.9`). They are listed individually here because they are not covered
by the usual Apache-2.0/MIT dual-license pattern; their complete license texts
are included in the generated attribution. No unrecognized license metadata is
overridden by this policy.
