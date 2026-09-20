# Contributing to DepGuard

Thanks for helping make dependency-upgrade evidence more useful and reproducible. DepGuard is Rust-first and npm-first in this alpha.

## Prerequisites and local setup

- Rust 1.88+ with `cargo` and `rustfmt`.
- Docker with a running daemon for verifier system tests and real `depguard verify` runs.
- Node.js 20+ and npm for npm fixtures and sandboxed npm verification.
- PostgreSQL 16+ only for the isolated network integration test. `docker compose up postgres` is a convenient local option.

Start from a clean clone; no private registry, database, or Sigstore credentials are needed for normal development:

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace
```

Run the PostgreSQL trust-boundary test separately against an empty disposable database:

```bash
docker compose up -d postgres
DATABASE_URL=postgresql://depguard:depguard@localhost:5432/depguard \
  cargo test -p depguard-server --test postgres_network -- --ignored
docker compose down -v
```

## Project map

- `crates/depguard-cli`: public `depguard` CLI.
- `crates/depguard-*`: verifier, npm resolution, sandboxing, observation, evidence, attestation, network client/server, and policy crates.
- `schemas/` and `fixtures/protocol/`: public V1 schemas and golden protocol inputs.
- `fixtures/`: self-contained npm and registry fixtures.
- `docs/`: architecture, protocols, threat model, ADRs, and network documentation.
- `.github/`: deterministic CI, release automation, and community templates.

## Tests and documentation

Add a focused unit test next to the behavior it protects. Put end-to-end CLI tests in `crates/depguard-cli/tests`, and keep fixtures self-contained and free of accidental network assumptions. The Docker-backed system test skips when Docker is unavailable; CI still runs all ordinary workspace tests. Update the relevant public documentation whenever CLI behavior, prerequisites, or limitations change.

## Frozen V1 protocol rules

Compatibility Evidence V1, Canonicalization V1, Attestation V1, and Verification Methodology V1 are frozen. Do not casually change their schema, wire fields, canonical bytes, typed verification errors, exit semantics, or golden fixtures. Normal CI runs the V1 conformance tests.

Propose any protocol change in an issue first. Explain compatibility impact, migration and test vectors. A maintainer-approved ADR and a new versioned protocol path are required for a semantic change; this alpha does not authorize a V2 implementation.

## Pull requests

Keep pull requests small and explain the user-visible effect. Before submitting, run the commands above, add or update tests, update docs where needed, and explicitly state whether V1 protocol semantics are unchanged. Discuss sandbox, privacy, security-boundary, or evidence-schema changes before implementation. By submitting a contribution, you agree to license it under [Apache-2.0](LICENSE).

## Good first contributions

Good community-sized work includes additional npm fixtures, test coverage, documentation corrections, platform compatibility investigation, observer improvements, OSV/deps.dev provider improvements, network API client improvements, and groundwork for a future ecosystem adapter. Do not add new ecosystems, Compatibility Packs, federation, or a web explorer as drive-by alpha changes; propose them first.
