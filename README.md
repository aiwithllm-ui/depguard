# DepGuard

DepGuard is a local-first verifier for npm dependency upgrades. It creates equivalent baseline and candidate project twins, runs their configured checks in a hardened Docker sandbox, compares what it can observe, and emits versioned Compatibility Evidence V1.

It exists to answer a practical, deliberately narrow question: **what changed for this project when a direct dependency moved between two exact versions?** DepGuard produces evidence and policy findings; it does not guarantee a dependency is safe or prove that a package is secure.

## Status: alpha, npm-first

`v0.1.0-alpha.1` supports npm projects with `package.json` and a direct dependency. The local verifier, frozen V1 evidence/attestation protocols, opt-in PostgreSQL-backed network MVP, and GitHub Actions Sigstore identity path are implemented. The public API and operational details may still change outside the frozen V1 protocol contracts.

```text
dependency upgrade
      ↓
baseline / candidate twins
      ↓
sandboxed verification
      ↓
Compatibility Evidence V1
      ↓
Attestation V1
      ↓
optional publish
      ↓
global compatibility network
```

## Five-minute quick start

Prerequisites:

- Rust 1.88 or newer (the locked workspace is the source of truth).
- Docker with a running daemon for `verify`; the current sandbox backend invokes Docker directly.
- Node.js 20+ and npm, both for your npm project and inside the default `node:20-alpine` sandbox image.
- PostgreSQL is needed only to develop or test the optional network MVP.

From a clean checkout:

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo run -p depguard-cli -- doctor
```

For a real verification, build the release CLI and point it at an npm project with the dependency already declared directly:

```bash
cargo build --release --locked -p depguard-cli
./target/release/depguard doctor
./target/release/depguard verify lodash@4.17.21 --project /path/to/npm-project \
  --evidence-out evidence.json
```

`verify` prints evidence (or JSON with `--json`) and can persist the public Compatibility Evidence V1 document using `--evidence-out`. The controlled Docker-backed system test demonstrates a complete local verification path without an external package registry:

```bash
cargo test -p depguard-cli --test real_system -- --nocapture
```

Generate and independently verify a local development attestation without contacting a network service:

```bash
depguard key-generate --private-key local.key --public-key local.pub
depguard attest evidence.json --key local.key --output attestation.json
depguard attest-verify attestation.json --public-key local.pub
```

`local.key` is a local development key: protect it and do not commit it. Publish is optional and transmits only an already-signed attestation:

```bash
depguard publish attestation.json --url https://network.example.invalid
```

For the network MVP and its separate Sigstore CI identity wrapper, see [Network MVP](docs/network-mvp.md). A valid GitHub CI Sigstore identity authenticates that CI execution; it is not maintainer or release approval.

## Current Alpha Limitations

- npm is the primary implemented ecosystem; DepGuard does not yet support PyPI, Cargo, Maven, or NuGet verification.
- Full verification needs Docker and a running daemon. Podman is not currently invoked by the CLI backend.
- Process observation is sampled and partial. Network execution is denied by policy; it is not fully observed or recorded.
- External intelligence and provenance providers are incomplete; unavailable signals are reported rather than inferred.
- The global compatibility network is an opt-in PostgreSQL MVP, not a federation or public explorer.
- Sigstore CI identity validates a GitHub Actions identity when configured; it does not establish package ownership, maintainer approval, or release authorization.
- The command executes npm install and configured project scripts inside the sandbox. Review your project configuration and evidence before relying on a conclusion.

## Documentation and contributing

Start with the [documentation index](docs/README.md): it links the frozen V1 protocols, verifier architecture, threat model, network MVP, ADRs, governance, security policy, roadmap, and release notes.

Outside developers can use the standard Rust workflow:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo check --workspace
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. The four V1 protocols are frozen; application version `0.1.0-alpha.1` is intentionally independent of the V1 protocol identifiers.
