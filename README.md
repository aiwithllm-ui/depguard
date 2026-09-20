# DepGuard

**Know what changes before a dependency enters your application.**

DepGuard is a local-first trust and compatibility layer for software dependencies. It creates baseline and candidate twins of an npm project, runs configured checks in equivalent isolated environments, compares observable evidence, inspects package deltas, and emits a versioned evidence document.

It answers a narrower, more useful question than “is this package safe?”:

> What changed when this repository moved from this exact dependency version to that one, and what reproducible evidence supports the result?

## What makes it different

| Tool | Primary question |
| --- | --- |
| Dependabot / Renovate | What can I update? |
| npm audit / OSV | Does a known vulnerability affect a dependency? |
| CI | Does the current pipeline pass? |
| **DepGuard** | What changes in **this application** for **this dependency transition**? |

DepGuard does not produce an opaque “trust score” and never claims a dependency is absolutely safe.

## Quick start

Requires Node.js 20+ for this MVP. The default verifier requires Docker or Podman; it will not run repository or dependency code directly on the host.

```bash
npm install
npm test
node bin/depguard.js init
node bin/depguard.js doctor
node bin/depguard.js verify axios@1.9.1
```

The package also exposes `depguard` when installed as a CLI package:

```bash
depguard scan
depguard verify axios@1.9.1 --json --output evidence.json
depguard report
```

For controlled development fixtures only, use `--unsafe-host-execution`. This escape hatch emits a prominent evidence flag and disables the claim that code was isolated. It should never be the normal developer or CI path.

## Architecture

```text
Package registry ──> factual package delta ──────────────┐
                                                         │
Your repository ──> baseline twin ──> configured checks ─┼─> behavior diff ─> evidence
                 └> candidate twin ─> configured checks ─┘                     │
                                                                                └> future signed attestation
```

The OCI execution backend uses a temporary project copy, a non-networked container, a read-only container filesystem, dropped capabilities, `no-new-privileges`, PID/memory/CPU limits, and a constrained writable workspace. The project source itself is never uploaded.

## Current MVP scope

- npm-family project detection: npm, pnpm, and Yarn lockfiles
- direct dependency transition discovery from manifests/`package-lock.json`
- controlled registry metadata lookup or supplied offline metadata
- lifecycle-script, dependency-count, and license delta evidence
- baseline/candidate workspace execution of build, test, typecheck, and lint
- portable filesystem and timing comparison
- JSON evidence (`schemas/compatibility-evidence/v1.schema.json`) and human report
- stable exit statuses: `0` verified, `10` review, `20` failed, `30` suspicious, `40` environment failure

Network tracing, OSV/deps.dev providers, deep process tracing, DSSE signing, and the global evidence service are deliberately separated extension points; they are not simulated as completed features. See [ROADMAP.md](ROADMAP.md).

## Configuration

`depguard init` creates an inspectable `depguard.yaml`. Projects with no configuration are still useful: scripts named `build`, `test`, `typecheck`, and `lint` are detected automatically.

```yaml
version: 1
verify:
  commands:
    build: npm run build
    test: npm test
sandbox:
  network: deny
  memory: 4GiB
  cpus: 2
  timeout: 20m
privacy:
  publishEvidence: false
```

## Privacy

Local verification does not upload source, fixtures, environment values, or raw application logs. Reports use an anonymized local project fingerprint. The future publication pathway is opt-in only and must sanitize evidence before signing.

## Development

```bash
npm test
npm run lint
```

The fixtures cover a verified update, a real application-level breaking transition, and a new lifecycle script that requires review.

Read [the threat model](docs/security/threat-model.md), [architecture notes](docs/architecture/local-verifier.md), and [contributing guide](CONTRIBUTING.md) before extending sandboxing or evidence code.
