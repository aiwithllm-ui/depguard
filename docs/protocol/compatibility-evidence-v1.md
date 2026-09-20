# Compatibility Evidence V1

Compatibility Evidence V1 is the public, canonical record produced by a DepGuard comparison. Its JSON Schema is [`schemas/compatibility-evidence/v1.schema.json`](../../schemas/compatibility-evidence/v1.schema.json). The top-level `schema` and `methodology.evidenceSchemaVersion` are both the string `"1"`.

The record has these required objects:

- `subject`: npm ecosystem, package name, and baseline/candidate `{version,purl}`. A PURL is exactly `pkg:{ecosystem}/{package}@{version}` for V1.
- `environment`: OS, architecture, runtime, package manager, sandbox implementation, image reference, and optional image digest.
- `artifacts`: SHA-256 digests (lower-case, `sha256:` prefixed) for baseline/candidate tarballs, lockfiles, dependency graphs, and candidate behavioral evidence. Registry integrity values are optional/null because npm may not provide one.
- `verification`: command results per `baseline` and `candidate`. Status is `PASSED`, `FAILED`, `NOT_CONFIGURED`, `TIMEOUT`, or `ERROR`; `exitCode` is an integer or null.
- `observations`: candidate filesystem and process records, network observation/policy state, and resource metrics. File/process fields use the exact JSON names in the schema (notably `parent_executable` and `exit_code`).
- `externalIntelligence`, `policy`, `capabilities`, `methodology`, and `missingEvidence`.

Capabilities describe what the verifier could establish, not an assertion that an event did or did not occur. `SUPPORTED` means a complete implementation is available; `PARTIAL` means observations can be incomplete; `UNAVAILABLE` means no observation was made; `ENFORCED` means the stated sandbox control was applied. In current V1 output filesystem observation is `SUPPORTED`, process observation is `PARTIAL`, network observation is `UNAVAILABLE`, and network sandbox policy is `ENFORCED`. A verifier must preserve these distinctions: `PARTIAL` is not equivalent to `SUPPORTED`.

`missingEvidence` is explicit negative knowledge. Each item names evidence that is absent and why it is absent; consumers must not infer a clean result from its absence. The current network observer records `network-observation` / `observer-not-implemented` while the sandbox policy remains `DENY`.

V1 is strict. Every object in the schema has `additionalProperties: false`; unknown fields, missing required fields, wrong field types, unsupported enum values, and invalid digest syntax are rejected. Producers must create a future schema version to add fields. Consumers must reject unknown V1 fields rather than silently ignore them.

`VerificationRun` is a separate output wrapper with `compatibilityEvidence`, `compatibilityEvidenceDigest`, and `run`. `run` may hold a run ID, timestamps, raw duration, container IDs, and temporary paths. It is never part of canonical evidence and must not affect `compatibilityEvidenceDigest`.
