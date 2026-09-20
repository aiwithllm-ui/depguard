# Verification Methodology V1

`methodology.evidenceSchemaVersion`, `verificationMethodologyVersion`, and `normalizationVersion` are each `"1"` in V1. `depguardVersion`, `observerVersion`, and `sandboxVersion` identify the producing components but do not loosen the version checks. A V1 verifier accepts only evidence schema and verification methodology version `1`; other values fail with `UNSUPPORTED_SCHEMA` or `UNSUPPORTED_METHODOLOGY`.

The methodology compares isolated baseline and candidate npm dependency twins. It fetches package artifacts, records content-addressed artifact digests, resolves lockfile and dependency-graph state, runs configured commands in hardened non-root Docker containers, then records candidate filesystem and partial process observations. Docker network isolation is an enforced deny policy; network observation is separately unavailable in V1.

The canonical evidence contains normalized compatibility facts only. Run IDs, timestamps, raw durations, container IDs, temporary paths, credentials, registry storage, and raw transient output are outside the canonical object. This permits two operational runs with different execution metadata to retain the same compatibility evidence digest when their canonical evidence is identical.

Consumers should make policy decisions from the explicit command results, observations, capability declarations, policy result, and missing-evidence list. They must not turn unavailable or partial observation into a positive claim. Unknown fields are rejected at every V1 evidence object, so an implementation that needs richer semantics must negotiate a future schema instead of extending V1 silently.
