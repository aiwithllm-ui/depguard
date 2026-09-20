# DepGuard threat model

DepGuard treats the package and the repository under verification as hostile. The default path never runs either on the host. This is a security boundary, not a convenience feature.

| Threat | MVP mitigation | Remaining work |
| --- | --- | --- |
| Sandbox escape | OCI default; non-root image expectation, dropped caps, read-only root, no-new-privileges, no Docker socket | gVisor/Firecracker backend and hardened image signing |
| Credential theft | source copy excludes `.env`, `.npmrc`, `node_modules`, and `.git`; container has no host home | secret scanner and explicit mount allowlist |
| Resource exhaustion | PID, memory, CPU limits and timeout | disk quota and cgroup accounting report |
| Network exfiltration | OCI execution uses `--network=none` | recording proxy and destination diff |
| Malicious archive | installation scripts are disabled | content-addressed fetcher, tar traversal and decompression limits |
| Terminal/log injection | report treats logs as data; common secret-shaped values are redacted and output capped | ANSI stripping and structured event protocol |
| Evidence poisoning / Sybil | no global ingestion in MVP | signed identity tiers, replay keys, contributor thresholds |
| Replay attacks | local evidence has a timestamp and content ID | server-side nonce/digest replay store |
| Compromised service | no service is required for local evidence | DSSE/Sigstore verification independent of depguard.dev |

`--unsafe-host-execution` removes the isolation guarantee. It is an explicit developer-only escape hatch and evidence records it. Never use it for untrusted repositories or package candidates.
