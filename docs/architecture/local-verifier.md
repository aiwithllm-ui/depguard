# Local verifier architecture

DepGuard keeps the decision path local: package metadata is factual input; a repository copy is executed only in an isolated OCI backend; an evidence document is the output. No source or logs leave the machine.

```text
metadata ─> package delta ─┐
                           ├─> policy/outcome ─> canonical evidence
baseline twin ─> observer ─┤
candidate twin ─> observer ┘
```

The twin copies are made before the dependency version in the candidate manifest is changed. Both receive the same command plan. Results are compared as status, redacted output summaries, duration, and filesystem changes. Portable observation deliberately reports unavailable signals rather than inventing network or syscall claims.

The OCI executor applies network denial, dropped capabilities, `no-new-privileges`, a read-only root filesystem, temporary workspace, PID limit, memory limit, CPU limit, and timeout. Package installation uses `--ignore-scripts`; lifecycle changes are reported as metadata evidence. `--unsafe-host-execution` is clearly marked in the evidence and is intended only for controlled fixtures.

## Extension seams

- `metadata.js`: registry, OSV, deps.dev, and provenance providers
- `sandbox.js`: OCI, gVisor, Firecracker, platform-native backends
- behavior record: portable observer now; syscall/eBPF observer later
- evidence schema: in-toto predicate and DSSE/Sigstore envelope later
- network: optional ingestion only after signed privacy-sanitized evidence exists
