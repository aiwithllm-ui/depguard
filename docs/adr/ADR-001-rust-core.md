# ADR-001: Rust for the long-term core agent

**Status:** accepted architecture; bootstrap implementation uses dependency-free Node.js because the supplied execution environment has Node.js but no Rust toolchain.

The production agent is intended to move to Rust for a single static binary, explicit resource control, and a strong systems integration story. The executable bootstrap preserves the public CLI, schema, evidence model, and backend boundary so this migration does not change the user contract.
