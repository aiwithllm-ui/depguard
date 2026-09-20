# DepGuard Global Compatibility Network MVP

Start the local stack with `docker compose up --build`. The server listens at
`http://localhost:8080` and applies SQLx migration `0001_network_mvp.sql` before
serving requests.

Publishing is explicit: `depguard publish signed-attestation.json --url
http://localhost:8080`. The command reads and sends only that already-signed V1
DSSE envelope. It does not inspect or upload the project, source, `.env`, logs,
or credentials.

Evidence identity is `sha256:` plus SHA-256 of the RFC 8785 canonical JSON DSSE
envelope. The server preserves the exact submitted envelope bytes as
`original_envelope`; decoded DSSE statement, predicate, and signature list are
retained as JSONB solely for query/index use. A repeated identical DSSE envelope
updates `firstSeenAt`/`lastSeenAt`/`submissionCount` instead of creating a
second verification run. A re-signed envelope has a distinct DSSE identity and
is stored as distinct signed evidence.

The network consumes frozen Compatibility Evidence v1, Canonicalization v1,
Attestation v1, and Verification Methodology v1 as a client. Local `verify`,
`attest`, and `attest-verify` remain network-free. V1 does not contain a project
fingerprint, runtime version, or package-manager version; API responses state
these dimensions as unavailable rather than fabricate values.

Run Postgres integration tests against the Compose database with:

```bash
DATABASE_URL=postgresql://depguard:depguard@localhost:5432/depguard \
  cargo test -p depguard-server --test postgres_network -- --ignored
```
