# DepGuard Global Compatibility Network MVP

Start the local stack with `docker compose up --build`. The server listens at
`http://localhost:8080` and applies the SQLx network migrations before serving
requests.

Publishing is explicit: `depguard publish signed-attestation.json --url
http://localhost:8080`. The command reads and sends only that already-signed V1
DSSE envelope. It does not inspect or upload the project, source, `.env`, logs,
or credentials. To add CI identity, explicitly provide a standard Cosign bundle:

```bash
depguard publish signed-attestation.json --identity-proof sigstore-bundle.json \
  --url http://localhost:8080
```

This uses the separate `/v1/submissions` network wrapper. It carries exact
base64-encoded attestation bytes and an optional Sigstore bundle; it never puts
Sigstore fields into frozen Attestation V1 or its predicate. The wrapper has no
submitter-controlled assurance, repository, workflow, ref, revision, or issuer
fields.

## Identity assurance

`LOCAL_DEVELOPMENT_KEY` is the default for an attestation-only submission. It
means the V1 DSSE signature is valid for its embedded local key; it does not
claim a repository, workflow, or organization. Repository and workflow identity
are `null` for this tier.

`SIGSTORE_KEYLESS_CI` is assigned only by the server after it verifies a Cosign
blob bundle over those exact immutable attestation bytes. Production runs the
following argument-safe invocation (not through a shell):

```text
/usr/local/bin/cosign verify-blob --new-bundle-format \
  --trusted-root /usr/local/share/depguard/sigstore-trusted-root.json \
  --bundle <private-random-tempdir>/bundle.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\\.com/[^/]+/[^/]+/\\.github/workflows/.+@refs/.+$' \
  <private-random-tempdir>/attestation.json
```

The `--trusted-root` file is an intentional vendored Sigstore Public Good
Instance TrustedRoot snapshot: `sigstore/root-signing` commit
`f774128f595393eb623cf7d9a0a38d2c210e33c4`, SHA-256
`6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`.
Cosign validates the Fulcio chain, embedded certificate-transparency evidence,
and Rekor transparency-log inclusion evidence against it; a certificate and
signature alone are insufficient. The normal server does not refresh TUF roots
or download binaries at request time.

The production image copies Cosign **v3.0.2** from
`ghcr.io/sigstore/cosign/cosign:v3.0.2@sha256:b29487e48205d875c324c79583e2806d9d269c0fa299e0861bbec023d8430c8b`.
It is not a `latest` tag. The root snapshot and image digest must be deliberately
reviewed and updated together when Sigstore introduces new trust material.

Only after Cosign exits successfully does the server read the same verified
bundle's Fulcio certificate. It requires the GitHub Actions issuer, repository,
workflow URI, commit SHA, ref, event, and certificate URI; values must parse and
be mutually consistent. Repository, workflow, ref, revision, event, issuer, and
certificate identity are stored only from those verified certificate claims.
Submitter JSON cannot choose an assurance tier. Deployments can pin
`DEPGUARD_SIGSTORE_REPOSITORY` and/or `DEPGUARD_SIGSTORE_WORKFLOW` for a stricter
server policy.

The verifier follows Cosign's bundle/time semantics: historical certificates
remain eligible when the bundle proves signing and transparency inclusion during
the certificate's validity period. DepGuard does not add its own “expired now”
test.

`SIGSTORE_KEYLESS_CI` means **a valid Sigstore/Fulcio identity authenticated a
GitHub Actions execution**. It does not mean a maintainer-approved release.
GitHub event, repository, workflow, ref, and commit are retained so later policy
can distinguish `push`, `pull_request`, `pull_request_target`,
`workflow_dispatch`, `release`, branch, tag, and pull-request refs. In
particular, a PR or `pull_request_target` identity is not upgraded to release
assurance; where GitHub's certificate does not identify a fork origin, DepGuard
does not invent one.

Cryptographic signature validity, identity assurance, and a compatibility
conclusion are different facts. An invalid V1 attestation is always rejected,
even with a valid Sigstore bundle. A valid CI identity does not turn passing or
failing compatibility evidence into a trust score. Contradictory records remain
available and transition results expose population counts by assurance tier.

Identity-input limits are enforced before verification: HTTP request body 1 MiB,
decoded attestation 256 KiB, and Sigstore bundle 512 KiB. Cosign has a 10-second
hard process timeout, private random temporary directory, zero-byte captured
stdout/stderr (discarded), and automatic temporary-file cleanup. It never logs
the bundle or command output. Local `depguard attest-verify` remains entirely
offline and neither reads nor needs GitHub, Sigstore, a network server, or the
Internet.

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
