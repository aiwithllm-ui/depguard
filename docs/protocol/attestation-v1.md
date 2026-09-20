# Attestation V1

DepGuard Attestation V1 is a DSSE envelope containing a canonical JSON in-toto Statement signed by one Ed25519 local development key. The envelope has `payloadType`, base64 `payload`, and one `{keyid,sig}` entry. `payloadType` is exactly `application/vnd.in-toto+json`; `keyid` is lower-case hex of the Ed25519 public key bytes; `sig` is standard base64 of the 64-byte Ed25519 signature.

The statement has `_type` `https://in-toto.io/Statement/v1`, one subject, predicate type `https://depguard.dev/attestation/compatibility/v1`, and a predicate. The subject name equals `evidence.subject.candidate.purl`; its only digest entry is `sha256`, equal to the candidate artifact digest without its `sha256:` prefix. The predicate contains `evidence`, `compatibilityEvidenceDigest`, and signer assurance `LOCAL_DEVELOPMENT_KEY`.

The statement itself is RFC 8785 canonical JSON. DSSE pre-authentication encoding is exactly the byte concatenation `DSSEv1 ` + decimal UTF-8 byte length of payload type + space + payload type bytes + space + decimal payload byte length + space + payload bytes. Sign and verify those exact bytes using Ed25519. `LOCAL_DEVELOPMENT_KEY` means a locally generated key; it is cryptographic integrity/authenticity for that configured key only, not a public identity or transparency-log assurance.

Offline verification performs: parse strict envelope; check payload type; base64-decode payload/signature; verify the Ed25519 signature and key ID; parse the strict statement; validate statement type, predicate type and assurance; raw-schema validate evidence; verify supported schema/methodology; compute the canonical evidence digest; and validate the subject/PURL/artifact binding.

The public typed failures are `MALFORMED_DSSE`, `INVALID_SIGNATURE`, `UNSUPPORTED_PAYLOAD_TYPE`, `INVALID_STATEMENT`, `UNSUPPORTED_PREDICATE`, `SCHEMA_VALIDATION_FAILED`, `UNSUPPORTED_SCHEMA`, `UNSUPPORTED_METHODOLOGY`, `INVALID_EVIDENCE_DIGEST`, `INVALID_SUBJECT`, and `INVALID_ARTIFACT_RELATIONSHIP`.

`depguard attest-verify attestation.json --public-key local.pub --json` writes `VALID` metadata on success or `{ "status":"INVALID", "reason":"..." }` on failure. Exit code 0 is valid; 41 is malformed DSSE; 42 is invalid signature; 43 is an unsupported payload/protocol/schema/methodology; 44 is statement or evidence consistency failure; 40 is a non-attestation CLI failure.
