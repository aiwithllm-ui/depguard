# Canonicalization V1

The compatibility evidence digest is `sha256:` followed by the lower-case hexadecimal SHA-256 digest of RFC 8785 (JSON Canonicalization Scheme) bytes for the Compatibility Evidence V1 JSON value. No newline, whitespace, transport envelope, run metadata, or pretty-printing bytes are included.

Implementations must first validate V1 JSON, then canonicalize the JSON value using RFC 8785, then hash the resulting UTF-8 bytes. RFC 8785 sorts object member names recursively, emits no insignificant whitespace, uses ECMAScript-compatible number serialization, and leaves array order intact. It is not sufficient to use an ordinary JSON serializer unless it implements RFC 8785 exactly.

The committed interoperability fixture is in [`fixtures/protocol/evidence-v1`](../../fixtures/protocol/evidence-v1): `evidence.json` is a realistic source value, `canonical.json` is its RFC 8785 byte sequence, and `canonical.sha256` is its digest. The terminal line ending of the text fixture is not canonical protocol data. Conformance requires canonicalizing `evidence.json` to the bytes represented by `canonical.json` without that line ending and producing the recorded digest. Reordering JSON object keys must produce identical canonical bytes and digest.

All artifact and behavior digests carried as fields are themselves `sha256:<64 lower-case hex>` strings. The outer compatibility evidence digest uses the same representation.
