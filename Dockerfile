FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p depguard-server

# Cosign v3.0.2, immutable OCI index digest verified 2026-09-20.
FROM ghcr.io/sigstore/cosign/cosign:v3.0.2@sha256:b29487e48205d875c324c79583e2806d9d269c0fa299e0861bbec023d8430c8b AS cosign

FROM debian:bookworm-slim
COPY --from=build /src/target/release/depguard-server /usr/local/bin/depguard-server
# The network verifier uses this independently maintained Sigstore client to
# validate Fulcio/trust-root and transparency material before reading cert claims.
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
COPY crates/depguard-server/fixtures/sigstore-trusted-root.json /usr/local/share/depguard/sigstore-trusted-root.json
EXPOSE 8080
CMD ["depguard-server"]
