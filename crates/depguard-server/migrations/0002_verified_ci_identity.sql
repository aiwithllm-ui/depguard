-- Network-only identity metadata. No V1 evidence, predicate, statement, or
-- signed DSSE bytes are changed by this migration.
ALTER TABLE signers DROP CONSTRAINT signers_assurance_tier_check;
ALTER TABLE signers ADD CONSTRAINT signers_assurance_tier_check
  CHECK (assurance_tier IN ('LOCAL_DEVELOPMENT_KEY', 'SIGSTORE_KEYLESS_CI'));

CREATE TABLE verified_ci_identities (
  id BIGSERIAL PRIMARY KEY,
  attestation_id BIGINT NOT NULL UNIQUE REFERENCES attestations(id),
  identity_assurance TEXT NOT NULL CHECK (identity_assurance = 'SIGSTORE_KEYLESS_CI'),
  identity_issuer TEXT NOT NULL,
  repository_identity TEXT NOT NULL,
  workflow_identity TEXT NOT NULL,
  source_revision TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  event_type TEXT NOT NULL,
  certificate_identity TEXT NOT NULL,
  bundle_digest TEXT NOT NULL,
  bundle JSONB NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (attestation_id, bundle_digest)
);
CREATE INDEX verified_ci_identities_repository_idx
  ON verified_ci_identities(repository_identity);
