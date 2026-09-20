CREATE TABLE packages (
  id BIGSERIAL PRIMARY KEY,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (ecosystem, name)
);
CREATE TABLE package_versions (
  id BIGSERIAL PRIMARY KEY,
  package_id BIGINT NOT NULL REFERENCES packages(id),
  version TEXT NOT NULL,
  purl TEXT NOT NULL,
  UNIQUE (package_id, version)
);
CREATE TABLE version_transitions (
  id BIGSERIAL PRIMARY KEY,
  package_id BIGINT NOT NULL REFERENCES packages(id),
  from_version_id BIGINT NOT NULL REFERENCES package_versions(id),
  to_version_id BIGINT NOT NULL REFERENCES package_versions(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (package_id, from_version_id, to_version_id)
);
CREATE TABLE signers (
  id BIGSERIAL PRIMARY KEY,
  key_id TEXT NOT NULL,
  assurance_tier TEXT NOT NULL CHECK (assurance_tier IN ('LOCAL_DEVELOPMENT_KEY','PERSISTENT_PUBLIC_KEY','SIGSTORE_KEYLESS_CI','VERIFIED_PROJECT_CI','RELEASE_SIGNING_IDENTITY')),
  public_key_hex TEXT NOT NULL,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (key_id, assurance_tier)
);
CREATE TABLE environments (
  id BIGSERIAL PRIMARY KEY,
  os TEXT NOT NULL,
  architecture TEXT NOT NULL,
  runtime TEXT NOT NULL,
  runtime_version TEXT,
  package_manager TEXT NOT NULL,
  package_manager_version TEXT,
  sandbox_backend TEXT NOT NULL,
  UNIQUE NULLS NOT DISTINCT (os, architecture, runtime, runtime_version, package_manager, package_manager_version, sandbox_backend)
);
CREATE TABLE methodology_versions (
  id BIGSERIAL PRIMARY KEY,
  evidence_schema_version TEXT NOT NULL,
  verification_methodology_version TEXT NOT NULL,
  normalization_version TEXT NOT NULL,
  depguard_version TEXT NOT NULL,
  observer_version TEXT NOT NULL,
  sandbox_version TEXT NOT NULL,
  UNIQUE NULLS NOT DISTINCT (evidence_schema_version, verification_methodology_version, normalization_version, depguard_version, observer_version, sandbox_version)
);
CREATE TABLE attestations (
  id BIGSERIAL PRIMARY KEY,
  evidence_id TEXT NOT NULL UNIQUE,
  evidence_digest TEXT NOT NULL,
  canonical_envelope JSONB NOT NULL,
  original_envelope BYTEA NOT NULL,
  original_statement JSONB NOT NULL,
  original_predicate JSONB NOT NULL,
  signatures JSONB NOT NULL,
  signer_id BIGINT NOT NULL REFERENCES signers(id),
  accepted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE evidence_submissions (
  id BIGSERIAL PRIMARY KEY,
  attestation_id BIGINT NOT NULL UNIQUE REFERENCES attestations(id),
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  submission_count BIGINT NOT NULL DEFAULT 1
);
CREATE TABLE verification_runs (
  id BIGSERIAL PRIMARY KEY,
  attestation_id BIGINT NOT NULL UNIQUE REFERENCES attestations(id),
  transition_id BIGINT NOT NULL REFERENCES version_transitions(id),
  environment_id BIGINT NOT NULL REFERENCES environments(id),
  methodology_version_id BIGINT NOT NULL REFERENCES methodology_versions(id),
  outcome TEXT NOT NULL,
  project_fingerprint TEXT,
  process_observation_capability TEXT NOT NULL,
  network_observation_capability TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE behavior_findings (
  id BIGSERIAL PRIMARY KEY,
  verification_run_id BIGINT NOT NULL REFERENCES verification_runs(id),
  kind TEXT NOT NULL,
  value JSONB NOT NULL
);
CREATE TABLE security_findings (
  id BIGSERIAL PRIMARY KEY,
  verification_run_id BIGINT NOT NULL REFERENCES verification_runs(id),
  provider TEXT NOT NULL,
  status TEXT NOT NULL,
  finding TEXT NOT NULL
);
CREATE TABLE policy_findings (
  id BIGSERIAL PRIMARY KEY,
  verification_run_id BIGINT NOT NULL REFERENCES verification_runs(id),
  outcome TEXT NOT NULL,
  finding TEXT NOT NULL
);
CREATE INDEX verification_runs_transition_idx ON verification_runs(transition_id);
CREATE INDEX package_versions_package_idx ON package_versions(package_id);
CREATE INDEX attestations_evidence_id_idx ON attestations(evidence_id);
CREATE INDEX attestations_evidence_digest_idx ON attestations(evidence_digest);
