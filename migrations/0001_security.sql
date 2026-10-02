-- Step 5 security persistence. Raw API keys and Authorization headers must
-- never be inserted into any of these tables.

CREATE TABLE api_keys (
  id TEXT PRIMARY KEY NOT NULL,
  principal_id TEXT NOT NULL COLLATE BINARY,
  key_hash TEXT NOT NULL UNIQUE COLLATE BINARY,
  key_prefix TEXT NOT NULL COLLATE BINARY,
  tenant_id TEXT NOT NULL COLLATE BINARY,
  label TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  revoked_at INTEGER,
  daily_ai_limit INTEGER NOT NULL,

  CHECK (length(id) BETWEEN 1 AND 128 AND id = trim(id)),
  CHECK (
    length(principal_id) BETWEEN 1 AND 128
    AND principal_id = trim(principal_id)
  ),
  CHECK (
    length(key_hash) = 64
    AND key_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (
    length(key_prefix) BETWEEN 9 AND 32
    AND substr(key_prefix, 1, 9) = 'aag_test_'
  ),
  CHECK (
    length(tenant_id) BETWEEN 1 AND 128
    AND tenant_id = trim(tenant_id)
    AND tenant_id = lower(tenant_id)
    AND tenant_id NOT GLOB '*[^a-z0-9._-]*'
  ),
  CHECK (length(trim(label)) BETWEEN 1 AND 200),
  CHECK (status IN ('active', 'revoked')),
  CHECK (created_at >= 0),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at),
  CHECK (typeof(daily_ai_limit) = 'integer' AND daily_ai_limit >= 0),
  CHECK (
    (status = 'active' AND revoked_at IS NULL)
    OR (status = 'revoked' AND revoked_at IS NOT NULL)
  )
) STRICT;

CREATE INDEX api_keys_principal_id_idx ON api_keys (principal_id);
CREATE INDEX api_keys_tenant_status_idx ON api_keys (tenant_id, status);
-- Deliberately non-unique: short display prefixes can collide.
CREATE INDEX api_keys_prefix_idx ON api_keys (key_prefix);

-- A principal may rotate across multiple keys, but its tenant authority is
-- immutable. These triggers prevent two keys for one principal from carrying
-- different tenants without requiring a larger principals table in V0.1.
CREATE TRIGGER api_keys_principal_tenant_insert
BEFORE INSERT ON api_keys
WHEN EXISTS (
  SELECT 1
  FROM api_keys
  WHERE principal_id = NEW.principal_id
    AND tenant_id <> NEW.tenant_id
)
BEGIN
  SELECT RAISE(ABORT, 'principal tenant mismatch');
END;

CREATE TRIGGER api_keys_authority_immutable
BEFORE UPDATE OF principal_id, tenant_id ON api_keys
WHEN NEW.principal_id <> OLD.principal_id OR NEW.tenant_id <> OLD.tenant_id
BEGIN
  SELECT RAISE(ABORT, 'API key authority is immutable');
END;

CREATE TABLE daily_ai_usage (
  principal_id TEXT NOT NULL COLLATE BINARY,
  day_utc TEXT NOT NULL COLLATE BINARY,
  ai_calls INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,

  PRIMARY KEY (principal_id, day_utc),
  CHECK (length(principal_id) BETWEEN 1 AND 128),
  CHECK (
    day_utc GLOB
      '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'
  ),
  CHECK (typeof(ai_calls) = 'integer' AND ai_calls >= 0),
  CHECK (updated_at >= 0)
) STRICT;

CREATE TABLE idempotency_records (
  principal_id TEXT NOT NULL COLLATE BINARY,
  idempotency_key_hash TEXT NOT NULL COLLATE BINARY,
  request_hash TEXT NOT NULL COLLATE BINARY,
  response_json TEXT,
  state TEXT NOT NULL,
  claim_token TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  lease_expires_at INTEGER,
  completed_at INTEGER,

  PRIMARY KEY (principal_id, idempotency_key_hash),
  CHECK (length(principal_id) BETWEEN 1 AND 128),
  CHECK (
    length(idempotency_key_hash) = 64
    AND idempotency_key_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (
    length(request_hash) = 64
    AND request_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (
    response_json IS NULL
    OR (length(response_json) <= 65536 AND json_valid(response_json))
  ),
  CHECK (state IN ('pending', 'completed')),
  CHECK (created_at >= 0 AND expires_at > created_at),
  CHECK (
    lease_expires_at IS NULL
    OR (lease_expires_at > created_at AND lease_expires_at <= expires_at)
  ),
  CHECK (
    completed_at IS NULL
    OR (completed_at >= created_at AND completed_at < expires_at)
  ),
  CHECK (
    (
      state = 'pending'
      AND response_json IS NULL
      AND claim_token IS NOT NULL
      AND length(claim_token) BETWEEN 16 AND 128
      AND lease_expires_at IS NOT NULL
      AND completed_at IS NULL
    )
    OR (
      state = 'completed'
      AND response_json IS NOT NULL
      AND claim_token IS NULL
      AND lease_expires_at IS NULL
      AND completed_at IS NOT NULL
    )
  )
) STRICT;

CREATE INDEX idempotency_records_expiry_idx
  ON idempotency_records (expires_at);
