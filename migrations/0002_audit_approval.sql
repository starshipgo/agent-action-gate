-- Step 6 audit and approval persistence. This migration deliberately stores
-- hashes instead of source_text or normalized arguments. Authorization
-- headers, bearer tokens, and API keys must never be inserted here.

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  request_id TEXT NOT NULL COLLATE BINARY,
  principal_id TEXT NOT NULL COLLATE BINARY,
  key_id TEXT COLLATE BINARY,
  tenant_id TEXT NOT NULL COLLATE BINARY,
  tool_name TEXT NOT NULL COLLATE BINARY,
  event_type TEXT NOT NULL COLLATE BINARY DEFAULT 'EVALUATED',
  decision TEXT COLLATE BINARY,
  risk_level TEXT COLLATE BINARY,
  policy_codes_json TEXT NOT NULL,
  arguments_hash TEXT COLLATE BINARY,
  source_text_hash TEXT COLLATE BINARY,
  approval_id TEXT COLLATE BINARY,
  created_at INTEGER NOT NULL,

  CHECK (length(id) BETWEEN 1 AND 128 AND id = trim(id)),
  CHECK (
    length(request_id) BETWEEN 1 AND 128
    AND request_id = trim(request_id)
  ),
  CHECK (
    length(principal_id) BETWEEN 1 AND 128
    AND principal_id = trim(principal_id)
  ),
  CHECK (
    key_id IS NULL
    OR (length(key_id) BETWEEN 1 AND 128 AND key_id = trim(key_id))
  ),
  CHECK (
    length(tenant_id) BETWEEN 1 AND 128
    AND tenant_id = trim(tenant_id)
    AND tenant_id = lower(tenant_id)
    AND tenant_id NOT GLOB '*[^a-z0-9._-]*'
  ),
  CHECK (
    tool_name IN (
      'crm.read_contact',
      'ticket.create',
      'email.draft',
      'email.send',
      'refund.create',
      'customer.export',
      'secret.read'
    )
    OR (
      length(tool_name) = 79
      AND substr(tool_name, 1, 15) = 'unknown.sha256.'
      AND substr(tool_name, 16) NOT GLOB '*[^0-9a-f]*'
    )
  ),
  CHECK (
    event_type IN (
      'EVALUATED',
      'APPROVED',
      'REJECTED',
      'CONSUMED',
      'EXPIRED',
      'CONSUME_MISMATCH'
    )
  ),
  CHECK (
    decision IS NULL
    OR decision IN ('ALLOW', 'REQUIRE_APPROVAL', 'DENY')
  ),
  CHECK (
    risk_level IS NULL
    OR risk_level IN ('low', 'medium', 'high', 'critical')
  ),
  CHECK (json_valid(policy_codes_json)),
  CHECK (json_type(policy_codes_json) = 'array'),
  CHECK (
    arguments_hash IS NULL
    OR (
      length(arguments_hash) = 64
      AND arguments_hash NOT GLOB '*[^0-9a-f]*'
    )
  ),
  CHECK (
    source_text_hash IS NULL
    OR (
      length(source_text_hash) = 64
      AND source_text_hash NOT GLOB '*[^0-9a-f]*'
    )
  ),
  CHECK (
    approval_id IS NULL
    OR (
      length(approval_id) BETWEEN 1 AND 128
      AND approval_id = trim(approval_id)
    )
  ),
  CHECK (typeof(created_at) = 'integer' AND created_at >= 0),
  CHECK (
    event_type <> 'EVALUATED'
    OR (
      key_id IS NOT NULL
      AND decision IS NOT NULL
      AND risk_level IS NOT NULL
      AND arguments_hash IS NOT NULL
      AND source_text_hash IS NOT NULL
    )
  )
) STRICT;

CREATE INDEX audit_events_tenant_created_idx
  ON audit_events (tenant_id, created_at DESC);
CREATE INDEX audit_events_decision_created_idx
  ON audit_events (decision, created_at DESC);
CREATE INDEX audit_events_tool_created_idx
  ON audit_events (tool_name, created_at DESC);
CREATE INDEX audit_events_approval_idx
  ON audit_events (approval_id, created_at DESC)
  WHERE approval_id IS NOT NULL;

CREATE TRIGGER audit_events_prevent_update
BEFORE UPDATE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_prevent_delete
BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only');
END;

-- SQLite's INSERT OR REPLACE performs an implicit delete before the insert.
-- With recursive triggers disabled (the default), that delete would not reach
-- the append-only trigger above. Reject a colliding insert before REPLACE can
-- replace security evidence.
CREATE TRIGGER audit_events_prevent_replace
BEFORE INSERT ON audit_events
WHEN EXISTS (SELECT 1 FROM audit_events WHERE id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only');
END;

-- policy_codes_json is intentionally the only optional metadata list. Keep it
-- constrained to the small, non-sensitive policy-code vocabulary so it cannot
-- become an alternate storage channel for source text or credentials.
CREATE TRIGGER audit_events_policy_codes_allowlisted
BEFORE INSERT ON audit_events
WHEN EXISTS (
  SELECT 1
  FROM json_each(NEW.policy_codes_json)
  WHERE type <> 'text'
     OR value NOT IN (
       'UNKNOWN_TOOL',
       'MISSING_TARGET_TENANT',
       'CROSS_TENANT_ACCESS',
       'FORBIDDEN_SECRET_ACCESS',
       'SENSITIVE_EXPORT',
       'PROMPT_INJECTION_SIGNAL',
       'DATA_EXFILTRATION_SIGNAL',
       'SUSPICIOUS_INSTRUCTION',
       'SOCIAL_ENGINEERING_SIGNAL',
       'OUTBOUND_SEND',
       'INVALID_REFUND_AMOUNT',
       'REFUND_LIMIT_EXCEEDED',
       'REFUND_REQUIRES_APPROVAL',
       'NO_MATCHING_POLICY',
       'MALFORMED_ARGUMENTS_JSON',
       'SEMANTIC_CLASSIFIER_FAILURE'
     )
)
BEGIN
  SELECT RAISE(ABORT, 'invalid audit policy code');
END;

CREATE TABLE approval_requests (
  id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  principal_id TEXT NOT NULL COLLATE BINARY,
  tenant_id TEXT NOT NULL COLLATE BINARY,
  tool_name TEXT NOT NULL COLLATE BINARY,
  request_hash TEXT NOT NULL COLLATE BINARY,
  risk_level TEXT NOT NULL COLLATE BINARY,
  policy_codes_json TEXT NOT NULL,
  status TEXT NOT NULL COLLATE BINARY DEFAULT 'PENDING',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  decided_at INTEGER,
  decided_by TEXT COLLATE BINARY,
  consumed_at INTEGER,

  CHECK (length(id) BETWEEN 1 AND 128 AND id = trim(id)),
  CHECK (
    length(principal_id) BETWEEN 1 AND 128
    AND principal_id = trim(principal_id)
  ),
  CHECK (
    length(tenant_id) BETWEEN 1 AND 128
    AND tenant_id = trim(tenant_id)
    AND tenant_id = lower(tenant_id)
    AND tenant_id NOT GLOB '*[^a-z0-9._-]*'
  ),
  CHECK (
    length(tool_name) BETWEEN 1 AND 256
    AND tool_name = trim(tool_name)
    AND tool_name = lower(tool_name)
  ),
  CHECK (
    length(request_hash) = 64
    AND request_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
  CHECK (json_valid(policy_codes_json)),
  CHECK (json_type(policy_codes_json) = 'array'),
  CHECK (
    status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CONSUMED')
  ),
  CHECK (typeof(created_at) = 'integer' AND created_at >= 0),
  CHECK (typeof(expires_at) = 'integer' AND expires_at > created_at),
  CHECK (
    decided_at IS NULL
    OR (typeof(decided_at) = 'integer' AND decided_at >= created_at)
  ),
  CHECK (
    decided_by IS NULL
    OR (
      length(decided_by) BETWEEN 1 AND 128
      AND decided_by = trim(decided_by)
    )
  ),
  CHECK (
    consumed_at IS NULL
    OR (typeof(consumed_at) = 'integer' AND consumed_at >= created_at)
  ),
  CHECK (
    (status = 'PENDING'
      AND decided_at IS NULL
      AND decided_by IS NULL
      AND consumed_at IS NULL)
    OR
    (status IN ('APPROVED', 'REJECTED')
      AND decided_at IS NOT NULL
      AND decided_by IS NOT NULL
      AND consumed_at IS NULL)
    OR
    (status = 'EXPIRED'
      AND consumed_at IS NULL
      AND (
        (decided_at IS NULL AND decided_by IS NULL)
        OR (decided_at IS NOT NULL AND decided_by IS NOT NULL)
      ))
    OR
    (status = 'CONSUMED'
      AND decided_at IS NOT NULL
      AND decided_by IS NOT NULL
      AND consumed_at IS NOT NULL
      AND consumed_at >= decided_at
      AND consumed_at < expires_at)
  )
) STRICT;

CREATE INDEX approval_requests_status_expiry_idx
  ON approval_requests (status, expires_at);
CREATE INDEX approval_requests_tenant_status_created_idx
  ON approval_requests (tenant_id, status, created_at DESC);
CREATE INDEX approval_requests_principal_status_idx
  ON approval_requests (principal_id, status);

-- New approvals can enter only at the beginning of the lifecycle. Requiring
-- every later state to pass through the transition trigger also guarantees its
-- corresponding append-only lifecycle audit event is emitted.
CREATE TRIGGER approval_requests_require_pending_insert
BEFORE INSERT ON approval_requests
WHEN
  NEW.status <> 'PENDING'
  OR NEW.decided_at IS NOT NULL
  OR NEW.decided_by IS NOT NULL
  OR NEW.consumed_at IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'approval_requests must be inserted pending');
END;

-- Once created, an approval must stay bound to exactly the same request and
-- authority. Only lifecycle state and its timestamps may change.
CREATE TRIGGER approval_requests_identity_immutable
BEFORE UPDATE OF
  id,
  principal_id,
  tenant_id,
  tool_name,
  request_hash,
  risk_level,
  policy_codes_json,
  created_at,
  expires_at
ON approval_requests
WHEN
  NEW.id <> OLD.id
  OR NEW.principal_id <> OLD.principal_id
  OR NEW.tenant_id <> OLD.tenant_id
  OR NEW.tool_name <> OLD.tool_name
  OR NEW.request_hash <> OLD.request_hash
  OR NEW.risk_level <> OLD.risk_level
  OR NEW.policy_codes_json <> OLD.policy_codes_json
  OR NEW.created_at <> OLD.created_at
  OR NEW.expires_at <> OLD.expires_at
BEGIN
  SELECT RAISE(ABORT, 'approval request binding is immutable');
END;

CREATE TRIGGER approval_requests_enforce_transition
BEFORE UPDATE OF status, decided_at, decided_by, consumed_at
ON approval_requests
WHEN NOT (
  (OLD.status = 'PENDING'
    AND NEW.status IN ('APPROVED', 'REJECTED')
    AND OLD.decided_at IS NULL
    AND OLD.decided_by IS NULL
    AND OLD.consumed_at IS NULL
    AND NEW.decided_at IS NOT NULL
    -- A decision made at the cutoff is too late: the approval has already
    -- expired. Keep this constraint in the database trigger so a direct SQL
    -- update cannot bypass the repository's expiry predicate.
    AND NEW.decided_at < NEW.expires_at
    AND NEW.decided_by IS NOT NULL
    AND NEW.consumed_at IS NULL)
  OR
  (OLD.status = 'PENDING'
    AND NEW.status = 'EXPIRED'
    AND NEW.decided_at IS NULL
    AND NEW.decided_by IS NULL
    AND NEW.consumed_at IS NULL)
  OR
  (OLD.status = 'APPROVED'
    AND NEW.status = 'CONSUMED'
    AND NEW.decided_at IS OLD.decided_at
    AND NEW.decided_by IS OLD.decided_by
    AND OLD.consumed_at IS NULL
    AND NEW.consumed_at IS NOT NULL)
  OR
  (OLD.status = 'APPROVED'
    AND NEW.status = 'EXPIRED'
    AND NEW.decided_at IS OLD.decided_at
    AND NEW.decided_by IS OLD.decided_by
    AND NEW.consumed_at IS NULL)
)
BEGIN
  SELECT RAISE(ABORT, 'invalid approval status transition');
END;

-- Lifecycle audit rows are inserted by the same SQLite statement that changes
-- the approval state. This makes the state transition and its audit event one
-- atomic database operation, including concurrent approve/consume attempts.
CREATE TRIGGER approval_requests_audit_transition
AFTER UPDATE OF status ON approval_requests
WHEN NEW.status <> OLD.status
BEGIN
  INSERT INTO audit_events (
    id,
    request_id,
    principal_id,
    key_id,
    tenant_id,
    tool_name,
    event_type,
    decision,
    risk_level,
    policy_codes_json,
    arguments_hash,
    source_text_hash,
    approval_id,
    created_at
  ) VALUES (
    lower(hex(randomblob(16))),
    NEW.id,
    NEW.principal_id,
    NULL,
    NEW.tenant_id,
    NEW.tool_name,
    NEW.status,
    NULL,
    NULL,
    NEW.policy_codes_json,
    NULL,
    NULL,
    NEW.id,
    CASE NEW.status
      WHEN 'CONSUMED' THEN NEW.consumed_at
      WHEN 'EXPIRED' THEN NEW.expires_at
      ELSE NEW.decided_at
    END
  );
END;

-- Approval history is security evidence. A future retention job should archive
-- records under an explicit migration rather than silently deleting them.
CREATE TRIGGER approval_requests_prevent_delete
BEFORE DELETE ON approval_requests
BEGIN
  SELECT RAISE(ABORT, 'approval_requests cannot be deleted');
END;

-- Match the audit-table REPLACE guard: approval state must not be replaced
-- without a valid transition or its corresponding lifecycle audit event.
CREATE TRIGGER approval_requests_prevent_replace
BEFORE INSERT ON approval_requests
WHEN EXISTS (SELECT 1 FROM approval_requests WHERE id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'approval_requests cannot be replaced');
END;

CREATE TRIGGER approval_requests_policy_codes_allowlisted
BEFORE INSERT ON approval_requests
WHEN EXISTS (
  SELECT 1
  FROM json_each(NEW.policy_codes_json)
  WHERE type <> 'text'
     OR value NOT IN (
       'UNKNOWN_TOOL',
       'MISSING_TARGET_TENANT',
       'CROSS_TENANT_ACCESS',
       'FORBIDDEN_SECRET_ACCESS',
       'SENSITIVE_EXPORT',
       'PROMPT_INJECTION_SIGNAL',
       'DATA_EXFILTRATION_SIGNAL',
       'SUSPICIOUS_INSTRUCTION',
       'SOCIAL_ENGINEERING_SIGNAL',
       'OUTBOUND_SEND',
       'INVALID_REFUND_AMOUNT',
       'REFUND_LIMIT_EXCEEDED',
       'REFUND_REQUIRES_APPROVAL',
       'NO_MATCHING_POLICY',
       'MALFORMED_ARGUMENTS_JSON',
       'SEMANTIC_CLASSIFIER_FAILURE'
     )
)
BEGIN
  SELECT RAISE(ABORT, 'invalid approval policy code');
END;

-- Idempotency replay privacy hardening. Older local/Preview rows may contain
-- normalized_tool/normalized_args from Step 5. Remove those fields once, then
-- reject every future attempt to persist either one. The Worker reconstructs
-- both only from the exact current request after its request_hash has matched.
UPDATE idempotency_records
SET response_json = json_remove(
  response_json,
  '$.normalized_tool',
  '$.normalized_args'
)
WHERE state = 'completed'
  AND response_json IS NOT NULL
  AND json_valid(response_json)
  AND (
    json_type(response_json, '$.normalized_tool') IS NOT NULL
    OR json_type(response_json, '$.normalized_args') IS NOT NULL
  );

CREATE TRIGGER idempotency_records_no_normalized_args_insert
BEFORE INSERT ON idempotency_records
WHEN NEW.response_json IS NOT NULL
  AND json_valid(NEW.response_json)
  AND (
    json_type(NEW.response_json, '$.normalized_tool') IS NOT NULL
    OR json_type(NEW.response_json, '$.normalized_args') IS NOT NULL
  )
BEGIN
  SELECT RAISE(
    ABORT,
    'idempotency response cannot store normalized request data'
  );
END;

CREATE TRIGGER idempotency_records_no_normalized_args_update
BEFORE UPDATE OF response_json ON idempotency_records
WHEN NEW.response_json IS NOT NULL
  AND json_valid(NEW.response_json)
  AND (
    json_type(NEW.response_json, '$.normalized_tool') IS NOT NULL
    OR json_type(NEW.response_json, '$.normalized_args') IS NOT NULL
  )
BEGIN
  SELECT RAISE(
    ABORT,
    'idempotency response cannot store normalized request data'
  );
END;
