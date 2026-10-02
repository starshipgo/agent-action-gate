-- Step 7 policy-version binding and human-readable approval summaries.
--
-- approval_display_json is untrusted, display-only metadata. It is constrained
-- to tool-specific allowlisted shapes and MUST NOT be used for authorization.
-- approval_requests.request_hash remains the exact-request authority.

ALTER TABLE audit_events
ADD COLUMN policy_version TEXT NOT NULL COLLATE BINARY
  DEFAULT 'aag-policy-legacy'
  CHECK (
    length(policy_version) BETWEEN 1 AND 64
    AND substr(policy_version, 1, 1) GLOB '[A-Za-z0-9]'
    AND policy_version NOT GLOB '*[^A-Za-z0-9._-]*'
  );

ALTER TABLE approval_requests
ADD COLUMN policy_version TEXT NOT NULL COLLATE BINARY
  DEFAULT 'aag-policy-legacy'
  CHECK (
    length(policy_version) BETWEEN 1 AND 64
    AND substr(policy_version, 1, 1) GLOB '[A-Za-z0-9]'
    AND policy_version NOT GLOB '*[^A-Za-z0-9._-]*'
  );

ALTER TABLE approval_requests
ADD COLUMN approval_display_json TEXT NOT NULL
  DEFAULT '{"kind":"generic"}'
  CHECK (
    length(approval_display_json) BETWEEN 1 AND 2048
    AND json_valid(approval_display_json)
    AND json_type(approval_display_json) = 'object'
  );

ALTER TABLE idempotency_records
ADD COLUMN policy_version TEXT NOT NULL COLLATE BINARY
  DEFAULT 'aag-policy-legacy'
  CHECK (
    length(policy_version) BETWEEN 1 AND 64
    AND substr(policy_version, 1, 1) GLOB '[A-Za-z0-9]'
    AND policy_version NOT GLOB '*[^A-Za-z0-9._-]*'
  );

-- Policy and presentation metadata are part of an approval's immutable
-- identity. Only the existing lifecycle columns may change after insertion.
CREATE TRIGGER approval_requests_step7_identity_immutable
BEFORE UPDATE OF policy_version, approval_display_json
ON approval_requests
WHEN
  NEW.policy_version <> OLD.policy_version
  OR NEW.approval_display_json <> OLD.approval_display_json
BEGIN
  SELECT RAISE(ABORT, 'approval request binding is immutable');
END;

-- Reject arbitrary display data. Generic summaries have no argument fields;
-- email and refund summaries expose only the explicitly listed scalar fields.
CREATE TRIGGER approval_requests_display_allowlisted_insert
BEFORE INSERT ON approval_requests
WHEN NOT coalesce((
  (
    NEW.tool_name NOT IN ('email.send', 'refund.create')
    AND
    json_extract(NEW.approval_display_json, '$.kind') = 'generic'
    AND (SELECT count(*) FROM json_each(NEW.approval_display_json)) = 1
  )
  OR
  (
    NEW.tool_name = 'email.send'
    AND json_extract(NEW.approval_display_json, '$.kind') = 'email_send'
    AND json_type(NEW.approval_display_json, '$.recipient') = 'text'
    AND length(json_extract(NEW.approval_display_json, '$.recipient')) <= 320
    AND json_extract(NEW.approval_display_json, '$.recipient') =
      trim(json_extract(NEW.approval_display_json, '$.recipient'))
    AND NOT EXISTS (
      WITH RECURSIVE control_character(ordinal) AS (
        SELECT 0
        UNION ALL
        SELECT ordinal + 1 FROM control_character WHERE ordinal < 64
      )
      SELECT 1 FROM control_character
      WHERE instr(
        json_extract(NEW.approval_display_json, '$.recipient'),
        char(CASE WHEN ordinal <= 31 THEN ordinal ELSE ordinal + 95 END)
      ) > 0
    )
    AND NOT EXISTS (
      WITH RECURSIVE character_at(position, codepoint) AS (
        SELECT 1, unicode(substr(
          json_extract(NEW.approval_display_json, '$.recipient'), 1, 1
        ))
        UNION ALL
        SELECT position + 1, unicode(substr(
          json_extract(NEW.approval_display_json, '$.recipient'),
          position + 1,
          1
        ))
        FROM character_at
        WHERE position < length(
          json_extract(NEW.approval_display_json, '$.recipient')
        )
      )
      SELECT 1 FROM character_at
      WHERE
        codepoint IN (
          173, 1564, 1757, 1807, 2274, 6158, 65279, 69821, 69837, 917505
        )
        OR codepoint BETWEEN 1536 AND 1541
        OR codepoint BETWEEN 2192 AND 2193
        OR codepoint BETWEEN 8203 AND 8207
        OR codepoint BETWEEN 8234 AND 8238
        OR codepoint BETWEEN 8288 AND 8292
        OR codepoint BETWEEN 8294 AND 8303
        OR codepoint BETWEEN 65529 AND 65531
        OR codepoint BETWEEN 78896 AND 78943
        OR codepoint BETWEEN 113824 AND 113827
        OR codepoint BETWEEN 119155 AND 119162
        OR codepoint BETWEEN 917536 AND 917631
    )
    AND json_type(NEW.approval_display_json, '$.has_attachments')
      IN ('true', 'false')
    AND (
      json_type(NEW.approval_display_json, '$.subject') IS NULL
      OR (
        json_type(NEW.approval_display_json, '$.subject') = 'text'
        AND length(json_extract(NEW.approval_display_json, '$.subject'))
          BETWEEN 1 AND 500
        AND json_extract(NEW.approval_display_json, '$.subject') =
          trim(json_extract(NEW.approval_display_json, '$.subject'))
        AND NOT EXISTS (
          WITH RECURSIVE control_character(ordinal) AS (
            SELECT 0
            UNION ALL
            SELECT ordinal + 1 FROM control_character WHERE ordinal < 64
          )
          SELECT 1 FROM control_character
          WHERE instr(
            json_extract(NEW.approval_display_json, '$.subject'),
            char(CASE WHEN ordinal <= 31 THEN ordinal ELSE ordinal + 95 END)
          ) > 0
        )
        AND NOT EXISTS (
          WITH RECURSIVE character_at(position, codepoint) AS (
            SELECT 1, unicode(substr(
              json_extract(NEW.approval_display_json, '$.subject'), 1, 1
            ))
            UNION ALL
            SELECT position + 1, unicode(substr(
              json_extract(NEW.approval_display_json, '$.subject'),
              position + 1,
              1
            ))
            FROM character_at
            WHERE position < length(
              json_extract(NEW.approval_display_json, '$.subject')
            )
          )
          SELECT 1 FROM character_at
          WHERE
            codepoint IN (
              173, 1564, 1757, 1807, 2274, 6158, 65279, 69821, 69837, 917505
            )
            OR codepoint BETWEEN 1536 AND 1541
            OR codepoint BETWEEN 2192 AND 2193
            OR codepoint BETWEEN 8203 AND 8207
            OR codepoint BETWEEN 8234 AND 8238
            OR codepoint BETWEEN 8288 AND 8292
            OR codepoint BETWEEN 8294 AND 8303
            OR codepoint BETWEEN 65529 AND 65531
            OR codepoint BETWEEN 78896 AND 78943
            OR codepoint BETWEEN 113824 AND 113827
            OR codepoint BETWEEN 119155 AND 119162
            OR codepoint BETWEEN 917536 AND 917631
        )
      )
    )
    AND NOT EXISTS (
      SELECT 1 FROM json_each(NEW.approval_display_json)
      WHERE key NOT IN ('kind', 'recipient', 'subject', 'has_attachments')
    )
    AND (SELECT count(*) FROM json_each(NEW.approval_display_json))
      BETWEEN 3 AND 4
  )
  OR
  (
    NEW.tool_name = 'refund.create'
    AND json_extract(NEW.approval_display_json, '$.kind') = 'refund_create'
    AND json_type(NEW.approval_display_json, '$.amount_minor') = 'integer'
    AND json_extract(NEW.approval_display_json, '$.amount_minor')
      BETWEEN 1 AND 50000
    AND (
      json_type(NEW.approval_display_json, '$.currency') IS NULL
      OR (
        json_type(NEW.approval_display_json, '$.currency') = 'text'
        AND length(json_extract(NEW.approval_display_json, '$.currency')) = 3
        AND json_extract(NEW.approval_display_json, '$.currency')
          NOT GLOB '*[^A-Z]*'
      )
    )
    AND (
      json_type(NEW.approval_display_json, '$.order_id') IS NULL
      OR (
        json_type(NEW.approval_display_json, '$.order_id') = 'text'
        AND length(json_extract(NEW.approval_display_json, '$.order_id'))
          BETWEEN 1 AND 128
        AND json_extract(NEW.approval_display_json, '$.order_id') =
          trim(json_extract(NEW.approval_display_json, '$.order_id'))
        AND NOT EXISTS (
          WITH RECURSIVE control_character(ordinal) AS (
            SELECT 0
            UNION ALL
            SELECT ordinal + 1 FROM control_character WHERE ordinal < 64
          )
          SELECT 1 FROM control_character
          WHERE instr(
            json_extract(NEW.approval_display_json, '$.order_id'),
            char(CASE WHEN ordinal <= 31 THEN ordinal ELSE ordinal + 95 END)
          ) > 0
        )
        AND NOT EXISTS (
          WITH RECURSIVE character_at(position, codepoint) AS (
            SELECT 1, unicode(substr(
              json_extract(NEW.approval_display_json, '$.order_id'), 1, 1
            ))
            UNION ALL
            SELECT position + 1, unicode(substr(
              json_extract(NEW.approval_display_json, '$.order_id'),
              position + 1,
              1
            ))
            FROM character_at
            WHERE position < length(
              json_extract(NEW.approval_display_json, '$.order_id')
            )
          )
          SELECT 1 FROM character_at
          WHERE
            codepoint IN (
              173, 1564, 1757, 1807, 2274, 6158, 65279, 69821, 69837, 917505
            )
            OR codepoint BETWEEN 1536 AND 1541
            OR codepoint BETWEEN 2192 AND 2193
            OR codepoint BETWEEN 8203 AND 8207
            OR codepoint BETWEEN 8234 AND 8238
            OR codepoint BETWEEN 8288 AND 8292
            OR codepoint BETWEEN 8294 AND 8303
            OR codepoint BETWEEN 65529 AND 65531
            OR codepoint BETWEEN 78896 AND 78943
            OR codepoint BETWEEN 113824 AND 113827
            OR codepoint BETWEEN 119155 AND 119162
            OR codepoint BETWEEN 917536 AND 917631
        )
      )
    )
    AND NOT EXISTS (
      SELECT 1 FROM json_each(NEW.approval_display_json)
      WHERE key NOT IN ('kind', 'amount_minor', 'currency', 'order_id')
    )
    AND (SELECT count(*) FROM json_each(NEW.approval_display_json))
      BETWEEN 2 AND 4
  )
), 0)
BEGIN
  SELECT RAISE(ABORT, 'invalid approval display summary');
END;

-- Recreate the lifecycle trigger so every derived audit row carries exactly
-- the immutable version of the approval that caused it.
DROP TRIGGER approval_requests_audit_transition;

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
    created_at,
    policy_version
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
      -- Current-version lazy expiry runs at/after expires_at. During this
      -- migration, a still-live legacy approval is deliberately retired early,
      -- so record that transition now rather than creating future audit data.
      WHEN 'EXPIRED' THEN min(NEW.expires_at, unixepoch())
      ELSE NEW.decided_at
    END,
    NEW.policy_version
  );
END;

-- Pre-Step-7 approvals lack both an explicit version and a trustworthy human
-- summary. They remain as evidence but lose all actionable authority. This is
-- intentionally after the replacement trigger so forced legacy expiry carries
-- its policy version and a truthful transition timestamp.
UPDATE approval_requests
SET status = 'EXPIRED'
WHERE status IN ('PENDING', 'APPROVED');
