import type {
  AiQuotaRepository,
  AiQuotaResult,
  ApiKeyRecord,
  IdempotencyClaimInput,
  IdempotencyClaimResult,
  IdempotencyCompletionInput,
  IdempotencyRepository,
  PrincipalRepository,
  CoreSecurityRepositories,
  StoredEvaluationResult,
  TrustedPrincipal,
} from "./types";
import type { EvaluationResult, PolicyCode } from "../contracts";
import { POLICY_VERSION } from "../policy-metadata";

type D1Connection = Pick<D1DatabaseSession, "prepare" | "batch">;

const POLICY_CODES = new Set<PolicyCode>([
  "UNKNOWN_TOOL",
  "MISSING_TARGET_TENANT",
  "CROSS_TENANT_ACCESS",
  "FORBIDDEN_SECRET_ACCESS",
  "SENSITIVE_EXPORT",
  "PROMPT_INJECTION_SIGNAL",
  "DATA_EXFILTRATION_SIGNAL",
  "SUSPICIOUS_INSTRUCTION",
  "SOCIAL_ENGINEERING_SIGNAL",
  "OUTBOUND_SEND",
  "INVALID_REFUND_AMOUNT",
  "REFUND_LIMIT_EXCEEDED",
  "REFUND_REQUIRES_APPROVAL",
  "NO_MATCHING_POLICY",
  "MALFORMED_ARGUMENTS_JSON",
  "SEMANTIC_CLASSIFIER_FAILURE",
]);

export const ATOMIC_QUOTA_SQL = `
INSERT INTO daily_ai_usage (principal_id, day_utc, ai_calls, updated_at)
SELECT ?1, ?2, 1, ?3
FROM api_keys
WHERE id = ?4
  AND principal_id = ?1
  AND status = 'active'
  AND revoked_at IS NULL
  AND daily_ai_limit > 0
ON CONFLICT(principal_id, day_utc) DO UPDATE SET
  ai_calls = daily_ai_usage.ai_calls + 1,
  updated_at = excluded.updated_at
WHERE daily_ai_usage.ai_calls < (
  SELECT daily_ai_limit
  FROM api_keys
  WHERE id = ?4
    AND principal_id = ?1
    AND status = 'active'
    AND revoked_at IS NULL
)
RETURNING ai_calls, (
  SELECT daily_ai_limit FROM api_keys WHERE id = ?4 AND principal_id = ?1
) AS daily_ai_limit
`;

export const CLAIM_IDEMPOTENCY_SQL = `
INSERT INTO idempotency_records (
  principal_id,
  idempotency_key_hash,
  request_hash,
  policy_version,
  response_json,
  state,
  claim_token,
  created_at,
  expires_at,
  lease_expires_at,
  completed_at
)
VALUES (?1, ?2, ?3, ?4, NULL, 'pending', ?5, ?6, ?7, ?8, NULL)
ON CONFLICT(principal_id, idempotency_key_hash) DO UPDATE SET
  request_hash = excluded.request_hash,
  policy_version = excluded.policy_version,
  response_json = NULL,
  state = 'pending',
  claim_token = excluded.claim_token,
  created_at = CASE
    WHEN idempotency_records.expires_at <= ?6 THEN excluded.created_at
    ELSE idempotency_records.created_at
  END,
  expires_at = CASE
    WHEN idempotency_records.expires_at <= ?6 THEN excluded.expires_at
    ELSE idempotency_records.expires_at
  END,
  lease_expires_at = excluded.lease_expires_at,
  completed_at = NULL
WHERE idempotency_records.expires_at <= ?6
   OR (
     idempotency_records.request_hash = excluded.request_hash
     AND idempotency_records.policy_version = excluded.policy_version
     AND idempotency_records.state = 'pending'
     AND idempotency_records.lease_expires_at <= ?6
     AND idempotency_records.expires_at >= excluded.lease_expires_at
   )
RETURNING request_hash, policy_version, response_json, state, claim_token, expires_at,
  lease_expires_at
`;

export const COMPLETE_IDEMPOTENCY_SQL = `
UPDATE idempotency_records
SET response_json = ?5,
    state = 'completed',
    claim_token = NULL,
    lease_expires_at = NULL,
    completed_at = ?6
WHERE principal_id = ?1
  AND idempotency_key_hash = ?2
  AND request_hash = ?3
  AND state = 'pending'
  AND claim_token = ?4
  AND expires_at > ?6
  AND policy_version = ?7
RETURNING response_json
`;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseStoredEvaluation(value: unknown): StoredEvaluationResult {
  if (!isRecord(value)) {
    throw new TypeError("stored idempotency response is not an object");
  }

  const baseFields = [
    "decision",
    "risk_level",
    "policy_codes",
    "requires_approval",
  ] as const;
  const isApproval = value.decision === "REQUIRE_APPROVAL";
  const expected = new Set<string>(
    isApproval
      ? [...baseFields, "approval_id", "expires_at"]
      : baseFields,
  );

  if (
    Object.keys(value).length !== expected.size ||
    Object.keys(value).some((key) => !expected.has(key)) ||
    (value.decision !== "ALLOW" &&
      value.decision !== "REQUIRE_APPROVAL" &&
      value.decision !== "DENY") ||
    (value.risk_level !== "low" &&
      value.risk_level !== "medium" &&
      value.risk_level !== "high" &&
      value.risk_level !== "critical") ||
    !Array.isArray(value.policy_codes) ||
    value.policy_codes.some(
      (code) => typeof code !== "string" || !POLICY_CODES.has(code as PolicyCode),
    ) ||
    typeof value.requires_approval !== "boolean" ||
    value.requires_approval !== isApproval ||
    (isApproval &&
      (typeof value.approval_id !== "string" ||
        value.approval_id.length === 0 ||
        typeof value.expires_at !== "string" ||
        !Number.isFinite(Date.parse(value.expires_at))))
  ) {
    throw new TypeError("stored idempotency response is invalid");
  }

  const result: StoredEvaluationResult = {
    decision: value.decision,
    risk_level: value.risk_level,
    policy_codes: value.policy_codes as PolicyCode[],
    requires_approval: value.requires_approval,
  };

  if (isApproval) {
    result.approval_id = value.approval_id as string;
    result.expires_at = value.expires_at as string;
  }

  return result;
}

/**
 * Builds an allowlisted replay envelope. In particular this never serializes
 * normalized_tool or normalized_args, even if an untrusted caller adds extra
 * runtime properties.
 */
export function serializeStoredEvaluationResult(
  response: EvaluationResult,
): string {
  const isApproval = response.decision === "REQUIRE_APPROVAL";
  const approvalId = response.approval_id;
  const expiresAt = response.expires_at;
  if (
    response.requires_approval !== isApproval ||
    (isApproval &&
      (typeof approvalId !== "string" ||
        approvalId.length === 0 ||
        typeof expiresAt !== "string" ||
        !Number.isFinite(Date.parse(expiresAt)))) ||
    (!isApproval &&
      (approvalId !== undefined || expiresAt !== undefined))
  ) {
    throw new TypeError("idempotency response approval metadata is invalid");
  }

  const stored: StoredEvaluationResult = {
    decision: response.decision,
    risk_level: response.risk_level,
    policy_codes: [...response.policy_codes],
    requires_approval: response.requires_approval,
  };

  if (
    isApproval &&
    typeof approvalId === "string" &&
    typeof expiresAt === "string"
  ) {
    stored.approval_id = approvalId;
    stored.expires_at = expiresAt;
  }

  return JSON.stringify(stored);
}

function requiredString(row: Record<string, unknown>, field: string): string {
  const value = row[field];

  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`invalid D1 ${field}`);
  }

  return value;
}

class D1PrincipalRepository implements PrincipalRepository {
  constructor(private readonly database: D1Connection) {}

  async findByKeyHash(keyHash: string): Promise<ApiKeyRecord | null> {
    const row = await this.database
      .prepare(
        `SELECT id AS key_id, principal_id, tenant_id, status, daily_ai_limit
         FROM api_keys
         WHERE key_hash = ?1
         LIMIT 1`,
      )
      .bind(keyHash)
      .first<Record<string, unknown>>();

    if (row === null) {
      return null;
    }

    const status = row.status;
    const dailyLimit = row.daily_ai_limit;

    if (
      (status !== "active" && status !== "revoked") ||
      typeof dailyLimit !== "number" ||
      !Number.isSafeInteger(dailyLimit) ||
      dailyLimit < 0
    ) {
      throw new TypeError("invalid D1 API key record");
    }

    return {
      key_id: requiredString(row, "key_id"),
      principal_id: requiredString(row, "principal_id"),
      tenant_id: requiredString(row, "tenant_id"),
      status,
      daily_ai_limit: dailyLimit,
    };
  }
}

class D1AiQuotaRepository implements AiQuotaRepository {
  constructor(private readonly database: D1Connection) {}

  async tryConsume(
    principal: TrustedPrincipal,
    dayUtc: string,
    nowUnixSeconds: number,
  ): Promise<AiQuotaResult> {
    const row = await this.database
      .prepare(ATOMIC_QUOTA_SQL)
      .bind(
        principal.principal_id,
        dayUtc,
        nowUnixSeconds,
        principal.key_id,
      )
      .first<Record<string, unknown>>();

    if (row === null) {
      return { allowed: false, limit: principal.daily_ai_limit };
    }

    const used = row.ai_calls;
    const limit = row.daily_ai_limit;

    if (
      typeof used !== "number" ||
      !Number.isSafeInteger(used) ||
      used < 1 ||
      typeof limit !== "number" ||
      !Number.isSafeInteger(limit) ||
      limit < used
    ) {
      throw new TypeError("invalid D1 quota result");
    }

    return { allowed: true, used, limit };
  }
}

class D1IdempotencyRepository implements IdempotencyRepository {
  constructor(private readonly database: D1Connection) {}

  async claim(input: IdempotencyClaimInput): Promise<IdempotencyClaimResult> {
    const policyVersion = input.policy_version ?? POLICY_VERSION;
    if (policyVersion !== POLICY_VERSION) {
      throw new TypeError("incompatible idempotency policy version");
    }
    const claimed = await this.database
      .prepare(CLAIM_IDEMPOTENCY_SQL)
      .bind(
        input.principal_id,
        input.idempotency_key_hash,
        input.request_hash,
        policyVersion,
        input.owner_token,
        input.now,
        input.expires_at,
        input.lease_expires_at,
      )
      .first<Record<string, unknown>>();

    if (claimed !== null) {
      if (
        claimed.state !== "pending" ||
        claimed.claim_token !== input.owner_token ||
        claimed.request_hash !== input.request_hash ||
        claimed.policy_version !== policyVersion
      ) {
        throw new TypeError("invalid D1 idempotency claim result");
      }

      return { kind: "acquired", owner_token: input.owner_token };
    }

    const existing = await this.database
      .prepare(
        `SELECT request_hash, policy_version, response_json, state
         FROM idempotency_records
         WHERE principal_id = ?1 AND idempotency_key_hash = ?2`,
      )
      .bind(input.principal_id, input.idempotency_key_hash)
      .first<Record<string, unknown>>();

    if (existing === null) {
      throw new Error("idempotency claim disappeared");
    }

    if (
      existing.request_hash !== input.request_hash ||
      existing.policy_version !== policyVersion
    ) {
      return { kind: "conflict" };
    }

    if (
      existing.state === "completed" &&
      typeof existing.response_json === "string"
    ) {
      return {
        kind: "replay",
        response: parseStoredEvaluation(
          JSON.parse(existing.response_json) as unknown,
        ),
      };
    }

    if (existing.state === "pending" && existing.response_json === null) {
      return { kind: "in_progress" };
    }

    throw new TypeError("invalid D1 idempotency record");
  }

  async complete(input: IdempotencyCompletionInput): Promise<boolean> {
    const policyVersion = input.policy_version ?? POLICY_VERSION;
    if (policyVersion !== POLICY_VERSION) {
      throw new TypeError("incompatible idempotency policy version");
    }
    const row = await this.database
      .prepare(COMPLETE_IDEMPOTENCY_SQL)
      .bind(
        input.principal_id,
        input.idempotency_key_hash,
        input.request_hash,
        input.owner_token,
        serializeStoredEvaluationResult(input.response),
        input.now,
        policyVersion,
      )
      .first<Record<string, unknown>>();

    return row !== null;
  }

  async abandon(input: {
    principal_id: string;
    idempotency_key_hash: string;
    request_hash: string;
    owner_token: string;
  }): Promise<void> {
    await this.database
      .prepare(
        `DELETE FROM idempotency_records
         WHERE principal_id = ?1
           AND idempotency_key_hash = ?2
           AND request_hash = ?3
           AND state = 'pending'
           AND claim_token = ?4`,
      )
      .bind(
        input.principal_id,
        input.idempotency_key_hash,
        input.request_hash,
        input.owner_token,
      )
      .run();
  }
}

export function createD1SecurityRepositories(
  database: D1Database,
): CoreSecurityRepositories {
  const session = database.withSession("first-primary");

  return {
    principals: new D1PrincipalRepository(session),
    quota: new D1AiQuotaRepository(session),
    idempotency: new D1IdempotencyRepository(session),
  };
}
