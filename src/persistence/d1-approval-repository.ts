import type { RiskLevel } from "../contracts";
import {
  parseApprovalDisplaySummary,
  serializeApprovalDisplaySummary,
} from "../approvals/display-summary";
import { POLICY_VERSION } from "../policy-metadata";
import {
  nullableInteger,
  nullableString,
  parsePolicyCodes,
  parsePolicyVersion,
  queryLimit,
  requiredInteger,
  requiredString,
} from "./d1-codec";
import type {
  ApprovalConsumeInput,
  ApprovalConsumeResult,
  ApprovalDecisionInput,
  ApprovalDecisionResult,
  ApprovalQuery,
  ApprovalRepository,
  ApprovalRequest,
  ApprovalStatus,
  NewApprovalRequest,
} from "./types";

type D1Connection = Pick<D1DatabaseSession, "prepare">;

export const APPROVAL_COLUMNS = `
  id,
  principal_id,
  tenant_id,
  tool_name,
  request_hash,
  risk_level,
  policy_codes_json,
  policy_version,
  approval_display_json,
  status,
  created_at,
  expires_at,
  decided_at,
  decided_by,
  consumed_at
`;

export const INSERT_APPROVAL_SQL = `
INSERT INTO approval_requests (
  id,
  principal_id,
  tenant_id,
  tool_name,
  request_hash,
  risk_level,
  policy_codes_json,
  policy_version,
  approval_display_json,
  status,
  created_at,
  expires_at,
  decided_at,
  decided_by,
  consumed_at
)
VALUES (
  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'PENDING', ?10, ?11,
  NULL, NULL, NULL
)
RETURNING ${APPROVAL_COLUMNS}
`;

export const DECIDE_APPROVAL_SQL = `
UPDATE approval_requests
SET status = ?2,
    decided_at = ?3,
    decided_by = ?4
WHERE id = ?1
  AND status = 'PENDING'
  AND expires_at > ?3
RETURNING ${APPROVAL_COLUMNS}
`;

export const EXPIRE_APPROVAL_SQL = `
UPDATE approval_requests
SET status = 'EXPIRED'
WHERE id = ?1
  AND status IN ('PENDING', 'APPROVED')
  AND expires_at <= ?2
RETURNING ${APPROVAL_COLUMNS}
`;

export const EXPIRE_DUE_APPROVALS_SQL = `
UPDATE approval_requests
SET status = 'EXPIRED'
WHERE status IN ('PENDING', 'APPROVED')
  AND expires_at <= ?1
`;

/** The conditional UPDATE is the one-time approval-consumption authority. */
export const CONSUME_APPROVAL_SQL = `
UPDATE approval_requests
SET status = 'CONSUMED',
    consumed_at = ?5
WHERE id = ?1
  AND principal_id = ?2
  AND tenant_id = ?3
  AND request_hash = ?4
  AND status = 'APPROVED'
  AND expires_at > ?5
  AND policy_version = ?6
RETURNING ${APPROVAL_COLUMNS}
`;

const APPROVAL_STATUSES = new Set<ApprovalStatus>([
  "PENDING",
  "APPROVED",
  "REJECTED",
  "EXPIRED",
  "CONSUMED",
]);
const RISK_LEVELS = new Set<RiskLevel>([
  "low",
  "medium",
  "high",
  "critical",
]);

export function approvalRequestFromD1Row(
  row: Record<string, unknown>,
): ApprovalRequest {
  const status = requiredString(row, "status");
  const riskLevel = requiredString(row, "risk_level");

  if (!APPROVAL_STATUSES.has(status as ApprovalStatus)) {
    throw new TypeError("invalid D1 approval status");
  }
  if (!RISK_LEVELS.has(riskLevel as RiskLevel)) {
    throw new TypeError("invalid D1 risk_level");
  }

  return {
    id: requiredString(row, "id"),
    principal_id: requiredString(row, "principal_id"),
    tenant_id: requiredString(row, "tenant_id"),
    tool_name: requiredString(row, "tool_name"),
    request_hash: requiredString(row, "request_hash"),
    risk_level: riskLevel as RiskLevel,
    policy_codes: parsePolicyCodes(row.policy_codes_json),
    policy_version: parsePolicyVersion(row.policy_version),
    approval_display: parseApprovalDisplaySummary(
      JSON.parse(requiredString(row, "approval_display_json")) as unknown,
    ),
    status: status as ApprovalStatus,
    created_at: requiredInteger(row, "created_at"),
    expires_at: requiredInteger(row, "expires_at"),
    decided_at: nullableInteger(row, "decided_at"),
    decided_by: nullableString(row, "decided_by"),
    consumed_at: nullableInteger(row, "consumed_at"),
  };
}

export class D1ApprovalRepository implements ApprovalRepository {
  constructor(private readonly database: D1Connection) {}

  async create(input: NewApprovalRequest): Promise<ApprovalRequest> {
    if (input.policy_version !== POLICY_VERSION) {
      throw new TypeError("approval policy version is not current");
    }

    const row = await this.database
      .prepare(INSERT_APPROVAL_SQL)
      .bind(
        input.id,
        input.principal_id,
        input.tenant_id,
        input.tool_name,
        input.request_hash,
        input.risk_level,
        JSON.stringify(input.policy_codes),
        input.policy_version,
        serializeApprovalDisplaySummary(input.approval_display),
        input.created_at,
        input.expires_at,
      )
      .first<Record<string, unknown>>();

    if (row === null) {
      throw new Error("approval creation returned no row");
    }

    return approvalRequestFromD1Row(row);
  }

  async findById(id: string, now: number): Promise<ApprovalRequest | null> {
    await this.expire(id, now);
    return this.selectById(id);
  }

  async decide(input: ApprovalDecisionInput): Promise<ApprovalDecisionResult> {
    const row = await this.database
      .prepare(DECIDE_APPROVAL_SQL)
      .bind(input.id, input.decision, input.now, input.decided_by)
      .first<Record<string, unknown>>();

    if (row !== null) {
      // The approval lifecycle trigger runs as part of this UPDATE. If it
      // cannot append the audit event, SQLite aborts this statement and no
      // successful row can be returned.
      return {
        kind: "decided",
        approval: approvalRequestFromD1Row(row),
        audit_persisted: true,
      };
    }

    await this.expire(input.id, input.now);
    const existing = await this.selectById(input.id);
    if (existing === null) {
      return { kind: "not_found" };
    }
    if (existing.status === "EXPIRED") {
      return { kind: "expired", approval: existing };
    }
    return { kind: "conflict", approval: existing };
  }

  async consume(input: ApprovalConsumeInput): Promise<ApprovalConsumeResult> {
    const row = await this.database
      .prepare(CONSUME_APPROVAL_SQL)
      .bind(
        input.id,
        input.principal_id,
        input.tenant_id,
        input.request_hash,
        input.now,
        POLICY_VERSION,
      )
      .first<Record<string, unknown>>();

    if (row !== null) {
      // See decide(): the lifecycle audit trigger is atomic with this
      // conditional one-time-consume transition.
      return {
        kind: "consumed",
        approval: approvalRequestFromD1Row(row),
        audit_persisted: true,
      };
    }

    await this.expire(input.id, input.now);
    const existing = await this.selectById(input.id);
    if (existing === null) {
      return { kind: "not_found" };
    }
    if (
      existing.principal_id !== input.principal_id ||
      existing.tenant_id !== input.tenant_id
    ) {
      return { kind: "ownership_mismatch" };
    }

    switch (existing.status) {
      case "PENDING":
        return { kind: "pending", approval: existing };
      case "REJECTED":
        return { kind: "rejected", approval: existing };
      case "EXPIRED":
        return { kind: "expired", approval: existing };
      case "CONSUMED":
        return { kind: "already_consumed", approval: existing };
      case "APPROVED":
        return { kind: "request_mismatch", approval: existing };
    }
  }

  async list(query: ApprovalQuery): Promise<ApprovalRequest[]> {
    await this.database.prepare(EXPIRE_DUE_APPROVALS_SQL).bind(query.now).run();

    const conditions: string[] = [];
    const bindings: unknown[] = [];
    if (query.status !== undefined) {
      bindings.push(query.status);
      conditions.push(`status = ?${bindings.length}`);
    }
    if (query.tenant_id !== undefined) {
      bindings.push(query.tenant_id);
      conditions.push(`tenant_id = ?${bindings.length}`);
    }

    bindings.push(queryLimit(query.limit));
    const where = conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")}`;
    const result = await this.database
      .prepare(
        `SELECT ${APPROVAL_COLUMNS}
         FROM approval_requests
         ${where}
         ORDER BY created_at DESC, id DESC
         LIMIT ?${bindings.length}`,
      )
      .bind(...bindings)
      .all<Record<string, unknown>>();

    return result.results.map(approvalRequestFromD1Row);
  }

  private async expire(id: string, now: number): Promise<void> {
    await this.database.prepare(EXPIRE_APPROVAL_SQL).bind(id, now).run();
  }

  private async selectById(id: string): Promise<ApprovalRequest | null> {
    const row = await this.database
      .prepare(
        `SELECT ${APPROVAL_COLUMNS}
         FROM approval_requests
         WHERE id = ?1`,
      )
      .bind(id)
      .first<Record<string, unknown>>();

    return row === null ? null : approvalRequestFromD1Row(row);
  }
}
