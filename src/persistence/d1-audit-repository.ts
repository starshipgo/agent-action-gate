import type { Decision, RiskLevel } from "../contracts";
import {
  nullableString,
  parsePolicyCodes,
  parsePolicyVersion,
  queryLimit,
  queryUnixSecond,
  requiredInteger,
  requiredString,
} from "./d1-codec";
import type {
  AuditEvent,
  AuditEventType,
  AuditQuery,
  AuditRepository,
} from "./types";

type D1Connection = Pick<D1DatabaseSession, "prepare">;

export const INSERT_AUDIT_EVENT_SQL = `
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
  policy_version,
  created_at
)
VALUES (
  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
)
`;

const DECISIONS = new Set<Decision>([
  "ALLOW",
  "REQUIRE_APPROVAL",
  "DENY",
]);
const RISK_LEVELS = new Set<RiskLevel>([
  "low",
  "medium",
  "high",
  "critical",
]);
const EVENT_TYPES = new Set<AuditEventType>([
  "EVALUATED",
  "APPROVED",
  "REJECTED",
  "EXPIRED",
  "CONSUMED",
  "CONSUME_MISMATCH",
]);

function parseNullableDecision(value: string | null): Decision | null {
  if (value !== null && !DECISIONS.has(value as Decision)) {
    throw new TypeError("invalid D1 decision");
  }

  return value as Decision | null;
}

function parseNullableRiskLevel(value: string | null): RiskLevel | null {
  if (value !== null && !RISK_LEVELS.has(value as RiskLevel)) {
    throw new TypeError("invalid D1 risk_level");
  }

  return value as RiskLevel | null;
}

function auditEventFromRow(row: Record<string, unknown>): AuditEvent {
  const eventType = requiredString(row, "event_type");

  if (!EVENT_TYPES.has(eventType as AuditEventType)) {
    throw new TypeError("invalid D1 event_type");
  }

  return {
    id: requiredString(row, "id"),
    request_id: requiredString(row, "request_id"),
    principal_id: requiredString(row, "principal_id"),
    key_id: nullableString(row, "key_id"),
    tenant_id: requiredString(row, "tenant_id"),
    tool_name: requiredString(row, "tool_name"),
    event_type: eventType as AuditEventType,
    decision: parseNullableDecision(nullableString(row, "decision")),
    risk_level: parseNullableRiskLevel(nullableString(row, "risk_level")),
    policy_codes: parsePolicyCodes(row.policy_codes_json),
    arguments_hash: nullableString(row, "arguments_hash"),
    source_text_hash: nullableString(row, "source_text_hash"),
    approval_id: nullableString(row, "approval_id"),
    policy_version: parsePolicyVersion(row.policy_version),
    created_at: requiredInteger(row, "created_at"),
  };
}

export class D1AuditRepository implements AuditRepository {
  constructor(private readonly database: D1Connection) {}

  async append(event: AuditEvent): Promise<void> {
    await this.database
      .prepare(INSERT_AUDIT_EVENT_SQL)
      .bind(
        event.id,
        event.request_id,
        event.principal_id,
        event.key_id,
        event.tenant_id,
        event.tool_name,
        event.event_type,
        event.decision,
        event.risk_level,
        JSON.stringify(event.policy_codes),
        event.arguments_hash,
        event.source_text_hash,
        event.approval_id,
        event.policy_version,
        event.created_at,
      )
      .run();
  }

  async list(query: AuditQuery): Promise<AuditEvent[]> {
    const conditions: string[] = [];
    const bindings: unknown[] = [];

    if (query.tenant_id !== undefined) {
      bindings.push(query.tenant_id);
      conditions.push(`tenant_id = ?${bindings.length}`);
    }
    if (query.decision !== undefined) {
      bindings.push(query.decision);
      conditions.push(`decision = ?${bindings.length}`);
    }
    if (query.tool_name !== undefined) {
      bindings.push(query.tool_name);
      conditions.push(`tool_name = ?${bindings.length}`);
    }

    const createdFrom = queryUnixSecond(query.created_from, "created_from");
    const createdTo = queryUnixSecond(query.created_to, "created_to");
    if (
      createdFrom !== undefined &&
      createdTo !== undefined &&
      createdFrom >= createdTo
    ) {
      throw new RangeError("created_from must be less than created_to");
    }
    if (createdFrom !== undefined) {
      bindings.push(createdFrom);
      conditions.push(`created_at >= ?${bindings.length}`);
    }
    if (createdTo !== undefined) {
      bindings.push(createdTo);
      conditions.push(`created_at < ?${bindings.length}`);
    }

    bindings.push(queryLimit(query.limit));
    const where = conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")}`;
    const result = await this.database
      .prepare(
        `SELECT
           id, request_id, principal_id, key_id, tenant_id, tool_name,
           event_type, decision, risk_level, policy_codes_json,
           arguments_hash, source_text_hash, approval_id, policy_version,
           created_at
         FROM audit_events
         ${where}
         ORDER BY created_at DESC, id DESC
         LIMIT ?${bindings.length}`,
      )
      .bind(...bindings)
      .all<Record<string, unknown>>();

    return result.results.map(auditEventFromRow);
  }
}
