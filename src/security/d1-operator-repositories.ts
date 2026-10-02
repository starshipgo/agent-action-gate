import { queryLimit, requiredInteger, requiredString } from "../persistence/d1-codec";
import type {
  ApiKeyCreateResult,
  ApiKeyListQuery,
  ApiKeyManagementRepository,
  ApiKeyMetadata,
  ApiKeyRevokeResult,
  NewApiKeyRecord,
  OperatorOverviewMetrics,
  OperatorOverviewRepository,
} from "./types";

type D1Connection = Pick<D1DatabaseSession, "prepare">;

function nullableInteger(
  row: Record<string, unknown>,
  field: string,
): number | null {
  const value = row[field];
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`invalid D1 ${field}`);
  }
  return value;
}

function apiKeyFromRow(row: Record<string, unknown>): ApiKeyMetadata {
  const status = requiredString(row, "status");
  if (status !== "active" && status !== "revoked") {
    throw new TypeError("invalid D1 API key status");
  }

  const metadata: ApiKeyMetadata = {
    key_id: requiredString(row, "key_id"),
    principal_id: requiredString(row, "principal_id"),
    tenant_id: requiredString(row, "tenant_id"),
    daily_ai_limit: requiredInteger(row, "daily_ai_limit"),
    status,
    key_prefix: requiredString(row, "key_prefix"),
    label: requiredString(row, "label"),
    created_at: requiredInteger(row, "created_at"),
    revoked_at: nullableInteger(row, "revoked_at"),
  };

  if (
    (metadata.status === "active" && metadata.revoked_at !== null) ||
    (metadata.status === "revoked" && metadata.revoked_at === null)
  ) {
    throw new TypeError("incoherent D1 API key lifecycle");
  }

  return metadata;
}

const API_KEY_PROJECTION = `
  id AS key_id, principal_id, tenant_id, daily_ai_limit, status,
  key_prefix, label, created_at, revoked_at
`;

export class D1ApiKeyManagementRepository
  implements ApiKeyManagementRepository
{
  constructor(private readonly database: D1Connection) {}

  async list(query: ApiKeyListQuery): Promise<ApiKeyMetadata[]> {
    const conditions: string[] = [];
    const bindings: unknown[] = [];

    if (query.tenant_id !== undefined) {
      bindings.push(query.tenant_id);
      conditions.push(`tenant_id = ?${bindings.length}`);
    }
    if (query.status !== undefined) {
      bindings.push(query.status);
      conditions.push(`status = ?${bindings.length}`);
    }

    bindings.push(queryLimit(query.limit));
    const where = conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")}`;
    const result = await this.database
      .prepare(
        `SELECT ${API_KEY_PROJECTION}
         FROM api_keys
         ${where}
         ORDER BY created_at DESC, id DESC
         LIMIT ?${bindings.length}`,
      )
      .bind(...bindings)
      .all<Record<string, unknown>>();

    return result.results.map(apiKeyFromRow);
  }

  async create(input: NewApiKeyRecord): Promise<ApiKeyCreateResult> {
    const mismatch = await this.database
      .prepare(
        `SELECT 1 AS present FROM api_keys
         WHERE principal_id = ?1 AND tenant_id <> ?2
         LIMIT 1`,
      )
      .bind(input.principal_id, input.tenant_id)
      .first<Record<string, unknown>>();

    if (mismatch !== null) return { kind: "principal_tenant_conflict" };

    // The database trigger remains the final authority under a concurrent
    // insert. Such a race fails closed as unavailable rather than being
    // mislabeled as an ordinary key collision.
    const row = await this.database
      .prepare(
        `INSERT INTO api_keys (
           id, principal_id, key_hash, key_prefix, tenant_id, label,
           status, created_at, revoked_at, daily_ai_limit
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, NULL, ?8)
         ON CONFLICT DO NOTHING
         RETURNING ${API_KEY_PROJECTION}`,
      )
      .bind(
        input.key_id,
        input.principal_id,
        input.key_hash,
        input.key_prefix,
        input.tenant_id,
        input.label,
        input.created_at,
        input.daily_ai_limit,
      )
      .first<Record<string, unknown>>();

    if (row !== null) {
      return { kind: "created", api_key: apiKeyFromRow(row) };
    }

    return { kind: "conflict" };
  }

  async revoke(keyId: string, revokedAt: number): Promise<ApiKeyRevokeResult> {
    const row = await this.database
      .prepare(
        `UPDATE api_keys
         SET status = 'revoked', revoked_at = ?2
         WHERE id = ?1 AND status = 'active' AND revoked_at IS NULL
         RETURNING ${API_KEY_PROJECTION}`,
      )
      .bind(keyId, revokedAt)
      .first<Record<string, unknown>>();

    if (row !== null) {
      return { kind: "revoked", api_key: apiKeyFromRow(row) };
    }

    const existing = await this.database
      .prepare(`SELECT ${API_KEY_PROJECTION} FROM api_keys WHERE id = ?1`)
      .bind(keyId)
      .first<Record<string, unknown>>();

    return existing === null
      ? { kind: "not_found" }
      : { kind: "already_revoked", api_key: apiKeyFromRow(existing) };
  }
}

function metric(row: Record<string, unknown>, field: string): number {
  return requiredInteger(row, field);
}

export class D1OperatorOverviewRepository
  implements OperatorOverviewRepository
{
  constructor(private readonly database: D1Connection) {}

  async getMetrics(
    dayUtc: string,
    nowUnixSeconds: number,
  ): Promise<OperatorOverviewMetrics> {
    const row = await this.database
      .prepare(
        `SELECT
           (SELECT count(*) FROM audit_events
            WHERE event_type = 'EVALUATED' AND decision = 'ALLOW') AS allowed,
           (SELECT count(*) FROM audit_events
            WHERE event_type = 'EVALUATED' AND decision = 'DENY') AS blocked,
           (SELECT count(*) FROM audit_events
            WHERE event_type = 'EVALUATED'
              AND decision = 'REQUIRE_APPROVAL') AS approval_required,
           (SELECT count(*) FROM approval_requests
            WHERE status = 'PENDING' AND expires_at > ?2) AS pending_approvals,
           (SELECT coalesce(sum(ai_calls), 0) FROM daily_ai_usage
            WHERE day_utc = ?1) AS ai_quota_used_today,
           (SELECT coalesce(sum(principal_limit), 0)
            FROM (
              SELECT principal_id, max(daily_ai_limit) AS principal_limit
              FROM api_keys
              WHERE status = 'active' AND revoked_at IS NULL
              GROUP BY principal_id
            )) AS ai_daily_limit`,
      )
      .bind(dayUtc, nowUnixSeconds)
      .first<Record<string, unknown>>();

    if (row === null) {
      throw new Error("D1 overview query returned no row");
    }

    return {
      allowed: metric(row, "allowed"),
      blocked: metric(row, "blocked"),
      approval_required: metric(row, "approval_required"),
      pending_approvals: metric(row, "pending_approvals"),
      ai_quota_used_today: metric(row, "ai_quota_used_today"),
      ai_daily_limit: metric(row, "ai_daily_limit"),
    };
  }
}

export function createD1OperatorRepositories(database: D1Database) {
  const session = database.withSession("first-primary");
  return {
    apiKeys: new D1ApiKeyManagementRepository(session),
    overview: new D1OperatorOverviewRepository(session),
  };
}
