import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createD1OperatorRepositories } from "../src/security/d1-operator-repositories";
import { sha256Hex } from "../src/security/crypto";

const databases: Database[] = [];

interface SqliteStatementLike {
  all(...bindings: unknown[]): Record<string, unknown>[];
  get(...bindings: unknown[]): Record<string, unknown> | null;
  run(...bindings: unknown[]): unknown;
}

class LocalD1Statement {
  constructor(
    private readonly database: Database,
    private readonly sql: string,
    private readonly bindings: unknown[] = [],
  ) {}

  bind(...bindings: unknown[]): LocalD1Statement {
    return new LocalD1Statement(this.database, this.sql, bindings);
  }

  async first<T>(): Promise<T | null> {
    return (this.database.query(this.sql) as unknown as SqliteStatementLike).get(
      ...this.bindings,
    ) as T | null;
  }

  async all<T>(): Promise<D1Result<T>> {
    return {
      results: (this.database.query(this.sql) as unknown as SqliteStatementLike).all(
        ...this.bindings,
      ) as T[],
    } as D1Result<T>;
  }

  async run<T>(): Promise<D1Result<T>> {
    (this.database.query(this.sql) as unknown as SqliteStatementLike).run(
      ...this.bindings,
    );
    return { results: [] } as unknown as D1Result<T>;
  }
}

function localD1(database: Database): D1Database {
  return {
    withSession: () => ({
      prepare: (sql: string) => new LocalD1Statement(database, sql),
    }),
  } as unknown as D1Database;
}

async function database(): Promise<Database> {
  const db = new Database(":memory:", { strict: true });
  databases.push(db);
  for (const migration of [
    "migrations/0001_security.sql",
    "migrations/0002_audit_approval.sql",
    "migrations/0003_policy_version_approval_display.sql",
  ]) {
    db.exec(await Bun.file(migration).text());
  }
  return db;
}

afterEach(() => {
  for (const db of databases.splice(0)) db.close();
});

describe("D1 Step 7 operator repositories", () => {
  test("stores only the API-key hash and exposes safe metadata through list/revoke", async () => {
    const db = await database();
    const repositories = createD1OperatorRepositories(localD1(db));
    const rawKey = ["aag", "test", "obviously_fake_d1_operator_repo_key"].join("_");
    const keyHash = await sha256Hex(rawKey);
    const created = await repositories.apiKeys.create({
      key_id: "aagk_fixture",
      principal_id: "aagp_fixture",
      tenant_id: "tenant-a",
      daily_ai_limit: 25,
      key_prefix: "aag_test_obviousl",
      label: "Operator repository fixture",
      created_at: 100,
      key_hash: keyHash,
    });

    expect(created).toMatchObject({
      kind: "created",
      api_key: { key_id: "aagk_fixture", status: "active" },
    });
    const stored = db
      .query<{ key_hash: string }, []>("SELECT key_hash FROM api_keys")
      .get();
    expect(stored).toEqual({ key_hash: keyHash });
    expect(JSON.stringify(stored)).not.toContain(rawKey);
    expect(
      db.query<{ name: string }, []>("PRAGMA table_info(api_keys)").all()
        .map(({ name }) => name),
    ).not.toContain("raw_api_key");

    if (created.kind !== "created") throw new Error("fixture key was not created");
    expect(await repositories.apiKeys.list({ limit: 10 })).toEqual([
      created.api_key,
    ]);
    expect(await repositories.apiKeys.revoke("aagk_fixture", 200)).toMatchObject({
      kind: "revoked",
      api_key: { status: "revoked", revoked_at: 200 },
    });
  });

  test("preserves tenant authority and returns bounded aggregate overview metrics", async () => {
    const db = await database();
    const repositories = createD1OperatorRepositories(localD1(db));
    const first = await repositories.apiKeys.create({
      key_id: "key-a",
      principal_id: "principal-a",
      tenant_id: "tenant-a",
      daily_ai_limit: 20,
      key_prefix: "aag_test_keyaaaaa",
      label: "First key",
      created_at: 100,
      key_hash: "a".repeat(64),
    });
    expect(first.kind).toBe("created");
    expect(
      await repositories.apiKeys.create({
        key_id: "key-b",
        principal_id: "principal-a",
        tenant_id: "tenant-b",
        daily_ai_limit: 20,
        key_prefix: "aag_test_keybbbbb",
        label: "Conflicting key",
        created_at: 101,
        key_hash: "b".repeat(64),
      }),
    ).toEqual({ kind: "principal_tenant_conflict" });

    db.query(
      `INSERT INTO daily_ai_usage
       (principal_id, day_utc, ai_calls, updated_at) VALUES (?, ?, ?, ?)`,
    ).run("principal-a", "2026-10-01", 7, 200);
    for (const [id, decision] of [
      ["audit-allow", "ALLOW"],
      ["audit-deny", "DENY"],
      ["audit-approval", "REQUIRE_APPROVAL"],
    ] as const) {
      db.query(
        `INSERT INTO audit_events (
           id, request_id, principal_id, key_id, tenant_id, tool_name,
           event_type, decision, risk_level, policy_codes_json,
           arguments_hash, source_text_hash, approval_id, created_at,
           policy_version
         ) VALUES (?, ?, 'principal-a', 'key-a', 'tenant-a',
           'crm.read_contact', 'EVALUATED', ?, 'low', '[]', ?, ?, NULL,
           200, 'aag-policy-v1')`,
      ).run(id, `request-${id}`, decision, "c".repeat(64), "d".repeat(64));
    }
    db.query(
      `INSERT INTO approval_requests (
         id, principal_id, tenant_id, tool_name, request_hash, risk_level,
         policy_codes_json, status, created_at, expires_at, policy_version,
         approval_display_json
       ) VALUES ('approval-1', 'principal-a', 'tenant-a', 'email.send', ?,
         'medium', '["OUTBOUND_SEND"]', 'PENDING', 100, 1000,
         'aag-policy-v1',
         '{"kind":"email_send","recipient":"customer@example.com","has_attachments":false}')`,
    ).run("e".repeat(64));

    expect(
      await repositories.overview.getMetrics("2026-10-01", 500),
    ).toEqual({
      allowed: 1,
      blocked: 1,
      approval_required: 1,
      pending_approvals: 1,
      ai_quota_used_today: 7,
      ai_daily_limit: 20,
    });
    expect(
      (await repositories.overview.getMetrics("2026-10-01", 1_000))
        .pending_approvals,
    ).toBe(0);
  });
});
