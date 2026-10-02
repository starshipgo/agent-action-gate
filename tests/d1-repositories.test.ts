import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import {
  ATOMIC_QUOTA_SQL,
  CLAIM_IDEMPOTENCY_SQL,
  COMPLETE_IDEMPOTENCY_SQL,
} from "../src/security/d1-repositories";
import { POLICY_VERSION } from "../src/policy-metadata";

const databases: Database[] = [];

async function securityDatabase(limit = 2): Promise<Database> {
  const database = new Database(":memory:", { strict: true });
  databases.push(database);
  database.exec(await Bun.file("migrations/0001_security.sql").text());
  database.exec(await Bun.file("migrations/0002_audit_approval.sql").text());
  database.exec(
    await Bun.file("migrations/0003_policy_version_approval_display.sql").text(),
  );
  database
    .query(
      `INSERT INTO api_keys (
        id, principal_id, key_hash, key_prefix, tenant_id, label,
        status, daily_ai_limit
      ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
    )
    .run(
      "key-fixture",
      "principal-fixture",
      "0".repeat(64),
      "aag_test_fixture",
      "tenant-a",
      "Unit test fixture",
      limit,
    );
  return database;
}

afterEach(() => {
  for (const database of databases.splice(0)) {
    database.close();
  }
});

describe("D1 security migration and quota SQL", () => {
  test("migration creates all three security tables", async () => {
    const database = await securityDatabase();
    const names = database
      .query<{ name: string }, []>(
        `SELECT name FROM sqlite_schema
         WHERE type = 'table' AND name NOT LIKE '_cf_%'
         ORDER BY name`,
      )
      .all()
      .map(({ name }) => name);

    expect(names).toContain("api_keys");
    expect(names).toContain("daily_ai_usage");
    expect(names).toContain("idempotency_records");
  });

  test("one principal cannot be assigned API keys for different tenants", async () => {
    const database = await securityDatabase();
    const insert = database.query(
      `INSERT INTO api_keys (
        id, principal_id, key_hash, key_prefix, tenant_id, label,
        status, daily_ai_limit
      ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
    );

    expect(() =>
      insert.run(
        "key-fixture-2",
        "principal-fixture",
        "9".repeat(64),
        "aag_test_fixture2",
        "tenant-b",
        "Conflicting tenant fixture",
        2,
      ),
    ).toThrow("principal tenant mismatch");
  });

  test("an existing key's principal and tenant authority cannot be changed", async () => {
    const database = await securityDatabase();

    expect(() =>
      database
        .query("UPDATE api_keys SET tenant_id = ? WHERE id = ?")
        .run("tenant-b", "key-fixture"),
    ).toThrow("API key authority is immutable");
    expect(() =>
      database
        .query("UPDATE api_keys SET principal_id = ? WHERE id = ?")
        .run("principal-b", "key-fixture"),
    ).toThrow("API key authority is immutable");
  });

  test("allows the call that reaches the exact limit and denies the next", async () => {
    const database = await securityDatabase(2);
    const reserve = database.query<
      { ai_calls: number; daily_ai_limit: number },
      [string, string, number, string]
    >(ATOMIC_QUOTA_SQL);

    expect(
      reserve.get("principal-fixture", "2026-09-28", 1, "key-fixture"),
    ).toEqual({ ai_calls: 1, daily_ai_limit: 2 });
    expect(
      reserve.get("principal-fixture", "2026-09-28", 2, "key-fixture"),
    ).toEqual({ ai_calls: 2, daily_ai_limit: 2 });
    expect(
      reserve.get("principal-fixture", "2026-09-28", 3, "key-fixture"),
    ).toBeNull();

    expect(
      database
        .query<{ ai_calls: number }, []>("SELECT ai_calls FROM daily_ai_usage")
        .get(),
    ).toEqual({ ai_calls: 2 });
  });

  test("a zero limit creates no usage row", async () => {
    const database = await securityDatabase(0);

    expect(
      database
        .query(ATOMIC_QUOTA_SQL)
        .get("principal-fixture", "2026-09-28", 1, "key-fixture"),
    ).toBeNull();
    expect(
      database.query<{ count: number }, []>("SELECT count(*) AS count FROM daily_ai_usage").get(),
    ).toEqual({ count: 0 });
  });

  test("revocation between authentication and reservation prevents an AI call", async () => {
    const database = await securityDatabase(2);
    database
      .query(
        `UPDATE api_keys
         SET status = 'revoked', revoked_at = unixepoch()
         WHERE id = 'key-fixture'`,
      )
      .run();

    expect(
      database
        .query(ATOMIC_QUOTA_SQL)
        .get("principal-fixture", "2026-09-28", 1, "key-fixture"),
    ).toBeNull();
  });
});

describe("D1 idempotency ownership SQL", () => {
  test("migration removes legacy normalized request data and blocks it thereafter", async () => {
    const database = new Database(":memory:", { strict: true });
    databases.push(database);
    database.exec(await Bun.file("migrations/0001_security.sql").text());
    const legacyResponse = JSON.stringify({
      decision: "ALLOW",
      risk_level: "low",
      policy_codes: [],
      requires_approval: false,
      normalized_tool: "email.send.secret-fixture",
      normalized_args: { to: "private-recipient@example.com" },
    });
    database
      .query(
        `INSERT INTO idempotency_records (
          principal_id, idempotency_key_hash, request_hash, response_json,
          state, claim_token, created_at, expires_at, lease_expires_at,
          completed_at
        ) VALUES (?, ?, ?, ?, 'completed', NULL, ?, ?, NULL, ?)`,
      )
      .run(
        "principal-fixture",
        "8".repeat(64),
        "9".repeat(64),
        legacyResponse,
        100,
        1_000,
        110,
      );

    database.exec(await Bun.file("migrations/0002_audit_approval.sql").text());

    const stored = database
      .query<{ response_json: string }, []>(
        "SELECT response_json FROM idempotency_records",
      )
      .get();
    expect(JSON.parse(stored!.response_json)).toEqual({
      decision: "ALLOW",
      risk_level: "low",
      policy_codes: [],
      requires_approval: false,
    });
    expect(stored?.response_json).not.toContain("private-recipient@example.com");
    expect(stored?.response_json).not.toContain("secret-fixture");

    expect(() =>
      database
        .query(
          `UPDATE idempotency_records
           SET response_json = ?
           WHERE principal_id = 'principal-fixture'`,
        )
        .run(legacyResponse),
    ).toThrow("idempotency response cannot store normalized request data");
  });

  test("only one unexpired claimant owns an idempotency key", async () => {
    const database = await securityDatabase();
    const claim = database.query(CLAIM_IDEMPOTENCY_SQL);
    const values = [
      "principal-fixture",
      "1".repeat(64),
      "2".repeat(64),
      POLICY_VERSION,
      "owner-token-0000000000000001",
      1_000,
      87_400,
      1_060,
    ] as const;

    expect(claim.get(...values)).toMatchObject({
      request_hash: "2".repeat(64),
      state: "pending",
      claim_token: "owner-token-0000000000000001",
    });
    expect(
      claim.get(
        values[0],
        values[1],
        values[2],
        values[3],
        "owner-token-0000000000000002",
        1_001,
        87_401,
        1_061,
      ),
    ).toBeNull();
  });

  test("completion is guarded by the owning token and becomes replayable", async () => {
    const database = await securityDatabase();
    const principalId = "principal-fixture";
    const keyHash = "3".repeat(64);
    const requestHash = "4".repeat(64);
    const ownerToken = "owner-token-0000000000000003";
    const response = JSON.stringify({ decision: "DENY" });

    database
      .query(CLAIM_IDEMPOTENCY_SQL)
      .get(
        principalId,
        keyHash,
        requestHash,
        POLICY_VERSION,
        ownerToken,
        1_000,
        87_400,
        1_060,
      );

    expect(
      database
        .query(COMPLETE_IDEMPOTENCY_SQL)
        .get(
          principalId,
          keyHash,
          requestHash,
          "wrong-owner-token-0000000000",
          response,
          1_010,
          POLICY_VERSION,
        ),
    ).toBeNull();
    expect(
      database
        .query(COMPLETE_IDEMPOTENCY_SQL)
        .get(
          principalId,
          keyHash,
          requestHash,
          ownerToken,
          response,
          1_010,
          POLICY_VERSION,
        ),
    ).toEqual({ response_json: response });

    expect(
      database
        .query<{ state: string; response_json: string }, []>(
          `SELECT state, response_json FROM idempotency_records`,
        )
        .get(),
    ).toEqual({ state: "completed", response_json: response });
  });

  test("an expired record can be atomically replaced", async () => {
    const database = await securityDatabase();
    const claim = database.query(CLAIM_IDEMPOTENCY_SQL);
    const principalId = "principal-fixture";
    const keyHash = "5".repeat(64);

    claim.get(
      principalId,
      keyHash,
      "6".repeat(64),
      POLICY_VERSION,
      "owner-token-0000000000000004",
      1_000,
      2_000,
      1_060,
    );

    expect(
      claim.get(
        principalId,
        keyHash,
        "7".repeat(64),
        POLICY_VERSION,
        "owner-token-0000000000000005",
        2_001,
        88_401,
        2_061,
      ),
    ).toMatchObject({
      request_hash: "7".repeat(64),
      state: "pending",
      claim_token: "owner-token-0000000000000005",
    });
  });
});
