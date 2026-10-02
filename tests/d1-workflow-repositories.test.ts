import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import type { EvaluationResult } from "../src/contracts";
import { createD1WorkflowRepositories } from "../src/persistence/d1-workflow-repositories";
import type {
  AuditEvent,
  NewApprovalRequest,
} from "../src/persistence/types";
import { sha256Hex } from "../src/security/crypto";
import { POLICY_VERSION } from "../src/policy-metadata";
import { createD1SecurityRepositories } from "../src/security/d1-repositories";

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
    return this.firstSync<T>();
  }

  async all<T>(): Promise<D1Result<T>> {
    return { results: this.allSync<T>() } as D1Result<T>;
  }

  async run<T>(): Promise<D1Result<T>> {
    this.statement().run(...this.bindings);
    return { results: [] } as unknown as D1Result<T>;
  }

  firstSync<T>(): T | null {
    return this.statement().get(...this.bindings) as T | null;
  }

  allSync<T>(): T[] {
    return this.statement().all(...this.bindings) as T[];
  }

  private statement(): SqliteStatementLike {
    return this.database.query(this.sql) as unknown as SqliteStatementLike;
  }
}

function localD1(database: Database): D1Database {
  const session = {
    prepare: (sql: string) => new LocalD1Statement(database, sql),
    batch: async <T>(statements: D1PreparedStatement[]) => {
      const transaction = database.transaction(
        (items: D1PreparedStatement[]) =>
          items.map((item) => ({
            results: (item as unknown as LocalD1Statement).allSync<T>(),
          })) as D1Result<T>[],
      );
      return transaction(statements);
    },
  };

  // Only the D1 surface exercised by the repositories is emulated here.
  return {
    withSession: () => session,
  } as unknown as D1Database;
}

async function workflowDatabase(): Promise<Database> {
  const database = new Database(":memory:", { strict: true });
  databases.push(database);
  database.exec(await Bun.file("migrations/0001_security.sql").text());
  database.exec(await Bun.file("migrations/0002_audit_approval.sql").text());
  database.exec(
    await Bun.file("migrations/0003_policy_version_approval_display.sql").text(),
  );
  return database;
}

function insertPendingIdempotency(input: {
  database: Database;
  keyHash: string;
  requestHash: string;
  owner: string;
}): void {
  input.database
    .query(
      `INSERT INTO idempotency_records (
        principal_id, idempotency_key_hash, request_hash, policy_version,
        response_json, state, claim_token, created_at, expires_at,
        lease_expires_at, completed_at
      ) VALUES (?, ?, ?, ?, NULL, 'pending', ?, 100, 1000, 200, NULL)`,
    )
    .run(
      "principal-a",
      input.keyHash,
      input.requestHash,
      POLICY_VERSION,
      input.owner,
    );
}

function approvalFixture(id: string): NewApprovalRequest {
  return {
    id,
    principal_id: "principal-a",
    tenant_id: "tenant-a",
    tool_name: "email.send",
    request_hash: "a".repeat(64),
    risk_level: "medium",
    policy_codes: ["OUTBOUND_SEND"],
    policy_version: POLICY_VERSION,
    approval_display: {
      kind: "email_send",
      recipient: "customer@example.com",
      has_attachments: false,
    },
    created_at: 100,
    expires_at: 700,
  };
}

function eventFixture(id: string, approvalId: string): AuditEvent {
  return {
    id,
    request_id: `request-${id}`,
    principal_id: "principal-a",
    key_id: "key-a",
    tenant_id: "tenant-a",
    tool_name: "email.send",
    event_type: "EVALUATED",
    decision: "REQUIRE_APPROVAL",
    risk_level: "medium",
    policy_codes: ["OUTBOUND_SEND"],
    arguments_hash: "b".repeat(64),
    source_text_hash: "c".repeat(64),
    approval_id: approvalId,
    policy_version: POLICY_VERSION,
    created_at: 100,
  };
}

function responseFixture(approvalId: string): EvaluationResult {
  return {
    decision: "REQUIRE_APPROVAL",
    risk_level: "medium",
    policy_codes: ["OUTBOUND_SEND"],
    requires_approval: true,
    normalized_tool: "email.send",
    normalized_args: {
      to: "customer@example.com",
      target_tenant: "tenant-a",
    },
    approval_id: approvalId,
    expires_at: new Date(700_000).toISOString(),
  };
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe("D1 evaluation persistence transaction", () => {
  test("applies inclusive-from and exclusive-to audit time bounds", async () => {
    const database = await workflowDatabase();
    const repositories = createD1WorkflowRepositories(localD1(database));
    await repositories.audit.append({
      ...eventFixture("audit-window-start", "approval-window-start"),
      created_at: 100,
    });
    await repositories.audit.append({
      ...eventFixture("audit-window-end", "approval-window-end"),
      created_at: 200,
    });

    expect(
      (await repositories.audit.list({ created_from: 100, created_to: 200 })).map(
        ({ id }) => id,
      ),
    ).toEqual(["audit-window-start"]);
    await expect(
      repositories.audit.list({ created_from: 200, created_to: 200 }),
    ).rejects.toThrow("created_from must be less than created_to");
  });

  test("commits approval, audit, and a request-data-free replay envelope", async () => {
    const database = await workflowDatabase();
    const keyHash = "d".repeat(64);
    const requestHash = "e".repeat(64);
    const owner = "owner-token-0000000000000001";
    insertPendingIdempotency({ database, keyHash, requestHash, owner });
    const repositories = createD1WorkflowRepositories(localD1(database));
    const approval = approvalFixture("approval-1");
    const event = eventFixture("audit-1", approval.id);
    const response = responseFixture(approval.id);

    await repositories.evaluations.persist({
      event,
      approval,
      idempotency: {
        principal_id: "principal-a",
        idempotency_key_hash: keyHash,
        request_hash: requestHash,
        owner_token: owner,
        response,
        now: 110,
      },
    });

    expect(
      database
        .query<{ count: number }, []>(
          "SELECT count(*) AS count FROM audit_events",
        )
        .get(),
    ).toEqual({ count: 1 });
    expect(
      database
        .query<{ count: number }, []>(
          "SELECT count(*) AS count FROM approval_requests",
        )
        .get(),
    ).toEqual({ count: 1 });
    const stored = database
      .query<
        { state: string; response_json: string; policy_version: string },
        []
      >(
        "SELECT state, response_json, policy_version FROM idempotency_records",
      )
      .get();
    expect(stored?.state).toBe("completed");
    expect(stored?.policy_version).toBe(POLICY_VERSION);
    expect(JSON.parse(stored!.response_json)).toEqual({
      decision: "REQUIRE_APPROVAL",
      risk_level: "medium",
      policy_codes: ["OUTBOUND_SEND"],
      requires_approval: true,
      approval_id: approval.id,
      expires_at: new Date(700_000).toISOString(),
    });
    expect(stored?.response_json).not.toContain("normalized_args");
    expect(stored?.response_json).not.toContain("normalized_tool");
    expect(stored?.response_json).not.toContain("customer@example.com");
    expect(stored?.response_json).not.toContain("target_tenant");
    expect(
      database
        .query<
          { policy_version: string; approval_display_json: string },
          []
        >(
          `SELECT policy_version, approval_display_json
           FROM approval_requests WHERE id = 'approval-1'`,
        )
        .get(),
    ).toEqual({
      policy_version: POLICY_VERSION,
      approval_display_json: JSON.stringify(approval.approval_display),
    });

    const replay = await createD1SecurityRepositories(localD1(database)).idempotency.claim({
      principal_id: "principal-a",
      idempotency_key_hash: keyHash,
      request_hash: requestHash,
      owner_token: "owner-token-0000000000000099",
      now: 120,
      expires_at: 1_000,
      lease_expires_at: 180,
    });
    expect(replay).toEqual({
      kind: "replay",
      response: {
        decision: "REQUIRE_APPROVAL",
        risk_level: "medium",
        policy_codes: ["OUTBOUND_SEND"],
        requires_approval: true,
        approval_id: approval.id,
        expires_at: new Date(700_000).toISOString(),
      },
    });
  });

  test("lost idempotency ownership creates neither audit nor approval", async () => {
    const database = await workflowDatabase();
    const keyHash = "f".repeat(64);
    const requestHash = "1".repeat(64);
    insertPendingIdempotency({
      database,
      keyHash,
      requestHash,
      owner: "actual-owner-token-000000000001",
    });
    const repositories = createD1WorkflowRepositories(localD1(database));
    const approval = approvalFixture("approval-2");

    await expect(
      repositories.evaluations.persist({
        event: eventFixture("audit-2", approval.id),
        approval,
        idempotency: {
          principal_id: "principal-a",
          idempotency_key_hash: keyHash,
          request_hash: requestHash,
          owner_token: "wrong-owner-token-000000000002",
          response: responseFixture(approval.id),
          now: 110,
        },
      }),
    ).rejects.toThrow("lost ownership");

    expect(
      database
        .query<{ audits: number; approvals: number }, []>(
          `SELECT
             (SELECT count(*) FROM audit_events) AS audits,
             (SELECT count(*) FROM approval_requests) AS approvals`,
        )
        .get(),
    ).toEqual({ audits: 0, approvals: 0 });
    expect(
      database
        .query<{ state: string }, []>(
          "SELECT state FROM idempotency_records",
        )
        .get(),
    ).toEqual({ state: "pending" });
  });

  test("idempotent unknown tools persist only a hashed audit sentinel", async () => {
    const database = await workflowDatabase();
    const keyHash = "2".repeat(64);
    const requestHash = "3".repeat(64);
    const owner = "owner-token-0000000000000003";
    const rawTool = "private.tool.aag_test_secret_fixture";
    const persistedTool = `unknown.sha256.${await sha256Hex(rawTool)}`;
    insertPendingIdempotency({ database, keyHash, requestHash, owner });
    const repositories = createD1WorkflowRepositories(localD1(database));
    const response: EvaluationResult = {
      decision: "DENY",
      risk_level: "high",
      policy_codes: ["UNKNOWN_TOOL"],
      requires_approval: false,
      normalized_tool: rawTool,
      normalized_args: {
        recipient: "private-recipient@example.com",
        target_tenant: "tenant-a",
      },
    };

    await repositories.evaluations.persist({
      event: {
        id: "audit-unknown",
        request_id: "request-unknown",
        principal_id: "principal-a",
        key_id: "key-a",
        tenant_id: "tenant-a",
        tool_name: persistedTool,
        event_type: "EVALUATED",
        decision: "DENY",
        risk_level: "high",
        policy_codes: ["UNKNOWN_TOOL"],
        arguments_hash: "4".repeat(64),
        source_text_hash: "5".repeat(64),
        approval_id: null,
        policy_version: POLICY_VERSION,
        created_at: 110,
      },
      approval: null,
      idempotency: {
        principal_id: "principal-a",
        idempotency_key_hash: keyHash,
        request_hash: requestHash,
        owner_token: owner,
        response,
        now: 110,
      },
    });

    const audit = database
      .query<{ tool_name: string }, []>(
        "SELECT tool_name FROM audit_events WHERE id = 'audit-unknown'",
      )
      .get();
    const replay = database
      .query<{ response_json: string }, []>(
        "SELECT response_json FROM idempotency_records",
      )
      .get();
    expect(audit?.tool_name).toBe(persistedTool);
    expect(replay?.response_json).not.toContain(rawTool);
    expect(replay?.response_json).not.toContain("private-recipient@example.com");
    expect(JSON.parse(replay!.response_json)).toEqual({
      decision: "DENY",
      risk_level: "high",
      policy_codes: ["UNKNOWN_TOOL"],
      requires_approval: false,
    });
  });
});
