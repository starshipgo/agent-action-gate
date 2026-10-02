import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import {
  APPROVAL_TTL_SECONDS,
  buildEvaluationPersistenceArtifacts,
  consumeApprovedAction,
} from "../src/approvals/workflow";
import type {
  ActionRequest,
  EvaluationResult,
  NormalizationResult,
} from "../src/contracts";
import { normalizeToolCall } from "../src/normalize";
import { POLICY_VERSION } from "../src/policy-metadata";
import {
  CONSUME_APPROVAL_SQL,
  EXPIRE_DUE_APPROVALS_SQL,
} from "../src/persistence/d1-approval-repository";
import type {
  ApprovalRepository,
  ApprovalRequest,
  NewApprovalRequest,
} from "../src/persistence/types";
import { hashApprovalRequest, sha256Hex } from "../src/security/crypto";
import type { TrustedPrincipal } from "../src/security/types";

const databases: Database[] = [];
const syntheticBearer = ["Bearer", ["aag", "test", "secret", "value"].join("_")].join(" ");

const principal: TrustedPrincipal = {
  principal_id: "principal-a",
  tenant_id: "tenant-a",
  key_id: "key-a",
  daily_ai_limit: 25,
};

const approvalResult: EvaluationResult = {
  decision: "REQUIRE_APPROVAL",
  risk_level: "medium",
  policy_codes: ["OUTBOUND_SEND"],
  requires_approval: true,
  normalized_tool: "email.send",
  normalized_args: {
    to: "customer@example.com",
    target_tenant: "tenant-a",
  },
};

const approvalRequest: ActionRequest = {
  agent_role: "support-agent",
  tool_name: "email.send",
  arguments_json:
    '{"to":"customer@example.com","target_tenant":"tenant-a"}',
  source_text: "Send the requested account update.",
  request_tenant: "tenant-a",
};

async function auditApprovalDatabase(): Promise<Database> {
  const database = new Database(":memory:", { strict: true });
  databases.push(database);
  database.exec(await Bun.file("migrations/0001_security.sql").text());
  database.exec(await Bun.file("migrations/0002_audit_approval.sql").text());
  database.exec(
    await Bun.file("migrations/0003_policy_version_approval_display.sql").text(),
  );
  return database;
}

function insertApproval(
  database: Database,
  input: {
    id: string;
    requestHash: string;
    status?: "PENDING" | "APPROVED";
    createdAt?: number;
    expiresAt?: number;
    decidedAt?: number | null;
    decidedBy?: string | null;
  },
): void {
  const status = input.status ?? "PENDING";
  const createdAt = input.createdAt ?? 100;
  const expiresAt = input.expiresAt ?? 700;
  const decidedAt = input.decidedAt ?? (status === "APPROVED" ? 200 : null);
  const decidedBy = input.decidedBy ?? (status === "APPROVED" ? "operator-a" : null);

  database
    .query(
      `INSERT INTO approval_requests (
        id, principal_id, tenant_id, tool_name, request_hash, risk_level,
        policy_codes_json, policy_version, approval_display_json, status,
        created_at, expires_at, decided_at, decided_by, consumed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
    )
    .run(
      input.id,
      "principal-a",
      "tenant-a",
      "email.send",
      input.requestHash,
      "medium",
      '["OUTBOUND_SEND"]',
      POLICY_VERSION,
      '{"kind":"email_send","recipient":"customer@example.com","has_attachments":false}',
      status,
      createdAt,
      expiresAt,
      decidedAt,
      decidedBy,
    );
}

function normalizedRequest(): Extract<NormalizationResult, { parse_ok: true }> {
  const normalization = normalizeToolCall(approvalRequest);
  if (!normalization.parse_ok) {
    throw new Error("approval fixture must normalize");
  }
  return normalization;
}

afterEach(() => {
  for (const database of databases.splice(0)) {
    database.close();
  }
});

describe("Step 6 audit migration", () => {
  test("stores hashes rather than raw source text or bearer material and is append-only", async () => {
    const database = await auditApprovalDatabase();
    const sourceText = `${syntheticBearer} must never be persisted`;
    const sourceTextHash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(sourceText),
    );
    const hex = Array.from(new Uint8Array(sourceTextHash), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");

    database
      .query(
        `INSERT INTO audit_events (
          id, request_id, principal_id, key_id, tenant_id, tool_name,
          event_type, decision, risk_level, policy_codes_json,
          arguments_hash, source_text_hash, approval_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        "audit-1",
        "request-1",
        "principal-a",
        "key-a",
        "tenant-a",
        "email.send",
        "EVALUATED",
        "REQUIRE_APPROVAL",
        "medium",
        '["OUTBOUND_SEND"]',
        "a".repeat(64),
        hex,
        "approval-1",
        100,
      );

    const columns = database
      .query<{ name: string }, []>("PRAGMA table_info(audit_events)")
      .all()
      .map(({ name }) => name);
    const row = database
      .query<{ arguments_hash: string; source_text_hash: string }, []>(
        "SELECT arguments_hash, source_text_hash FROM audit_events",
      )
      .get();

    expect(columns).not.toContain("source_text");
    expect(columns).not.toContain("normalized_args");
    expect(columns).not.toContain("authorization");
    expect(JSON.stringify(row)).not.toContain(sourceText);
    expect(JSON.stringify(row)).not.toContain("aag_test_secret_value");
    expect(row?.source_text_hash).toBe(hex);
    expect(() =>
      database.query("UPDATE audit_events SET created_at = 101").run(),
    ).toThrow("audit_events is append-only");
    expect(() => database.query("DELETE FROM audit_events").run()).toThrow(
      "audit_events is append-only",
    );
  });

  test("emits append-only lifecycle audit events and consumes an approval once", async () => {
    const database = await auditApprovalDatabase();
    const requestHash = "b".repeat(64);
    insertApproval(database, { id: "approval-1", requestHash });

    database
      .query(
        `UPDATE approval_requests
         SET status = 'APPROVED', decided_at = ?, decided_by = ?
         WHERE id = ?`,
      )
      .run(200, "operator-a", "approval-1");

    const first = database
      .query<
        { status: string },
        [string, string, string, string, number, string]
      >(
        CONSUME_APPROVAL_SQL,
      )
      .get(
        "approval-1",
        "principal-a",
        "tenant-a",
        requestHash,
        300,
        POLICY_VERSION,
      );
    const second = database
      .query<
        { status: string },
        [string, string, string, string, number, string]
      >(
        CONSUME_APPROVAL_SQL,
      )
      .get(
        "approval-1",
        "principal-a",
        "tenant-a",
        requestHash,
        301,
        POLICY_VERSION,
      );
    const eventTypes = database
      .query<{ event_type: string }, []>(
        "SELECT event_type FROM audit_events ORDER BY created_at, id",
      )
      .all()
      .map(({ event_type }) => event_type);

    expect(first).toMatchObject({ status: "CONSUMED" });
    expect(second).toBeNull();
    expect(eventTypes).toEqual(["APPROVED", "CONSUMED"]);
  });

  test("requires every approval to be inserted in its initial pending state", async () => {
    const database = await auditApprovalDatabase();
    const states = [
      {
        status: "APPROVED",
        decidedAt: 200,
        decidedBy: "operator-a",
        consumedAt: null,
      },
      {
        status: "REJECTED",
        decidedAt: 200,
        decidedBy: "operator-a",
        consumedAt: null,
      },
      {
        status: "EXPIRED",
        decidedAt: null,
        decidedBy: null,
        consumedAt: null,
      },
      {
        status: "CONSUMED",
        decidedAt: 200,
        decidedBy: "operator-a",
        consumedAt: 300,
      },
    ] as const;

    for (const [index, state] of states.entries()) {
      expect(() =>
        database
          .query(
            `INSERT INTO approval_requests (
              id, principal_id, tenant_id, tool_name, request_hash, risk_level,
              policy_codes_json, policy_version, approval_display_json, status,
              created_at, expires_at, decided_at, decided_by, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            `approval-direct-${index}`,
            "principal-a",
            "tenant-a",
            "email.send",
            "d".repeat(64),
            "medium",
            '["OUTBOUND_SEND"]',
            POLICY_VERSION,
            '{"kind":"email_send","recipient":"customer@example.com","has_attachments":false}',
            state.status,
            100,
            700,
            state.decidedAt,
            state.decidedBy,
            state.consumedAt,
          ),
      ).toThrow("approval_requests must be inserted pending");
    }
  });

  test("allows only known or exactly hashed unknown audit tool names", async () => {
    const database = await auditApprovalDatabase();
    const insert = (id: string, toolName: string) =>
      database
        .query(
          `INSERT INTO audit_events (
            id, request_id, principal_id, key_id, tenant_id, tool_name,
            event_type, decision, risk_level, policy_codes_json,
            arguments_hash, source_text_hash, approval_id, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          id,
          `request-${id}`,
          "principal-a",
          "key-a",
          "tenant-a",
          toolName,
          "EVALUATED",
          "DENY",
          "high",
          '["UNKNOWN_TOOL"]',
          "a".repeat(64),
          "b".repeat(64),
          null,
          100,
        );

    insert("audit-known", "email.send");
    insert("audit-hashed", `unknown.sha256.${"c".repeat(64)}`);
    expect(() => insert("audit-raw", "bearer.aag_tool_secret_value")).toThrow();
    expect(() =>
      insert("audit-short-hash", `unknown.sha256.${"c".repeat(63)}`),
    ).toThrow();
    expect(() =>
      insert("audit-uppercase-hash", `unknown.sha256.${"C".repeat(64)}`),
    ).toThrow();
  });

  test("rejects REPLACE, sensitive policy metadata, and tampered lifecycle history", async () => {
    const database = await auditApprovalDatabase();
    const auditInsert = `
      INSERT INTO audit_events (
        id, request_id, principal_id, key_id, tenant_id, tool_name,
        event_type, decision, risk_level, policy_codes_json,
        arguments_hash, source_text_hash, approval_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const auditValues = [
      "audit-1",
      "request-1",
      "principal-a",
      "key-a",
      "tenant-a",
      "email.send",
      "EVALUATED",
      "DENY",
      "high",
      '["OUTBOUND_SEND"]',
      "a".repeat(64),
      "b".repeat(64),
      null,
      100,
    ] as const;
    database.query(auditInsert).run(...auditValues);

    expect(() =>
      database
        .query(auditInsert.replace("INSERT INTO", "INSERT OR REPLACE INTO"))
        .run(...auditValues),
    ).toThrow("audit_events is append-only");
    expect(() =>
      database
        .query(auditInsert)
        .run(
          "audit-2",
          "request-2",
          "principal-a",
          "key-a",
          "tenant-a",
          "email.send",
          "EVALUATED",
          "DENY",
          "high",
          JSON.stringify([syntheticBearer]),
          "a".repeat(64),
          "b".repeat(64),
          null,
          100,
        ),
    ).toThrow("invalid audit policy code");

    expect(() =>
      database
        .query(
          `INSERT INTO approval_requests (
            id, principal_id, tenant_id, tool_name, request_hash, risk_level,
            policy_codes_json, policy_version, approval_display_json, status,
            created_at, expires_at, decided_at, decided_by, consumed_at
          ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, NULL, NULL, NULL
          )`,
        )
        .run(
          "approval-unsafe-policy",
          "principal-a",
          "tenant-a",
          "email.send",
          "c".repeat(64),
          "medium",
          JSON.stringify([syntheticBearer]),
          POLICY_VERSION,
          '{"kind":"email_send","recipient":"customer@example.com","has_attachments":false}',
          100,
          700,
        ),
    ).toThrow("invalid approval policy code");

    const requestHash = "c".repeat(64);
    insertApproval(database, { id: "approval-1", requestHash });
    expect(() =>
      database
        .query(
          `INSERT OR REPLACE INTO approval_requests (
            id, principal_id, tenant_id, tool_name, request_hash, risk_level,
            policy_codes_json, policy_version, approval_display_json, status,
            created_at, expires_at, decided_at, decided_by, consumed_at
          ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?, ?, ?, NULL
          )`,
        )
        .run(
          "approval-1",
          "principal-a",
          "tenant-a",
          "email.send",
          requestHash,
          "medium",
          '["OUTBOUND_SEND"]',
          POLICY_VERSION,
          '{"kind":"email_send","recipient":"customer@example.com","has_attachments":false}',
          100,
          700,
          200,
          "operator-a",
        ),
    ).toThrow("approval_requests cannot be replaced");

    database
      .query(
        `UPDATE approval_requests
         SET status = 'APPROVED', decided_at = ?, decided_by = ?
         WHERE id = ?`,
      )
      .run(200, "operator-a", "approval-1");
    expect(() =>
      database
        .query(
          `UPDATE approval_requests
           SET status = 'CONSUMED', consumed_at = ?, decided_at = ?, decided_by = ?
           WHERE id = ?`,
        )
        .run(300, 250, "forged-operator", "approval-1"),
    ).toThrow("invalid approval status transition");
    expect(() =>
      database
        .query(
          `UPDATE approval_requests
           SET status = 'EXPIRED', decided_at = NULL, decided_by = NULL
           WHERE id = ?`,
        )
        .run("approval-1"),
    ).toThrow("invalid approval status transition");

    insertApproval(database, { id: "approval-2", requestHash });
    expect(() =>
      database
        .query(
          `UPDATE approval_requests
           SET status = 'EXPIRED', decided_at = ?, decided_by = ?
           WHERE id = ?`,
        )
        .run(300, "forged-operator", "approval-2"),
    ).toThrow("invalid approval status transition");
  });

  test("does not permit approval decisions at or after the expiry cutoff", async () => {
    const database = await auditApprovalDatabase();
    const requestHash = "d".repeat(64);

    insertApproval(database, {
      id: "approval-at-expiry",
      requestHash,
      expiresAt: 700,
    });
    expect(() =>
      database
        .query(
          `UPDATE approval_requests
           SET status = 'APPROVED', decided_at = ?, decided_by = ?
           WHERE id = ?`,
        )
        .run(700, "operator-a", "approval-at-expiry"),
    ).toThrow("invalid approval status transition");

    insertApproval(database, {
      id: "rejection-after-expiry",
      requestHash,
      expiresAt: 700,
    });
    expect(() =>
      database
        .query(
          `UPDATE approval_requests
           SET status = 'REJECTED', decided_at = ?, decided_by = ?
           WHERE id = ?`,
        )
        .run(701, "operator-a", "rejection-after-expiry"),
    ).toThrow("invalid approval status transition");
  });

  test("lazy list expiration cannot leave later expired approvals pending", async () => {
    const database = await auditApprovalDatabase();

    for (let index = 0; index < 101; index += 1) {
      insertApproval(database, {
        id: `approval-${index}`,
        requestHash: index.toString(16).padStart(64, "a"),
        createdAt: 0,
        expiresAt: 1,
      });
    }

    database.query(EXPIRE_DUE_APPROVALS_SQL).run(1);
    const expired = database
      .query<{ count: number }, []>(
        "SELECT count(*) AS count FROM approval_requests WHERE status = 'EXPIRED'",
      )
      .get();

    expect(expired).toEqual({ count: 101 });
  });
});

describe("approval workflow privacy and request binding", () => {
  test("creates an approval only for REQUIRE_APPROVAL and persists only hashed evidence", async () => {
    let sequence = 0;
    const artifacts = await buildEvaluationPersistenceArtifacts({
      request: approvalRequest,
      normalization: normalizedRequest(),
      result: approvalResult,
      principal,
      now: 1_000,
      createId: (kind) => `${kind}-${++sequence}`,
    });

    expect(artifacts.result).toMatchObject({
      approval_id: "approval-1",
      expires_at: new Date(
        (1_000 + APPROVAL_TTL_SECONDS) * 1_000,
      ).toISOString(),
    });
    expect(artifacts.persistence.approval).toMatchObject({
      id: "approval-1",
      request_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(artifacts.persistence.event).toMatchObject({
      source_text_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
      arguments_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
      approval_id: "approval-1",
    });
    expect(JSON.stringify(artifacts.persistence)).not.toContain(
      approvalRequest.source_text,
    );
    expect(JSON.stringify(artifacts.persistence)).not.toContain(
      approvalRequest.arguments_json,
    );

    const allowArtifacts = await buildEvaluationPersistenceArtifacts({
      request: approvalRequest,
      normalization: normalizedRequest(),
      result: {
        ...approvalResult,
        decision: "ALLOW",
        requires_approval: false,
      },
      principal,
      now: 1_000,
      createId: (kind) => `${kind}-${++sequence}`,
    });
    expect(allowArtifacts.persistence.approval).toBeNull();
    expect(allowArtifacts.result.approval_id).toBeUndefined();
  });

  test("hashes a secret-like unknown tool name before audit persistence", async () => {
    const secretToolName = "Bearer.aag_tool_secret_value";
    const request: ActionRequest = {
      ...approvalRequest,
      tool_name: secretToolName,
    };
    const normalization = normalizeToolCall(request);
    const artifacts = await buildEvaluationPersistenceArtifacts({
      request,
      normalization,
      result: {
        decision: "DENY",
        risk_level: "high",
        policy_codes: ["UNKNOWN_TOOL"],
        requires_approval: false,
        normalized_tool: normalization.normalized.tool_name,
        normalized_args: normalization.normalized.args,
      },
      principal,
      now: 1_000,
      createId: (kind) => `${kind}-unknown`,
    });
    const expected = `unknown.sha256.${await sha256Hex(
      normalization.normalized.tool_name,
    )}`;

    expect(artifacts.persistence.event.tool_name).toBe(expected);
    expect(artifacts.persistence.event.tool_name).toMatch(
      /^unknown\.sha256\.[0-9a-f]{64}$/,
    );
    expect(JSON.stringify(artifacts.persistence)).not.toContain(
      secretToolName.toLowerCase(),
    );
  });

  test("requires the exact request hash before atomic consumption", async () => {
    const normalization = normalizedRequest();
    const requestHash = await hashApprovalRequest({
      principal_id: principal.principal_id,
      trusted_tenant_id: principal.tenant_id,
      normalized: normalization.normalized,
      source_text: approvalRequest.source_text,
      policy: approvalResult,
    });
    const approval: ApprovalRequest = {
      id: "approval-1",
      principal_id: principal.principal_id,
      tenant_id: principal.tenant_id,
      tool_name: "email.send",
      request_hash: requestHash,
      risk_level: "medium",
      policy_codes: ["OUTBOUND_SEND"],
      policy_version: POLICY_VERSION,
      approval_display: {
        kind: "email_send",
        recipient: "customer@example.com",
        has_attachments: false,
      },
      status: "APPROVED",
      created_at: 1_000,
      expires_at: 1_600,
      decided_at: 1_010,
      decided_by: "operator-a",
      consumed_at: null,
    };
    let consumeCalls = 0;
    const approvals: ApprovalRepository = {
      create: async (_input: NewApprovalRequest) => approval,
      findById: async () => approval,
      decide: async () => ({ kind: "conflict", approval }),
      consume: async (input) => {
        consumeCalls += 1;
        return input.request_hash === requestHash
          ? { kind: "consumed", approval, audit_persisted: true }
          : { kind: "request_mismatch", approval };
      },
      list: async () => [],
    };
    const changedRecipient: ActionRequest = {
      ...approvalRequest,
      arguments_json:
        '{"to":"different@example.com","target_tenant":"tenant-a"}',
    };

    const mismatch = await consumeApprovedAction({
      approval_id: approval.id,
      request: changedRecipient,
      principal,
      approvals,
      now: 1_100,
    });
    const consumed = await consumeApprovedAction({
      approval_id: approval.id,
      request: approvalRequest,
      principal,
      approvals,
      now: 1_100,
    });

    expect(mismatch).toEqual({
      authorized: false,
      error: "APPROVAL_REQUEST_MISMATCH",
    });
    expect(consumed).toMatchObject({
      authorized: true,
      approval_id: approval.id,
      tool_name: "email.send",
    });
    expect(consumeCalls).toBe(1);
  });

  test("treats a changed refund amount_minor as an approval mismatch", async () => {
    const refundRequest: ActionRequest = {
      agent_role: "support-agent",
      tool_name: "refund.create",
      arguments_json:
        '{"amount_minor":1200,"target_tenant":"tenant-a"}',
      source_text: "Issue the approved refund.",
      request_tenant: "tenant-a",
    };
    const refundPolicy: EvaluationResult = {
      decision: "REQUIRE_APPROVAL",
      risk_level: "medium",
      policy_codes: ["REFUND_REQUIRES_APPROVAL"],
      requires_approval: true,
      normalized_tool: "refund.create",
      normalized_args: {
        amount_minor: 1200,
        target_tenant: "tenant-a",
      },
    };
    const normalized = normalizeToolCall(refundRequest);
    if (!normalized.parse_ok) throw new Error("refund fixture must normalize");
    const requestHash = await hashApprovalRequest({
      principal_id: principal.principal_id,
      trusted_tenant_id: principal.tenant_id,
      normalized: normalized.normalized,
      source_text: refundRequest.source_text,
      policy: refundPolicy,
    });
    const approval: ApprovalRequest = {
      id: "refund-approval-1",
      principal_id: principal.principal_id,
      tenant_id: principal.tenant_id,
      tool_name: "refund.create",
      request_hash: requestHash,
      risk_level: "medium",
      policy_codes: ["REFUND_REQUIRES_APPROVAL"],
      policy_version: POLICY_VERSION,
      approval_display: {
        kind: "refund_create",
        amount_minor: 1200,
      },
      status: "APPROVED",
      created_at: 1_000,
      expires_at: 1_600,
      decided_at: 1_010,
      decided_by: "operator-a",
      consumed_at: null,
    };
    let consumeCalls = 0;
    const approvals: ApprovalRepository = {
      create: async () => approval,
      findById: async () => approval,
      decide: async () => ({ kind: "conflict", approval }),
      consume: async () => {
        consumeCalls += 1;
        return { kind: "consumed", approval, audit_persisted: true };
      },
      list: async () => [],
    };
    const changedAmount: ActionRequest = {
      ...refundRequest,
      arguments_json:
        '{"amount_minor":1201,"target_tenant":"tenant-a"}',
    };

    const result = await consumeApprovedAction({
      approval_id: approval.id,
      request: changedAmount,
      principal,
      approvals,
      now: 1_100,
    });

    expect(result).toEqual({
      authorized: false,
      error: "APPROVAL_REQUEST_MISMATCH",
    });
    expect(consumeCalls).toBe(0);
  });
});
