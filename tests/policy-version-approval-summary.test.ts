import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import {
  buildApprovalDisplaySummary,
  type ApprovalDisplaySummary,
} from "../src/approvals/display-summary";
import { consumeApprovedAction } from "../src/approvals/workflow";
import type {
  ActionRequest,
  EvaluationResult,
  NormalizedToolCall,
} from "../src/contracts";
import type {
  ApprovalRepository,
  ApprovalRequest,
} from "../src/persistence/types";
import { POLICY_VERSION } from "../src/policy-metadata";
import {
  hashApprovalRequest,
  hashEvaluationRequest,
} from "../src/security/crypto";
import {
  CLAIM_IDEMPOTENCY_SQL,
  COMPLETE_IDEMPOTENCY_SQL,
} from "../src/security/d1-repositories";
import type { TrustedPrincipal } from "../src/security/types";

const databases: Database[] = [];

const principal: TrustedPrincipal = {
  principal_id: "principal-a",
  tenant_id: "tenant-a",
  key_id: "key-a",
  daily_ai_limit: 25,
};

const emailRequest: ActionRequest = {
  agent_role: "support-agent",
  tool_name: "email.send",
  arguments_json: JSON.stringify({
    to: "customer@example.com",
    subject: "Account update",
    body: "private body that must not be stored",
    attachment: "private-attachment-contents",
    target_tenant: "tenant-a",
  }),
  source_text: "Send the requested account update.",
  request_tenant: "tenant-a",
};

function emailNormalized(): NormalizedToolCall {
  return {
    agent_role: "support-agent",
    tool_name: "email.send",
    request_tenant: "tenant-a",
    target_tenant: "tenant-a",
    amount_minor: null,
    recipient: "customer@example.com",
    args: JSON.parse(emailRequest.arguments_json),
  };
}

async function migratedDatabase(): Promise<Database> {
  const database = new Database(":memory:", { strict: true });
  databases.push(database);
  database.exec(await Bun.file("migrations/0001_security.sql").text());
  database.exec(await Bun.file("migrations/0002_audit_approval.sql").text());
  database.exec(
    await Bun.file("migrations/0003_policy_version_approval_display.sql").text(),
  );
  return database;
}

function approvalFixture(input: {
  requestHash: string;
  policyVersion?: string;
  display?: ApprovalDisplaySummary;
}): ApprovalRequest {
  return {
    id: "approval-1",
    principal_id: principal.principal_id,
    tenant_id: principal.tenant_id,
    tool_name: "email.send",
    request_hash: input.requestHash,
    risk_level: "medium",
    policy_codes: ["OUTBOUND_SEND"],
    policy_version: input.policyVersion ?? POLICY_VERSION,
    approval_display:
      input.display ?? {
        kind: "email_send",
        recipient: "customer@example.com",
        has_attachments: true,
      },
    status: "APPROVED",
    created_at: 100,
    expires_at: 700,
    decided_at: 200,
    decided_by: "operator-a",
    consumed_at: null,
  };
}

function approvalRepository(
  approval: ApprovalRequest,
  onConsume: () => void,
): ApprovalRepository {
  return {
    create: async () => approval,
    findById: async () => approval,
    decide: async () => ({ kind: "conflict", approval }),
    consume: async (input) => {
      onConsume();
      if (input.request_hash !== approval.request_hash) {
        return { kind: "request_mismatch", approval };
      }
      return { kind: "consumed", approval, audit_persisted: true };
    },
    list: async () => [],
  };
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe("Step 7 immutable policy version", () => {
  test("migration retires unversioned actionable approvals as legacy evidence", async () => {
    const beforeMigration = Math.floor(Date.now() / 1_000);
    const database = new Database(":memory:", { strict: true });
    databases.push(database);
    database.exec(await Bun.file("migrations/0001_security.sql").text());
    database.exec(await Bun.file("migrations/0002_audit_approval.sql").text());
    database
      .query(
        `INSERT INTO approval_requests (
          id, principal_id, tenant_id, tool_name, request_hash, risk_level,
          policy_codes_json, status, created_at, expires_at, decided_at,
          decided_by, consumed_at
        ) VALUES (
          'legacy-approval', 'principal-a', 'tenant-a', 'email.send', ?,
          'medium', '["OUTBOUND_SEND"]', 'PENDING', 100, 4000000000,
          NULL, NULL, NULL
        )`,
      )
      .run("0".repeat(64));

    database.exec(
      await Bun.file("migrations/0003_policy_version_approval_display.sql").text(),
    );

    expect(
      database
        .query<
          {
            status: string;
            policy_version: string;
            approval_display_json: string;
          },
          []
        >(
          `SELECT status, policy_version, approval_display_json
           FROM approval_requests WHERE id = 'legacy-approval'`,
        )
        .get(),
    ).toEqual({
      status: "EXPIRED",
      policy_version: "aag-policy-legacy",
      approval_display_json: '{"kind":"generic"}',
    });
    expect(
      database
        .query<{ event_type: string; policy_version: string; created_at: number }, []>(
          `SELECT event_type, policy_version, created_at FROM audit_events
           WHERE approval_id = 'legacy-approval'`,
        )
        .get(),
    ).toMatchObject({
      event_type: "EXPIRED",
      policy_version: "aag-policy-legacy",
    });
    const legacyExpiryEvent = database
      .query<{ created_at: number }, []>(
        `SELECT created_at FROM audit_events
         WHERE approval_id = 'legacy-approval'`,
      )
      .get();
    expect(legacyExpiryEvent).not.toBeNull();
    expect(legacyExpiryEvent!.created_at).toBeGreaterThanOrEqual(beforeMigration);
    expect(legacyExpiryEvent!.created_at).toBeLessThanOrEqual(
      Math.floor(Date.now() / 1_000),
    );
    expect(legacyExpiryEvent!.created_at).toBeLessThan(4_000_000_000);
  });

  test("changes evaluation and approval request bindings", async () => {
    const evaluationInput = {
      agent_role: "support-agent",
      tool_name: "email.send",
      arguments_json: emailRequest.arguments_json,
      source_text: emailRequest.source_text,
      request_tenant: "tenant-a",
    };
    const policy: Pick<
      EvaluationResult,
      "decision" | "risk_level" | "policy_codes" | "requires_approval"
    > = {
      decision: "REQUIRE_APPROVAL",
      risk_level: "medium",
      policy_codes: ["OUTBOUND_SEND"],
      requires_approval: true,
    };

    expect(
      await hashEvaluationRequest(
        evaluationInput,
        "tenant-a",
        "aag-policy-v1",
      ),
    ).not.toBe(
      await hashEvaluationRequest(
        evaluationInput,
        "tenant-a",
        "aag-policy-v2",
      ),
    );
    expect(
      await hashApprovalRequest({
        principal_id: principal.principal_id,
        trusted_tenant_id: principal.tenant_id,
        normalized: emailNormalized(),
        source_text: emailRequest.source_text,
        policy,
        policy_version: "aag-policy-v1",
      }),
    ).not.toBe(
      await hashApprovalRequest({
        principal_id: principal.principal_id,
        trusted_tenant_id: principal.tenant_id,
        normalized: emailNormalized(),
        source_text: emailRequest.source_text,
        policy,
        policy_version: "aag-policy-v2",
      }),
    );
  });

  test("does not consume an approval created by an incompatible policy", async () => {
    const oldHash = await hashApprovalRequest({
      principal_id: principal.principal_id,
      trusted_tenant_id: principal.tenant_id,
      normalized: emailNormalized(),
      source_text: emailRequest.source_text,
      policy: {
        decision: "REQUIRE_APPROVAL",
        risk_level: "medium",
        policy_codes: ["OUTBOUND_SEND"],
        requires_approval: true,
      },
      policy_version: "aag-policy-v0",
    });
    const stale = approvalFixture({
      requestHash: oldHash,
      policyVersion: "aag-policy-v0",
    });
    let consumeCalls = 0;

    const result = await consumeApprovedAction({
      approval_id: stale.id,
      request: emailRequest,
      principal,
      approvals: approvalRepository(stale, () => {
        consumeCalls += 1;
      }),
      now: 300,
    });

    expect(result).toEqual({
      authorized: false,
      error: "APPROVAL_REQUEST_MISMATCH",
    });
    expect(consumeCalls).toBe(0);
  });

  test("does not let one idempotency record cross policy versions", async () => {
    const database = await migratedDatabase();
    const keyHash = "1".repeat(64);
    const v1Hash = "2".repeat(64);
    const v2Hash = "3".repeat(64);

    database
      .query(CLAIM_IDEMPOTENCY_SQL)
      .get(
        "principal-a",
        keyHash,
        v1Hash,
        "aag-policy-v1",
        "owner-token-0000000000000001",
        100,
        1_000,
        200,
      );
    database
      .query(COMPLETE_IDEMPOTENCY_SQL)
      .get(
        "principal-a",
        keyHash,
        v1Hash,
        "owner-token-0000000000000001",
        '{"decision":"ALLOW"}',
        110,
        "aag-policy-v1",
      );

    expect(
      database
        .query(CLAIM_IDEMPOTENCY_SQL)
        .get(
          "principal-a",
          keyHash,
          v2Hash,
          "aag-policy-v2",
          "owner-token-0000000000000002",
          120,
          1_020,
          220,
        ),
    ).toBeNull();
    expect(
      database
        .query<{ policy_version: string }, []>(
          "SELECT policy_version FROM idempotency_records",
        )
        .get(),
    ).toEqual({ policy_version: "aag-policy-v1" });
  });
});

describe("Step 7 allowlisted approval display", () => {
  test("keeps only safe email fields and a boolean attachment indicator", () => {
    const summary = buildApprovalDisplaySummary(emailNormalized());
    const serialized = JSON.stringify(summary);

    expect(summary).toEqual({
      kind: "email_send",
      recipient: "customer@example.com",
      subject: "Account update",
      has_attachments: true,
    });
    expect(serialized).not.toContain("private body");
    expect(serialized).not.toContain("private-attachment-contents");
    expect(serialized).not.toContain("target_tenant");

    const missingRecipient = buildApprovalDisplaySummary({
      ...emailNormalized(),
      recipient: "",
      args: { target_tenant: "tenant-a" },
    });
    expect(missingRecipient).toEqual({
      kind: "email_send",
      recipient: "",
      has_attachments: false,
    });
  });

  test("keeps only safe refund fields and uses a generic summary otherwise", () => {
    const refund = buildApprovalDisplaySummary({
      agent_role: "support-agent",
      tool_name: "refund.create",
      request_tenant: "tenant-a",
      target_tenant: "tenant-a",
      amount_minor: 8_500,
      recipient: "",
      args: {
        amount_minor: 8_500,
        currency: "aud",
        order_id: "order-42",
        card_number: "4111111111111111",
        target_tenant: "tenant-a",
      },
    });
    const generic = buildApprovalDisplaySummary({
      agent_role: "support-agent",
      tool_name: "future.tool",
      request_tenant: "tenant-a",
      target_tenant: "tenant-a",
      amount_minor: null,
      recipient: "",
      args: { arbitrary_secret: "must-not-leak" },
    });

    expect(refund).toEqual({
      kind: "refund_create",
      amount_minor: 8_500,
      currency: "AUD",
      order_id: "order-42",
    });
    expect(JSON.stringify(refund)).not.toContain("4111111111111111");
    expect(generic).toEqual({ kind: "generic" });
  });

  test("never uses presentation metadata as consumption authority", async () => {
    const requestHash = await hashApprovalRequest({
      principal_id: principal.principal_id,
      trusted_tenant_id: principal.tenant_id,
      normalized: emailNormalized(),
      source_text: emailRequest.source_text,
      policy: {
        decision: "REQUIRE_APPROVAL",
        risk_level: "medium",
        policy_codes: ["OUTBOUND_SEND"],
        requires_approval: true,
      },
    });
    const approval = approvalFixture({
      requestHash,
      display: {
        kind: "email_send",
        recipient: "display-only@example.com",
        has_attachments: false,
      },
    });
    let consumeCalls = 0;

    const result = await consumeApprovedAction({
      approval_id: approval.id,
      request: emailRequest,
      principal,
      approvals: approvalRepository(approval, () => {
        consumeCalls += 1;
      }),
      now: 300,
    });

    expect(result.authorized).toBe(true);
    expect(consumeCalls).toBe(1);
  });

  test("migration rejects extra display fields and makes valid summaries immutable", async () => {
    const database = await migratedDatabase();
    const insert = database.query(
      `INSERT INTO approval_requests (
        id, principal_id, tenant_id, tool_name, request_hash, risk_level,
        policy_codes_json, policy_version, approval_display_json, status,
        created_at, expires_at, decided_at, decided_by, consumed_at
      ) VALUES (
        ?, 'principal-a', 'tenant-a', 'email.send', ?, 'medium',
        '["OUTBOUND_SEND"]', ?, ?, 'PENDING', 100, 700, NULL, NULL, NULL
      )`,
    );

    expect(() =>
      insert.run(
        "approval-unsafe",
        "4".repeat(64),
        POLICY_VERSION,
        JSON.stringify({
          kind: "email_send",
          recipient: "customer@example.com",
          has_attachments: false,
          body: "must-not-be-stored",
        }),
      ),
    ).toThrow("invalid approval display summary");
    expect(() =>
      insert.run(
        "approval-null-kind",
        "9".repeat(64),
        POLICY_VERSION,
        JSON.stringify({
          kind: null,
          recipient: "customer@example.com",
          has_attachments: false,
        }),
      ),
    ).toThrow("invalid approval display summary");
    expect(() =>
      insert.run(
        "approval-untrimmed",
        "6".repeat(64),
        POLICY_VERSION,
        JSON.stringify({
          kind: "email_send",
          recipient: " customer@example.com ",
          has_attachments: false,
        }),
      ),
    ).toThrow("invalid approval display summary");
    expect(() =>
      insert.run(
        "approval-format-control",
        "a".repeat(64),
        POLICY_VERSION,
        JSON.stringify({
          kind: "email_send",
          recipient: "customer@example.com",
          subject: "Invoice\u202Efdp.exe",
          has_attachments: false,
        }),
      ),
    ).toThrow("invalid approval display summary");
    expect(() =>
      insert.run(
        "approval-control-character",
        "7".repeat(64),
        POLICY_VERSION,
        JSON.stringify({
          kind: "email_send",
          recipient: "customer@example.com",
          subject: "misleading\nsecond line",
          has_attachments: false,
        }),
      ),
    ).toThrow("invalid approval display summary");

    expect(() =>
      database
        .query(
          `INSERT INTO approval_requests (
            id, principal_id, tenant_id, tool_name, request_hash, risk_level,
            policy_codes_json, policy_version, approval_display_json, status,
            created_at, expires_at, decided_at, decided_by, consumed_at
          ) VALUES (
            'refund-untrimmed', 'principal-a', 'tenant-a', 'refund.create', ?,
            'medium', '["REFUND_REQUIRES_APPROVAL"]', ?, ?, 'PENDING',
            100, 700, NULL, NULL, NULL
          )`,
        )
        .run(
          "8".repeat(64),
          POLICY_VERSION,
          JSON.stringify({
            kind: "refund_create",
            amount_minor: 8_500,
            order_id: " order-42 ",
          }),
        ),
    ).toThrow("invalid approval display summary");

    insert.run(
      "approval-safe",
      "5".repeat(64),
      POLICY_VERSION,
      JSON.stringify({
        kind: "email_send",
        recipient: "customer@example.com",
        has_attachments: false,
      }),
    );
    expect(() =>
      database
        .query(
          `UPDATE approval_requests
           SET approval_display_json = ?
           WHERE id = 'approval-safe'`,
        )
        .run(
          '{"kind":"email_send","recipient":"other@example.com","has_attachments":false}',
        ),
    ).toThrow("approval request binding is immutable");
    expect(() =>
      database
        .query(
          `UPDATE approval_requests
           SET policy_version = 'aag-policy-v2'
           WHERE id = 'approval-safe'`,
        )
        .run(),
    ).toThrow("approval request binding is immutable");

    database
      .query(
        `UPDATE approval_requests
         SET status = 'APPROVED', decided_at = 200, decided_by = 'operator-a'
         WHERE id = 'approval-safe'`,
      )
      .run();
    expect(
      database
        .query<{ policy_version: string }, []>(
          "SELECT policy_version FROM audit_events WHERE approval_id = 'approval-safe'",
        )
        .get(),
    ).toEqual({ policy_version: POLICY_VERSION });
  });
});
