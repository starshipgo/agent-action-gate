import { describe, expect, test } from "bun:test";
import type { SemanticClassifier } from "../src/classifiers/types";
import type {
  ActionRequest,
  EvaluationResult,
  RawRiskSignals,
  SemanticRiskContext,
} from "../src/contracts";
import type {
  ApprovalConsumeInput,
  ApprovalConsumeResult,
  ApprovalDecisionInput,
  ApprovalDecisionResult,
  ApprovalQuery,
  ApprovalRepository,
  ApprovalRequest,
  AuditEvent,
  AuditQuery,
  AuditRepository,
  EvaluationPersistenceInput,
  EvaluationPersistenceRepository,
  NewApprovalRequest,
} from "../src/persistence/types";
import { sha256Hex } from "../src/security/crypto";
import { POLICY_VERSION } from "../src/policy-metadata";
import type {
  AiQuotaRepository,
  AiQuotaResult,
  ApiKeyRecord,
  BurstRateLimiter,
  IdempotencyClaimInput,
  IdempotencyClaimResult,
  IdempotencyCompletionInput,
  IdempotencyRepository,
  PrincipalRepository,
  SecurityRepositories,
  StoredEvaluationResult,
  TrustedPrincipal,
} from "../src/security/types";
import { createWorker } from "../src/worker";

const AGENT_TOKEN = ["aag", "test", "step6_primary_agent_token_123456789"].join("_");
const OTHER_PRINCIPAL_TOKEN =
  ["aag", "test", "step6_other_principal_token_123456789"].join("_");
const OTHER_TENANT_TOKEN =
  ["aag", "test", "step6_other_tenant_token_123456789"].join("_");
const OPERATOR_TOKEN = "step6-preview-operator-secret";
const START_SECONDS = Math.floor(
  Date.parse("2026-09-30T02:03:04.000Z") / 1_000,
);

const primaryPrincipal: ApiKeyRecord = {
  principal_id: "principal-a",
  tenant_id: "tenant-a",
  key_id: "key-a",
  daily_ai_limit: 1_000,
  status: "active",
};

const safeRisk: RawRiskSignals = {
  prompt_injection: false,
  data_exfiltration: false,
  social_engineering: false,
  suspicious_instruction: false,
  confidence: "low",
  reason: "Deterministic Step 6 test fixture.",
};

type JsonRecord = Record<string, unknown>;

function cloneApproval(approval: ApprovalRequest): ApprovalRequest {
  return { ...approval, policy_codes: [...approval.policy_codes] };
}

function cloneAudit(event: AuditEvent): AuditEvent {
  return { ...event, policy_codes: [...event.policy_codes] };
}

class FakeClassifier implements SemanticClassifier {
  calls = 0;
  contexts: SemanticRiskContext[] = [];
  throwIfCalled = false;

  async classify(context: SemanticRiskContext): Promise<RawRiskSignals> {
    this.calls += 1;
    this.contexts.push(context);
    if (this.throwIfCalled) {
      throw new Error("classifier must not run during approval consumption");
    }
    return safeRisk;
  }
}

class FakePrincipalRepository implements PrincipalRepository {
  readonly records = new Map<string, ApiKeyRecord>([
    [AGENT_TOKEN, primaryPrincipal],
    [
      OTHER_PRINCIPAL_TOKEN,
      {
        ...primaryPrincipal,
        principal_id: "principal-b",
        key_id: "key-b",
      },
    ],
    [
      OTHER_TENANT_TOKEN,
      {
        ...primaryPrincipal,
        tenant_id: "tenant-b",
        key_id: "key-tenant-b",
      },
    ],
  ]);

  async findByKeyHash(keyHash: string): Promise<ApiKeyRecord | null> {
    for (const [token, record] of this.records) {
      if ((await sha256Hex(token)) === keyHash) {
        return { ...record };
      }
    }
    return null;
  }
}

class FakeQuotaRepository implements AiQuotaRepository {
  calls = 0;
  throwIfCalled = false;

  async tryConsume(
    principal: TrustedPrincipal,
    _dayUtc: string,
    _nowUnixSeconds: number,
  ): Promise<AiQuotaResult> {
    this.calls += 1;
    if (this.throwIfCalled) {
      throw new Error("quota must not run during approval consumption");
    }
    return { allowed: true, used: this.calls, limit: principal.daily_ai_limit };
  }
}

class FakeIdempotencyRepository implements IdempotencyRepository {
  private readonly records = new Map<
    string,
    {
      requestHash: string;
      ownerToken: string;
      response?: StoredEvaluationResult;
    }
  >();

  async claim(input: IdempotencyClaimInput): Promise<IdempotencyClaimResult> {
    const key = `${input.principal_id}:${input.idempotency_key_hash}`;
    const existing = this.records.get(key);
    if (existing !== undefined) {
      if (existing.requestHash !== input.request_hash) {
        return { kind: "conflict" };
      }
      return existing.response === undefined
        ? { kind: "in_progress" }
        : { kind: "replay", response: existing.response };
    }
    this.records.set(key, {
      requestHash: input.request_hash,
      ownerToken: input.owner_token,
    });
    return { kind: "acquired", owner_token: input.owner_token };
  }

  async complete(input: IdempotencyCompletionInput): Promise<boolean> {
    const key = `${input.principal_id}:${input.idempotency_key_hash}`;
    const existing = this.records.get(key);
    if (
      existing === undefined ||
      existing.requestHash !== input.request_hash ||
      existing.ownerToken !== input.owner_token
    ) {
      return false;
    }
    const {
      normalized_tool: _normalizedTool,
      normalized_args: _normalizedArgs,
      ...stored
    } = input.response;
    existing.response = stored;
    return true;
  }

  async abandon(input: {
    principal_id: string;
    idempotency_key_hash: string;
    request_hash: string;
    owner_token: string;
  }): Promise<void> {
    const key = `${input.principal_id}:${input.idempotency_key_hash}`;
    const existing = this.records.get(key);
    if (
      existing?.requestHash === input.request_hash &&
      existing.ownerToken === input.owner_token
    ) {
      this.records.delete(key);
    }
  }
}

class FakeRateLimiter implements BurstRateLimiter {
  calls: string[] = [];

  async allow(principalId: string): Promise<boolean> {
    this.calls.push(principalId);
    return true;
  }
}

class FakeAuditRepository implements AuditRepository {
  readonly events: AuditEvent[] = [];
  failAppend = false;

  async append(event: AuditEvent): Promise<void> {
    if (this.failAppend) {
      throw new Error("simulated append-only audit outage");
    }
    this.events.push(cloneAudit(event));
  }

  async list(query: AuditQuery): Promise<AuditEvent[]> {
    const filtered = this.events.filter(
      (event) =>
        (query.tenant_id === undefined ||
          event.tenant_id === query.tenant_id) &&
        (query.decision === undefined || event.decision === query.decision) &&
        (query.tool_name === undefined ||
          event.tool_name === query.tool_name),
    );
    return filtered.slice(0, query.limit ?? 100).map(cloneAudit);
  }
}

class FakeApprovalRepository implements ApprovalRepository {
  readonly records = new Map<string, ApprovalRequest>();
  consumeCalls = 0;
  /** Lets focused endpoint tests model a nonconforming repository adapter. */
  decisionAuditPersisted = true;
  consumeAuditPersisted = true;

  async create(input: NewApprovalRequest): Promise<ApprovalRequest> {
    const approval: ApprovalRequest = {
      ...input,
      policy_codes: [...input.policy_codes],
      status: "PENDING",
      decided_at: null,
      decided_by: null,
      consumed_at: null,
    };
    this.records.set(approval.id, approval);
    return cloneApproval(approval);
  }

  async findById(id: string, now: number): Promise<ApprovalRequest | null> {
    const approval = this.records.get(id);
    if (approval === undefined) {
      return null;
    }
    this.expireIfDue(approval, now);
    return cloneApproval(approval);
  }

  async decide(input: ApprovalDecisionInput): Promise<ApprovalDecisionResult> {
    const approval = this.records.get(input.id);
    if (approval === undefined) {
      return { kind: "not_found" };
    }

    this.expireIfDue(approval, input.now);
    if (approval.status === "EXPIRED") {
      return { kind: "expired", approval: cloneApproval(approval) };
    }
    if (approval.status !== "PENDING") {
      return { kind: "conflict", approval: cloneApproval(approval) };
    }

    approval.status = input.decision;
    approval.decided_at = input.now;
    approval.decided_by = input.decided_by;
    if (!this.decisionAuditPersisted) {
      // Deliberately model a broken injected adapter at the runtime boundary.
      return {
        kind: "decided",
        approval: cloneApproval(approval),
      } as unknown as ApprovalDecisionResult;
    }
    return {
      kind: "decided",
      approval: cloneApproval(approval),
      audit_persisted: true,
    };
  }

  async consume(input: ApprovalConsumeInput): Promise<ApprovalConsumeResult> {
    this.consumeCalls += 1;
    const approval = this.records.get(input.id);
    if (approval === undefined) {
      return { kind: "not_found" };
    }

    this.expireIfDue(approval, input.now);
    if (
      approval.principal_id !== input.principal_id ||
      approval.tenant_id !== input.tenant_id
    ) {
      return { kind: "ownership_mismatch" };
    }
    if (approval.status === "PENDING") {
      return { kind: "pending", approval: cloneApproval(approval) };
    }
    if (approval.status === "REJECTED") {
      return { kind: "rejected", approval: cloneApproval(approval) };
    }
    if (approval.status === "EXPIRED") {
      return { kind: "expired", approval: cloneApproval(approval) };
    }
    if (approval.status === "CONSUMED") {
      return { kind: "already_consumed", approval: cloneApproval(approval) };
    }
    if (approval.request_hash !== input.request_hash) {
      return { kind: "request_mismatch", approval: cloneApproval(approval) };
    }

    // No await occurs between the state check and mutation: concurrent callers
    // observe exactly one APPROVED -> CONSUMED transition in this fake.
    approval.status = "CONSUMED";
    approval.consumed_at = input.now;
    if (!this.consumeAuditPersisted) {
      // Deliberately model a broken injected adapter at the runtime boundary.
      return {
        kind: "consumed",
        approval: cloneApproval(approval),
      } as unknown as ApprovalConsumeResult;
    }
    return {
      kind: "consumed",
      approval: cloneApproval(approval),
      audit_persisted: true,
    };
  }

  async list(query: ApprovalQuery): Promise<ApprovalRequest[]> {
    for (const approval of this.records.values()) {
      this.expireIfDue(approval, query.now);
    }
    return [...this.records.values()]
      .filter(
        (approval) =>
          (query.status === undefined || approval.status === query.status) &&
          (query.tenant_id === undefined ||
            approval.tenant_id === query.tenant_id),
      )
      .slice(0, query.limit ?? 100)
      .map(cloneApproval);
  }

  private expireIfDue(approval: ApprovalRequest, now: number): void {
    if (
      now >= approval.expires_at &&
      (approval.status === "PENDING" || approval.status === "APPROVED")
    ) {
      approval.status = "EXPIRED";
    }
  }
}

class FakeEvaluationPersistenceRepository
  implements EvaluationPersistenceRepository
{
  readonly calls: EvaluationPersistenceInput[] = [];

  constructor(
    private readonly audit: FakeAuditRepository,
    private readonly approvals: FakeApprovalRepository,
    private readonly idempotency: FakeIdempotencyRepository,
  ) {}

  async persist(
    input: EvaluationPersistenceInput,
  ): Promise<{ approval: ApprovalRequest | null }> {
    this.calls.push(input);

    // Stage the audit first. A failed required audit append creates neither a
    // response authorization nor an approval in this deterministic fake.
    await this.audit.append(input.event);
    const approval =
      input.approval === null
        ? null
        : await this.approvals.create(input.approval);
    if (input.idempotency !== undefined && input.idempotency !== null) {
      if (!(await this.idempotency.complete(input.idempotency))) {
        throw new Error("simulated idempotency completion failure");
      }
    }
    return { approval };
  }
}

interface Harness {
  worker: ReturnType<typeof createWorker>;
  env: Env;
  classifier: FakeClassifier;
  principals: FakePrincipalRepository;
  quota: FakeQuotaRepository;
  rateLimiter: FakeRateLimiter;
  audit: FakeAuditRepository;
  approvals: FakeApprovalRepository;
  evaluations: FakeEvaluationPersistenceRepository;
  setNow(seconds: number): void;
  advance(seconds: number): void;
}

function createHarness(): Harness {
  let now = START_SECONDS;
  const classifier = new FakeClassifier();
  const principals = new FakePrincipalRepository();
  const quota = new FakeQuotaRepository();
  const idempotency = new FakeIdempotencyRepository();
  const rateLimiter = new FakeRateLimiter();
  const audit = new FakeAuditRepository();
  const approvals = new FakeApprovalRepository();
  const evaluations = new FakeEvaluationPersistenceRepository(
    audit,
    approvals,
    idempotency,
  );
  const repositories: SecurityRepositories = {
    principals,
    quota,
    idempotency,
    audit,
    approvals,
    evaluations,
  };
  const sequences: Record<"approval" | "audit" | "request", number> = {
    approval: 0,
    audit: 0,
    request: 0,
  };

  const worker = createWorker({
    createClassifier: () => classifier,
    createSecurityRepositories: () => repositories,
    createRateLimiter: () => rateLimiter,
    now: () => new Date(now * 1_000),
    createOwnerToken: () => "step6-owner-token",
    createRecordId: (kind) => `${kind}-${++sequences[kind]}`,
    getOperatorSecret: () => OPERATOR_TOKEN,
    getOperatorIdentity: () => "preview-operator",
  });

  return {
    worker,
    env: {} as Env,
    classifier,
    principals,
    quota,
    rateLimiter,
    audit,
    approvals,
    evaluations,
    setNow(seconds: number) {
      now = seconds;
    },
    advance(seconds: number) {
      now += seconds;
    },
  };
}

function actionBody(
  toolName: string,
  args: JsonRecord,
  sourceText = "Perform the requested action.",
  requestTenant: string | undefined = "tenant-a",
): JsonRecord {
  return {
    agent_role: "support_agent",
    tool_name: toolName,
    arguments_json: JSON.stringify(args),
    source_text: sourceText,
    ...(requestTenant === undefined
      ? {}
      : { request_tenant: requestTenant }),
  };
}

function request(
  path: string,
  options: {
    method?: string;
    token?: string | null;
    body?: JsonRecord;
    idempotencyKey?: string;
  } = {},
): Request {
  const headers = new Headers();
  if (options.token !== null) {
    headers.set(
      "authorization",
      `Bearer ${options.token ?? AGENT_TOKEN}`,
    );
  }
  if (options.body !== undefined) {
    headers.set("content-type", "application/json");
  }
  if (options.idempotencyKey !== undefined) {
    headers.set("idempotency-key", options.idempotencyKey);
  }

  return new Request(`https://gate.example${path}`, {
    method: options.method ?? (options.body === undefined ? "GET" : "POST"),
    headers,
    ...(options.body === undefined
      ? {}
      : { body: JSON.stringify(options.body) }),
  });
}

async function json(response: Response): Promise<JsonRecord> {
  return (await response.json()) as JsonRecord;
}

async function evaluate(
  state: Harness,
  body: JsonRecord,
): Promise<{ response: Response; body: JsonRecord }> {
  const response = await state.worker.fetch(
    request("/v1/evaluate", { method: "POST", body }),
    state.env,
  );
  return { response, body: await json(response) };
}

async function createPendingEmailApproval(
  state: Harness,
  overrides: Partial<ActionRequest> = {},
): Promise<{ approvalId: string; body: JsonRecord; output: JsonRecord }> {
  const base = actionBody(
    "email.send",
    {
      to: "customer@example.com",
      attachment: "account-summary.pdf",
      target_tenant: "tenant-a",
    },
    "Send the requested account summary.",
  );
  const body = { ...base, ...overrides };
  const evaluation = await evaluate(state, body);

  expect(evaluation.response.status).toBe(200);
  expect(evaluation.body.decision).toBe("REQUIRE_APPROVAL");
  expect(typeof evaluation.body.approval_id).toBe("string");
  return {
    approvalId: evaluation.body.approval_id as string,
    body,
    output: evaluation.body,
  };
}

async function operatorDecision(
  state: Harness,
  approvalId: string,
  decision: "approve" | "reject",
  token: string | null = OPERATOR_TOKEN,
): Promise<Response> {
  return state.worker.fetch(
    request(`/v1/approvals/${approvalId}/${decision}`, {
      method: "POST",
      token,
    }),
    state.env,
  );
}

async function consume(
  state: Harness,
  approvalId: string,
  body: JsonRecord,
  token = AGENT_TOKEN,
): Promise<Response> {
  return state.worker.fetch(
    request(`/v1/approvals/${approvalId}/consume`, {
      method: "POST",
      token,
      body,
    }),
    state.env,
  );
}

describe("Step 6 Worker decision auditing", () => {
  test("persists ALLOW, DENY, and REQUIRE_APPROVAL decisions as hashed, secret-free events", async () => {
    const cases: Array<{
      tool: string;
      args: JsonRecord;
      decision: EvaluationResult["decision"];
    }> = [
      {
        tool: "crm.read_contact",
        args: {
          contact_id: "private-contact-allow",
          target_tenant: "tenant-a",
        },
        decision: "ALLOW",
      },
      {
        tool: "secret.read",
        args: {
          secret_name: "private-secret-deny",
          target_tenant: "tenant-a",
        },
        decision: "DENY",
      },
      {
        tool: "email.send",
        args: {
          to: "private-recipient@example.com",
          target_tenant: "tenant-a",
        },
        decision: "REQUIRE_APPROVAL",
      },
    ];

    for (const fixture of cases) {
      const state = createHarness();
      const sourceText = `raw-source-${fixture.decision}-must-not-persist`;
      const argumentsJson = JSON.stringify(fixture.args);
      const result = await evaluate(
        state,
        actionBody(fixture.tool, fixture.args, sourceText),
      );

      expect(result.response.status).toBe(200);
      expect(result.body.decision).toBe(fixture.decision);
      expect(state.audit.events).toHaveLength(1);
      const event = state.audit.events[0]!;
      expect(event).toMatchObject({
        principal_id: "principal-a",
        key_id: "key-a",
        tenant_id: "tenant-a",
        tool_name: fixture.tool,
        event_type: "EVALUATED",
        decision: fixture.decision,
      });
      expect(event.arguments_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(event.source_text_hash).toBe(await sha256Hex(sourceText));

      const persisted = JSON.stringify(state.evaluations.calls);
      expect(persisted).not.toContain(AGENT_TOKEN);
      expect(persisted).not.toContain(OPERATOR_TOKEN);
      expect(persisted).not.toContain(sourceText);
      expect(persisted).not.toContain(argumentsJson);
      for (const value of Object.values(fixture.args)) {
        const isAllowlistedEmailRecipient =
          fixture.tool === "email.send" && value === fixture.args.to;
        if (
          typeof value === "string" &&
          value !== "tenant-a" &&
          !isAllowlistedEmailRecipient
        ) {
          expect(persisted).not.toContain(value);
        }
      }
    }
  });

  test("fails closed when the required audit append is unavailable", async () => {
    const state = createHarness();
    state.audit.failAppend = true;
    const response = await state.worker.fetch(
      request("/v1/evaluate", {
        method: "POST",
        body: actionBody("email.send", {
          to: "customer@example.com",
          target_tenant: "tenant-a",
        }),
      }),
      state.env,
    );

    expect(response.status).toBe(503);
    expect(await json(response)).toEqual({
      error: "AUDIT_PERSISTENCE_UNAVAILABLE",
    });
    expect(state.audit.events).toHaveLength(0);
    expect(state.approvals.records.size).toBe(0);
  });

  test("creates approval records only for REQUIRE_APPROVAL", async () => {
    const state = createHarness();
    const allow = await evaluate(
      state,
      actionBody("crm.read_contact", {
        contact_id: "contact-1",
        target_tenant: "tenant-a",
      }),
    );
    const deny = await evaluate(
      state,
      actionBody("customer.export", { target_tenant: "tenant-a" }),
    );
    const approval = await evaluate(
      state,
      actionBody("refund.create", {
        amount_minor: 8_500,
        target_tenant: "tenant-a",
      }),
    );

    expect(allow.body).not.toHaveProperty("approval_id");
    expect(deny.body).not.toHaveProperty("approval_id");
    expect(approval.body).toMatchObject({
      decision: "REQUIRE_APPROVAL",
      policy_codes: ["REFUND_REQUIRES_APPROVAL"],
      requires_approval: true,
      approval_id: "approval-1",
      expires_at: new Date((START_SECONDS + 600) * 1_000).toISOString(),
    });
    expect(state.approvals.records.size).toBe(1);
  });

  test("replays one persisted REQUIRE_APPROVAL result for an idempotent retry", async () => {
    const state = createHarness();
    const body = actionBody("email.send", {
      to: "customer@example.com",
      target_tenant: "tenant-a",
    });
    const idempotencyKey = "step6-email-approval-retry";

    const first = await state.worker.fetch(
      request("/v1/evaluate", {
        method: "POST",
        body,
        idempotencyKey,
      }),
      state.env,
    );
    const firstBody = await json(first);
    const second = await state.worker.fetch(
      request("/v1/evaluate", {
        method: "POST",
        body,
        idempotencyKey,
      }),
      state.env,
    );
    const secondBody = await json(second);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(firstBody).toEqual(secondBody);
    expect(firstBody.approval_id).toBe("approval-1");
    expect(state.audit.events).toHaveLength(1);
    expect(state.approvals.records.size).toBe(1);
    expect(state.classifier.calls).toBe(1);
    expect(state.quota.calls).toBe(1);
  });
});

describe("Step 6 Worker operator authority", () => {
  test("rejects the operator credential from Agent evaluation and consumption", async () => {
    const state = createHarness();
    const evaluation = await state.worker.fetch(
      request("/v1/evaluate", {
        method: "POST",
        token: OPERATOR_TOKEN,
        body: actionBody("crm.read_contact", {
          contact_id: "contact-operator-must-not-read",
          target_tenant: "tenant-a",
        }),
      }),
      state.env,
    );

    expect(evaluation.status).toBe(401);
    expect(await json(evaluation)).toEqual({ error: "UNAUTHORIZED" });

    const pending = await createPendingEmailApproval(state);
    expect(
      (await operatorDecision(state, pending.approvalId, "approve")).status,
    ).toBe(200);

    const consumption = await consume(
      state,
      pending.approvalId,
      pending.body,
      OPERATOR_TOKEN,
    );
    expect(consumption.status).toBe(401);
    expect(await json(consumption)).toEqual({ error: "UNAUTHORIZED" });
    expect(state.approvals.records.get(pending.approvalId)?.status).toBe(
      "APPROVED",
    );
  });

  test("rejects a normal Agent key and missing or invalid operator credentials", async () => {
    const state = createHarness();
    const { approvalId } = await createPendingEmailApproval(state);
    const attempts = [
      operatorDecision(state, approvalId, "approve", AGENT_TOKEN),
      operatorDecision(state, approvalId, "approve", null),
      operatorDecision(state, approvalId, "approve", "wrong-operator-secret"),
    ];

    for (const response of await Promise.all(attempts)) {
      expect(response.status).toBe(401);
      expect(await json(response)).toEqual({ error: "UNAUTHORIZED" });
    }
    expect(state.approvals.records.get(approvalId)?.status).toBe("PENDING");
  });

  test("allows the operator to approve or reject and records its non-secret identity", async () => {
    const state = createHarness();
    const first = await createPendingEmailApproval(state);
    const second = await createPendingEmailApproval(state, {
      source_text: "Send the second account summary.",
    });

    const approvedResponse = await operatorDecision(
      state,
      first.approvalId,
      "approve",
    );
    const rejectedResponse = await operatorDecision(
      state,
      second.approvalId,
      "reject",
    );

    expect(approvedResponse.status).toBe(200);
    const approvedBody = await json(approvedResponse);
    expect(approvedBody).toMatchObject({
      approval: {
        approval_id: first.approvalId,
        status: "APPROVED",
        decided_at: START_SECONDS,
      },
    });
    expect(rejectedResponse.status).toBe(200);
    expect(await json(rejectedResponse)).toMatchObject({
      approval: {
        approval_id: second.approvalId,
        status: "REJECTED",
        decided_at: START_SECONDS,
      },
    });
    expect(state.approvals.records.get(first.approvalId)?.decided_by).toBe(
      "preview-operator",
    );
    expect(state.approvals.records.get(second.approvalId)?.decided_by).toBe(
      "preview-operator",
    );
    expect(JSON.stringify(approvedBody)).not.toContain(OPERATOR_TOKEN);
  });

  test("fails closed when an injected repository cannot confirm the decision audit", async () => {
    const state = createHarness();
    const { approvalId } = await createPendingEmailApproval(state);
    state.approvals.decisionAuditPersisted = false;

    const response = await operatorDecision(state, approvalId, "approve");

    expect(response.status).toBe(503);
    expect(await json(response)).toEqual({
      error: "APPROVAL_DECISION_UNAVAILABLE",
    });
  });

  test("expires at the exact ten-minute boundary", async () => {
    const state = createHarness();
    const { approvalId, output } = await createPendingEmailApproval(state);

    expect(output.expires_at).toBe(
      new Date((START_SECONDS + 600) * 1_000).toISOString(),
    );
    state.advance(599);
    expect(state.approvals.records.get(approvalId)?.status).toBe("PENDING");
    state.advance(1);

    const response = await operatorDecision(state, approvalId, "approve");
    expect(response.status).toBe(410);
    expect(await json(response)).toEqual({ error: "APPROVAL_EXPIRED" });
    expect(state.approvals.records.get(approvalId)?.status).toBe("EXPIRED");
  });
});

describe("Step 6 Worker approval binding and consumption", () => {
  test("binds approvals to the authenticated principal and trusted tenant", async () => {
    const state = createHarness();
    const pending = await createPendingEmailApproval(state);
    expect((await operatorDecision(state, pending.approvalId, "approve")).status).toBe(
      200,
    );
    const bodyWithoutCompatibilityTenant = { ...pending.body };
    delete bodyWithoutCompatibilityTenant.request_tenant;

    const otherPrincipal = await consume(
      state,
      pending.approvalId,
      bodyWithoutCompatibilityTenant,
      OTHER_PRINCIPAL_TOKEN,
    );
    const otherTenantBody = {
      ...bodyWithoutCompatibilityTenant,
      arguments_json: JSON.stringify({
        to: "customer@example.com",
        attachment: "account-summary.pdf",
        target_tenant: "tenant-b",
      }),
    };
    const otherTenant = await consume(
      state,
      pending.approvalId,
      otherTenantBody,
      OTHER_TENANT_TOKEN,
    );

    expect(otherPrincipal.status).toBe(404);
    expect(await json(otherPrincipal)).toEqual({ error: "APPROVAL_NOT_FOUND" });
    expect(otherTenant.status).toBe(404);
    expect(await json(otherTenant)).toEqual({ error: "APPROVAL_NOT_FOUND" });
    expect(state.approvals.records.get(pending.approvalId)?.status).toBe(
      "APPROVED",
    );
  });

  test("rejects a changed email recipient without consuming the approval", async () => {
    const state = createHarness();
    const pending = await createPendingEmailApproval(state);
    await operatorDecision(state, pending.approvalId, "approve");
    const changed = {
      ...pending.body,
      arguments_json: JSON.stringify({
        to: "attacker@example.com",
        attachment: "account-summary.pdf",
        target_tenant: "tenant-a",
      }),
    };

    const response = await consume(state, pending.approvalId, changed);
    expect(response.status).toBe(409);
    expect(await json(response)).toEqual({
      error: "APPROVAL_REQUEST_MISMATCH",
    });
    expect(state.approvals.records.get(pending.approvalId)?.status).toBe(
      "APPROVED",
    );
    expect(state.approvals.consumeCalls).toBe(0);
  });

  test("rejects a changed refund amount_minor without consuming the approval", async () => {
    const state = createHarness();
    const original = actionBody(
      "refund.create",
      { amount_minor: 8_500, target_tenant: "tenant-a" },
      "Refund the verified order.",
    );
    const evaluated = await evaluate(state, original);
    const approvalId = evaluated.body.approval_id as string;
    expect(evaluated.body.decision).toBe("REQUIRE_APPROVAL");
    await operatorDecision(state, approvalId, "approve");
    const changed = {
      ...original,
      arguments_json: JSON.stringify({
        amount_minor: 9_000,
        target_tenant: "tenant-a",
      }),
    };

    const response = await consume(state, approvalId, changed);
    expect(response.status).toBe(409);
    expect(await json(response)).toEqual({
      error: "APPROVAL_REQUEST_MISMATCH",
    });
    expect(state.approvals.records.get(approvalId)?.status).toBe("APPROVED");
    expect(state.approvals.consumeCalls).toBe(0);
  });

  test("atomically authorizes one concurrent consume and rejects the replay", async () => {
    const state = createHarness();
    const pending = await createPendingEmailApproval(state);
    await operatorDecision(state, pending.approvalId, "approve");

    const [first, second] = await Promise.all([
      consume(state, pending.approvalId, pending.body),
      consume(state, pending.approvalId, pending.body),
    ]);
    const outcomes = await Promise.all(
      [first, second].map(async (response) => ({
        status: response.status,
        body: await json(response),
      })),
    );

    expect(outcomes.filter(({ status }) => status === 200)).toHaveLength(1);
    expect(outcomes.filter(({ status }) => status === 409)).toHaveLength(1);
    expect(outcomes.find(({ status }) => status === 200)?.body).toEqual({
      authorized: true,
      approval_id: pending.approvalId,
      tool_name: "email.send",
      normalized_args: {
        to: "customer@example.com",
        attachment: "account-summary.pdf",
        target_tenant: "tenant-a",
      },
    });
    expect(outcomes.find(({ status }) => status === 409)?.body).toEqual({
      error: "APPROVAL_ALREADY_CONSUMED",
    });
    expect(state.approvals.consumeCalls).toBe(2);
    expect(state.approvals.records.get(pending.approvalId)?.status).toBe(
      "CONSUMED",
    );
  });

  test("fails closed when an injected repository cannot confirm the consume audit", async () => {
    const state = createHarness();
    const pending = await createPendingEmailApproval(state);
    expect(
      (await operatorDecision(state, pending.approvalId, "approve")).status,
    ).toBe(200);
    state.approvals.consumeAuditPersisted = false;

    const response = await consume(state, pending.approvalId, pending.body);

    expect(response.status).toBe(503);
    expect(await json(response)).toEqual({
      error: "APPROVAL_CONSUME_UNAVAILABLE",
    });
  });

  test("returns stable rejected and expired consumption errors", async () => {
    const rejectedState = createHarness();
    const rejected = await createPendingEmailApproval(rejectedState);
    await operatorDecision(rejectedState, rejected.approvalId, "reject");
    const rejectedResponse = await consume(
      rejectedState,
      rejected.approvalId,
      rejected.body,
    );

    expect(rejectedResponse.status).toBe(403);
    expect(await json(rejectedResponse)).toEqual({ error: "APPROVAL_REJECTED" });

    const expiredState = createHarness();
    const expired = await createPendingEmailApproval(expiredState);
    await operatorDecision(expiredState, expired.approvalId, "approve");
    expiredState.setNow(START_SECONDS + 600);
    const expiredResponse = await consume(
      expiredState,
      expired.approvalId,
      expired.body,
    );

    expect(expiredResponse.status).toBe(410);
    expect(await json(expiredResponse)).toEqual({ error: "APPROVAL_EXPIRED" });
    expect(expiredState.approvals.records.get(expired.approvalId)?.status).toBe(
      "EXPIRED",
    );
  });

  test("consumption never invokes the classifier, AI quota, or rate limiter", async () => {
    const state = createHarness();
    const pending = await createPendingEmailApproval(state);
    await operatorDecision(state, pending.approvalId, "approve");

    state.classifier.calls = 0;
    state.classifier.throwIfCalled = true;
    state.quota.calls = 0;
    state.quota.throwIfCalled = true;
    state.rateLimiter.calls.length = 0;

    const response = await consume(state, pending.approvalId, pending.body);
    expect(response.status).toBe(200);
    expect(await json(response)).toMatchObject({ authorized: true });
    expect(state.classifier.calls).toBe(0);
    expect(state.quota.calls).toBe(0);
    expect(state.rateLimiter.calls).toHaveLength(0);
  });
});

describe("Step 6 Worker operator query privacy", () => {
  test("returns only the sanitized public audit and approval projections", async () => {
    const state = createHarness();
    const rawSource = "raw-source-text-never-returned";
    const rawRecipient = "private-query-recipient@example.com";
    const pending = await createPendingEmailApproval(state, {
      source_text: rawSource,
      arguments_json: JSON.stringify({
        to: rawRecipient,
        attachment: "private-customer-file.csv",
        target_tenant: "tenant-a",
      }),
    });
    const stored = state.approvals.records.get(pending.approvalId)!;

    const auditResponse = await state.worker.fetch(
      request(
        "/v1/audit?tenant_id=tenant-a&decision=REQUIRE_APPROVAL&tool_name=email.send&limit=10",
        { token: OPERATOR_TOKEN },
      ),
      state.env,
    );
    const approvalResponse = await state.worker.fetch(
      request("/v1/approvals?status=PENDING&tenant_id=tenant-a&limit=10", {
        token: OPERATOR_TOKEN,
      }),
      state.env,
    );
    const auditBody = await json(auditResponse);
    const approvalBody = await json(approvalResponse);

    expect(auditResponse.status).toBe(200);
    expect(approvalResponse.status).toBe(200);
    expect(auditBody).toEqual({
      audit_events: [
        {
          id: "audit-1",
          request_id: "request-1",
          principal_id: "principal-a",
          key_id: "key-a",
          tenant_id: "tenant-a",
          tool_name: "email.send",
          event_type: "EVALUATED",
          decision: "REQUIRE_APPROVAL",
          risk_level: "medium",
          policy_codes: ["OUTBOUND_SEND"],
          policy_version: POLICY_VERSION,
          arguments_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
          source_text_hash: await sha256Hex(rawSource),
          approval_id: pending.approvalId,
          created_at: START_SECONDS,
        },
      ],
    });
    expect(approvalBody).toEqual({
      approvals: [
        {
          approval_id: pending.approvalId,
          principal_id: "principal-a",
          tenant_id: "tenant-a",
          tool_name: "email.send",
          risk_level: "medium",
          policy_codes: ["OUTBOUND_SEND"],
          policy_version: POLICY_VERSION,
          approval_display: {
            kind: "email_send",
            recipient: rawRecipient,
            has_attachments: true,
          },
          status: "PENDING",
          created_at: START_SECONDS,
          expires_at: START_SECONDS + 600,
          decided_at: null,
          consumed_at: null,
        },
      ],
    });

    const serialized = JSON.stringify({ auditBody, approvalBody });
    expect(serialized).not.toContain(rawSource);
    expect(serialized).not.toContain("private-customer-file.csv");
    expect(serialized).not.toContain(stored.request_hash);
    expect(serialized).not.toContain(AGENT_TOKEN);
    expect(serialized).not.toContain(OPERATOR_TOKEN);
    expect(serialized).not.toContain("authorization");
    expect(serialized).not.toContain("normalized_args");
  });
});
