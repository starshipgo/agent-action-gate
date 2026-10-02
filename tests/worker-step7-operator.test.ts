import { describe, expect, test } from "bun:test";
import type { AuditEvent, AuditQuery } from "../src/persistence/types";
import { POLICY_VERSION } from "../src/policy-metadata";
import { sha256Hex } from "../src/security/crypto";
import type {
  ApiKeyListQuery,
  ApiKeyManagementRepository,
  ApiKeyMetadata,
  NewApiKeyRecord,
  SecurityRepositories,
} from "../src/security/types";
import { createWorker } from "../src/worker";

const ORIGIN = "https://gate.example";
const OPERATOR_KEY = "step7-obviously-fake-operator-key";
const AGENT_KEY = ["aag", "test", "step7_agent_token_1234567890"].join("_");
const START_SECONDS = Date.parse("2026-10-01T00:00:00.000Z") / 1_000;

const recentEvent: AuditEvent = {
  id: "audit-1",
  request_id: "request-1",
  principal_id: "principal-1",
  key_id: "key-1",
  tenant_id: "tenant-a",
  tool_name: "crm.read_contact",
  event_type: "EVALUATED",
  decision: "ALLOW",
  risk_level: "low",
  policy_codes: [],
  arguments_hash: "a".repeat(64),
  source_text_hash: "b".repeat(64),
  approval_id: null,
  policy_version: POLICY_VERSION,
  created_at: START_SECONDS,
};

class MemoryApiKeys implements ApiKeyManagementRepository {
  readonly records = new Map<string, ApiKeyMetadata>();
  lastCreate: NewApiKeyRecord | null = null;

  async list(query: ApiKeyListQuery): Promise<ApiKeyMetadata[]> {
    return [...this.records.values()]
      .filter(
        (key) =>
          (query.tenant_id === undefined || key.tenant_id === query.tenant_id) &&
          (query.status === undefined || key.status === query.status),
      )
      .slice(0, query.limit ?? 50)
      .map((key) => ({ ...key }));
  }

  async create(input: NewApiKeyRecord) {
    this.lastCreate = { ...input };
    if (this.records.has(input.key_id)) return { kind: "conflict" } as const;
    const { key_hash: _keyHash, ...metadata } = input;
    const created: ApiKeyMetadata = {
      ...metadata,
      status: "active",
      revoked_at: null,
    };
    this.records.set(input.key_id, created);
    return { kind: "created", api_key: { ...created } } as const;
  }

  async revoke(keyId: string, revokedAt: number) {
    const record = this.records.get(keyId);
    if (record === undefined) return { kind: "not_found" } as const;
    if (record.status === "revoked") {
      return { kind: "already_revoked", api_key: { ...record } } as const;
    }
    record.status = "revoked";
    record.revoked_at = revokedAt;
    return { kind: "revoked", api_key: { ...record } } as const;
  }
}

interface Harness {
  worker: ReturnType<typeof createWorker>;
  env: Env;
  apiKeys: MemoryApiKeys;
  auditQueries: AuditQuery[];
  setNow(seconds: number): void;
}

function createHarness(): Harness {
  let now = START_SECONDS;
  const apiKeys = new MemoryApiKeys();
  const auditQueries: AuditQuery[] = [];
  const repositories: SecurityRepositories = {
    principals: {
      findByKeyHash: async (hash) =>
        hash === (await sha256Hex(AGENT_KEY))
          ? {
              key_id: "agent-key-1",
              principal_id: "agent-principal-1",
              tenant_id: "tenant-a",
              daily_ai_limit: 10,
              status: "active",
            }
          : null,
    },
    quota: {
      tryConsume: async () => ({ allowed: false, limit: 0 }),
    },
    idempotency: {
      claim: async () => {
        throw new Error("not used");
      },
      complete: async () => false,
      abandon: async () => undefined,
    },
    audit: {
      append: async () => undefined,
      list: async (query) => {
        auditQueries.push(query);
        return [recentEvent];
      },
    },
    approvals: {
      create: async () => {
        throw new Error("not used");
      },
      findById: async () => null,
      decide: async () => ({ kind: "not_found" }),
      consume: async () => ({ kind: "not_found" }),
      list: async () => [],
    },
    evaluations: {
      persist: async () => ({ approval: null }),
    },
    apiKeys,
    overview: {
      getMetrics: async () => ({
        allowed: 12,
        blocked: 4,
        approval_required: 3,
        pending_approvals: 2,
        ai_quota_used_today: 7,
        ai_daily_limit: 100,
      }),
    },
  };
  const worker = createWorker({
    createSecurityRepositories: () => repositories,
    getOperatorSecret: () => OPERATOR_KEY,
    now: () => new Date(now * 1_000),
  });

  return {
    worker,
    env: {} as Env,
    apiKeys,
    auditQueries,
    setNow(seconds) {
      now = seconds;
    },
  };
}

function request(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    bearer?: string;
    cookie?: string;
    origin?: string;
  } = {},
): Request {
  const headers = new Headers();
  if (options.body !== undefined) headers.set("content-type", "application/json");
  if (options.bearer !== undefined) {
    headers.set("authorization", `Bearer ${options.bearer}`);
  }
  if (options.cookie !== undefined) headers.set("cookie", options.cookie);
  if (options.origin !== undefined) headers.set("origin", options.origin);

  return new Request(`${ORIGIN}${path}`, {
    method: options.method ?? "GET",
    headers,
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  });
}

async function json(response: Response): Promise<Record<string, unknown>> {
  return response.json() as Promise<Record<string, unknown>>;
}

async function createSession(state: Harness): Promise<string> {
  const response = await state.worker.fetch(
    request("/v1/operator/session", {
      method: "POST",
      origin: ORIGIN,
      body: { operator_api_key: OPERATOR_KEY },
    }),
    state.env,
  );
  expect(response.status).toBe(200);
  return response.headers.get("set-cookie")!.split(";", 1)[0]!;
}

describe("Step 7 operator browser session", () => {
  test("rejects invalid credentials and issues a bounded secure cookie for a valid key", async () => {
    const state = createHarness();
    const missingOrigin = await state.worker.fetch(
      request("/v1/operator/session", {
        method: "POST",
        body: { operator_api_key: OPERATOR_KEY },
      }),
      state.env,
    );
    expect(missingOrigin.status).toBe(403);
    expect(await json(missingOrigin)).toEqual({ error: "ORIGIN_FORBIDDEN" });
    expect(missingOrigin.headers.get("set-cookie")).toBeNull();

    const crossOrigin = await state.worker.fetch(
      request("/v1/operator/session", {
        method: "POST",
        origin: "https://attacker.example",
        body: { operator_api_key: OPERATOR_KEY },
      }),
      state.env,
    );
    expect(crossOrigin.status).toBe(403);
    expect(crossOrigin.headers.get("set-cookie")).toBeNull();

    const invalid = await state.worker.fetch(
      request("/v1/operator/session", {
        method: "POST",
        origin: ORIGIN,
        body: { operator_api_key: ["wrong", "but", "long", "enough", "key"].join("-") },
      }),
      state.env,
    );
    expect(invalid.status).toBe(401);
    expect(await json(invalid)).toEqual({ error: "INVALID_OPERATOR_KEY" });

    const response = await state.worker.fetch(
      request("/v1/operator/session", {
        method: "POST",
        origin: ORIGIN,
        body: { operator_api_key: OPERATOR_KEY },
      }),
      state.env,
    );
    const body = await json(response);
    const cookie = response.headers.get("set-cookie")!;

    expect(response.status).toBe(200);
    expect(body).toEqual({
      authenticated: true,
      expires_at: "2026-10-01T08:00:00.000Z",
    });
    expect(cookie).toStartWith("__Host-aag_operator_session=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("Max-Age=28800");
    expect(cookie).not.toContain(OPERATOR_KEY);
    expect(JSON.stringify(body)).not.toContain(OPERATOR_KEY);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });

  test("accepts the cookie for reads, enforces expiry, and clears it on logout", async () => {
    const state = createHarness();
    const cookie = await createSession(state);
    const policies = await state.worker.fetch(
      request("/v1/policies", { cookie }),
      state.env,
    );
    expect(policies.status).toBe(200);
    expect(await json(policies)).toMatchObject({ policy_version: POLICY_VERSION });

    const finalCharacter = cookie.at(-1)!;
    const tamperedCookie = `${cookie.slice(0, -1)}${finalCharacter === "A" ? "B" : "A"}`;
    const tampered = await state.worker.fetch(
      request("/v1/policies", { cookie: tamperedCookie }),
      state.env,
    );
    expect(tampered.status).toBe(401);

    const approvals = await state.worker.fetch(
      request("/v1/approvals?status=PENDING&limit=10", { cookie }),
      state.env,
    );
    expect(approvals.status).toBe(200);
    expect(await json(approvals)).toEqual({ approvals: [] });
    const missingDecision = await state.worker.fetch(
      request("/v1/approvals/missing/approve", {
        method: "POST",
        cookie,
        origin: ORIGIN,
      }),
      state.env,
    );
    expect(missingDecision.status).toBe(404);

    const logout = await state.worker.fetch(
      request("/v1/operator/session", {
        method: "DELETE",
        cookie,
        origin: ORIGIN,
      }),
      state.env,
    );
    expect(logout.status).toBe(200);
    expect(logout.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(await json(logout)).toEqual({ authenticated: false });

    state.setNow(START_SECONDS + 8 * 60 * 60);
    const expired = await state.worker.fetch(
      request("/v1/policies", { cookie }),
      state.env,
    );
    expect(expired.status).toBe(401);
  });

  test("rejects Agent bearer credentials and cross-origin cookie mutations", async () => {
    const state = createHarness();
    const agentAttempt = await state.worker.fetch(
      request("/v1/policies", { bearer: AGENT_KEY }),
      state.env,
    );
    expect(agentAttempt.status).toBe(401);

    const cookie = await createSession(state);
    const crossOrigin = await state.worker.fetch(
      request("/v1/api-keys", {
        method: "POST",
        cookie,
        origin: "https://attacker.example",
        body: { tenant_id: "tenant-a", label: "test", daily_ai_limit: 10 },
      }),
      state.env,
    );
    expect(crossOrigin.status).toBe(403);
    expect(await json(crossOrigin)).toEqual({ error: "ORIGIN_FORBIDDEN" });
    expect(state.apiKeys.records.size).toBe(0);
  });
});

describe("Step 7 safe operator APIs", () => {
  test("returns server-side overview aggregates and recent sanitized activity", async () => {
    const state = createHarness();
    const cookie = await createSession(state);
    const response = await state.worker.fetch(
      request("/v1/operator/overview", { cookie }),
      state.env,
    );

    expect(response.status).toBe(200);
    expect(await json(response)).toEqual({
      policy_version: POLICY_VERSION,
      metrics: {
        allowed: 12,
        blocked: 4,
        pending_approvals: 2,
        approval_required: 3,
        ai_quota_usage: { used_today: 7, daily_limit: 100 },
      },
      recent_activity: [recentEvent],
    });
    expect(state.auditQueries).toEqual([{ limit: 10 }]);
  });

  test("creates a raw key once, stores only its hash, lists safe metadata, and revokes", async () => {
    const state = createHarness();
    const cookie = await createSession(state);
    const createResponse = await state.worker.fetch(
      request("/v1/api-keys", {
        method: "POST",
        cookie,
        origin: ORIGIN,
        body: {
          tenant_id: "tenant-a",
          label: "Disposable smoke key",
          daily_ai_limit: 25,
        },
      }),
      state.env,
    );
    const created = await json(createResponse);
    const rawKey = created.raw_api_key as string;
    const publicKey = created.api_key as Record<string, unknown>;

    expect(createResponse.status).toBe(201);
    expect(rawKey).toMatch(/^aag_test_[A-Za-z0-9_-]{43}$/);
    expect(Object.keys(publicKey).sort()).toEqual([
      "created_at",
      "daily_ai_limit",
      "key_id",
      "key_prefix",
      "label",
      "revoked_at",
      "status",
      "tenant_id",
    ]);
    expect(state.apiKeys.lastCreate?.key_hash).toBe(await sha256Hex(rawKey));
    expect(JSON.stringify(state.apiKeys.lastCreate)).not.toContain(rawKey);
    expect(state.apiKeys.lastCreate?.principal_id).toMatch(/^aagp_[0-9a-f-]{36}$/);

    const listResponse = await state.worker.fetch(
      request("/v1/api-keys?tenant_id=tenant-a&status=active&limit=10", {
        cookie,
      }),
      state.env,
    );
    const listed = await json(listResponse);
    expect(listResponse.status).toBe(200);
    expect(JSON.stringify(listed)).not.toContain(rawKey);
    expect(JSON.stringify(listed)).not.toContain("key_hash");
    expect(JSON.stringify(listed)).not.toContain("principal_id");

    const keyId = publicKey.key_id as string;
    const revokeResponse = await state.worker.fetch(
      request(`/v1/api-keys/${keyId}/revoke`, {
        method: "POST",
        cookie,
        origin: ORIGIN,
      }),
      state.env,
    );
    expect(revokeResponse.status).toBe(200);
    expect(await json(revokeResponse)).toMatchObject({
      api_key: { key_id: keyId, status: "revoked" },
    });
  });

  test("validates API-key inputs and audit time-window filters", async () => {
    const state = createHarness();
    const cookie = await createSession(state);
    const invalidKey = await state.worker.fetch(
      request("/v1/api-keys", {
        method: "POST",
        cookie,
        origin: ORIGIN,
        body: {
          tenant_id: "Tenant-A",
          label: "Bad tenant",
          daily_ai_limit: 10,
        },
      }),
      state.env,
    );
    expect(invalidKey.status).toBe(400);
    const callerControlledPrincipal = await state.worker.fetch(
      request("/v1/api-keys", {
        method: "POST",
        cookie,
        origin: ORIGIN,
        body: {
          principal_id: "caller-chosen-authority",
          tenant_id: "tenant-a",
          label: "Unexpected authority field",
          daily_ai_limit: 10,
        },
      }),
      state.env,
    );
    expect(callerControlledPrincipal.status).toBe(400);

    const audit = await state.worker.fetch(
      request(
        `/v1/audit?created_from=${START_SECONDS - 60}&created_to=${START_SECONDS + 60}&limit=10`,
        { cookie },
      ),
      state.env,
    );
    expect(audit.status).toBe(200);
    expect(state.auditQueries.at(-1)).toEqual({
      created_from: START_SECONDS - 60,
      created_to: START_SECONDS + 60,
      limit: 10,
    });

    const inverted = await state.worker.fetch(
      request(
        `/v1/audit?created_from=${START_SECONDS + 1}&created_to=${START_SECONDS}`,
        { cookie },
      ),
      state.env,
    );
    expect(inverted.status).toBe(400);
  });
});
