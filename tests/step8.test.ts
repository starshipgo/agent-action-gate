import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { DEMO_SCENARIOS } from "../src/demo/scenarios";
import { runDemoScenario, simulateFakeApproval } from "../src/demo/runtime";
import { DemoPage } from "../src/ui/pages/DemoPage";
import { DeveloperQuickstartPage } from "../src/ui/pages/DeveloperQuickstartPage";
import { AgentActionGate, GateHttpError } from "../packages/sdk/src/index";
import { parseBetaInterest, parsePublicEvent, type BetaRepository } from "../src/product/beta";
import { createWorker } from "../src/worker";
import type { SecurityRepositories } from "../src/security/types";
import { scanText } from "../scripts/public-release-check";
import { normalizeWranglerBuildMetadata } from "../scripts/normalize-wrangler-build";
import { resolveRoute } from "../src/ui/routing";
import { evaluateCorpus, optionalProvider, type EvalCase } from "../evals/run";

const request = { agent_role: "support_agent", tool_name: "crm.read_contact", arguments_json: '{"target_tenant":"demo-acme"}', source_text: "fictional", request_tenant: "demo-acme" };
function fakeFetch(decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL", calls: RequestInit[]): typeof fetch {
  return (async (_url: string | URL | Request, init?: RequestInit) => {
    calls.push(init ?? {});
    return Response.json({ decision, risk_level: decision === "ALLOW" ? "low" : "medium", policy_codes: [], requires_approval: decision === "REQUIRE_APPROVAL", normalized_tool: "crm.read_contact", normalized_args: {}, ...(decision === "REQUIRE_APPROVAL" ? { approval_id: "fictional-approval", expires_at: "2026-10-01T00:10:00.000Z" } : {}) });
  }) as typeof fetch;
}

describe("fixed public demo", () => {
  test("all six scenarios have the specified outcomes and never use a real executor", async () => {
    const expected = ["ALLOW", "REQUIRE_APPROVAL", "DENY", "DENY", "REQUIRE_APPROVAL", "DENY"] as const;
    for (let index = 0; index < DEMO_SCENARIOS.length; index++) {
      const scenario = DEMO_SCENARIOS[index]!;
      const result = await runDemoScenario(scenario.id);
      expect(result.result.decision).toBe(expected[index]!);
      expect(result.input.request_tenant).toBe("demo-acme");
      expect(result.fake_effect === null || result.fake_effect.startsWith("Fake CRM:")).toBe(true);
    }
    expect(await simulateFakeApproval("normal-email")).toContain("nothing was sent");
    expect(await simulateFakeApproval("small-refund")).toContain("no payment or account was changed");
  });

  test("cannot select arbitrary tenant, scenario, contact, or denied action", async () => {
    expect(runDemoScenario("arbitrary" as never)).rejects.toThrow();
    expect(simulateFakeApproval("cross-tenant")).rejects.toThrow();
    expect(simulateFakeApproval("injection-exfiltration")).rejects.toThrow();
    expect(DEMO_SCENARIOS.every((item) => item.input.request_tenant === "demo-acme")).toBe(true);
  });

  test("public UI labels demo and exposes one-click scenarios and quickstart", () => {
    const markup = renderToStaticMarkup(createElement(DemoPage, { onHome: () => {}, onQuickstart: () => {} }));
    expect(markup).toContain("Demo environment — no real external actions are executed.");
    expect((markup.match(/Run scenario/g) ?? []).length).toBe(6);
    expect(markup).toContain("no real external actions");
    expect(renderToStaticMarkup(createElement(DeveloperQuickstartPage, { onHome: () => {}, onDemo: () => {} }))).toContain("Proposed beta structure");
    expect(resolveRoute("/demo")).toBe("demo");
    expect(resolveRoute("/quickstart")).toBe("quickstart");
  });
  test("demo runtime and scenarios have no external adapter, credential, or arbitrary-tenant path", async () => {
    const runtime = await Bun.file("src/demo/runtime.ts").text();
    const scenarios = await Bun.file("src/demo/scenarios.ts").text();
    for (const forbidden of ["/integrations/", "../worker", "fetch(", "Bun.env", "process.env", "env.DB", "env.AI"]) {
      expect(runtime).not.toContain(forbidden);
      expect(scenarios).not.toContain(forbidden);
    }
    expect(DEMO_SCENARIOS).toHaveLength(6);
    for (const scenario of DEMO_SCENARIOS) {
      expect(scenario.input.request_tenant).toBe("demo-acme");
      const parsed = JSON.parse(scenario.input.arguments_json) as { target_tenant: string };
      expect(["demo-acme", "demo-other"]).toContain(parsed.target_tenant);
    }
  });
});

describe("explicit SDK", () => {
  test.each(["ALLOW", "DENY", "REQUIRE_APPROVAL"] as const)("types and returns %s without auto-execution", async (decision) => {
    const calls: RequestInit[] = [];
    const gate = new AgentActionGate({ baseUrl: "https://gate.example.invalid", apiKey: "fake-test-key", fetch: fakeFetch(decision, calls) });
    const result = await gate.evaluate(request);
    expect(result.decision).toBe(decision);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.body).toBe(JSON.stringify(request));
    if (result.decision === "REQUIRE_APPROVAL") expect(result.approval_id).toBe("fictional-approval");
  });
  test("consume is explicit and preserves the exact original request", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const gate = new AgentActionGate({ baseUrl: "https://gate.example.invalid", apiKey: "fake-test-key", fetch: (async (url: string | URL | Request, init: RequestInit) => { calls.push({ url: String(url), init }); return Response.json({ authorized: true, approval_id: "fictional-approval", tool_name: "email.send", normalized_args: {} }); }) as typeof fetch });
    expect((await gate.consumeApproval("fictional-approval", request)).authorized).toBe(true);
    expect(calls[0]?.url).toContain("/v1/approvals/fictional-approval/consume");
    expect(calls[0]?.init.body).toBe(JSON.stringify(request));
    expect(calls).toHaveLength(1);
  });
  test("rejects insecure nonlocal URL and propagates 409 without action", async () => {
    expect(() => new AgentActionGate({ baseUrl: "http://public.example.invalid", apiKey: "fake" })).toThrow();
    const gate = new AgentActionGate({ baseUrl: "https://gate.example.invalid", apiKey: "fake", fetch: (async () => Response.json({ error: "APPROVAL_ALREADY_CONSUMED" }, { status: 409 })) as unknown as typeof fetch });
    expect(gate.consumeApproval("fictional-approval", request)).rejects.toBeInstanceOf(GateHttpError);
  });
});

describe("privacy-preserving beta", () => {
  test("accepts only allowlisted aggregate events and minimal interest fields", () => {
    expect(parsePublicEvent({ event: "demo_scenario_run" })).toBe("demo_scenario_run");
    expect(parsePublicEvent({ event: "demo_scenario_run", source_text: "secret" })).toBeNull();
    expect(parseBetaInterest({ email: "test@example.invalid", intended_integration: "MCP", approximate_monthly_tool_calls: "under_1k" }, 100)?.created_at).toBe(100);
    expect(parseBetaInterest({ email: "test@example.invalid", intended_integration: "MCP", approximate_monthly_tool_calls: "under_1k", arguments: "secret" }, 100)).toBeNull();
    expect(parseBetaInterest({ email: "bad", intended_integration: "MCP", approximate_monthly_tool_calls: "under_1k" }, 100)).toBeNull();
    expect(parseBetaInterest({ email: "bad..dots@example.invalid", intended_integration: "MCP", approximate_monthly_tool_calls: "under_1k" }, 100)).toBeNull();
    expect(parseBetaInterest({ email: "test@a..invalid", intended_integration: "MCP", approximate_monthly_tool_calls: "under_1k" }, 100)).toBeNull();
  });
  test("public event and waitlist endpoints rate-limit before storage", async () => {
    let allows = 0;
    const stored: unknown[] = [];
    const beta: BetaRepository = { async recordPublicEvent(event, day) { stored.push({ event, day }); }, async createInterest(interest) { stored.push(interest); }, async funnel() { throw new Error("not used"); } };
    const worker = createWorker({ createSecurityRepositories: () => ({ beta }) as unknown as SecurityRepositories, createRateLimiter: () => ({ async allow() { allows++; return allows <= 1; } }) });
    const env = {} as Env;
    const make = (path: string, body: unknown) => new Request(`https://gate.example.invalid${path}`, { method: "POST", headers: { origin: "https://gate.example.invalid", "content-type": "application/json", "cf-connecting-ip": "192.0.2.1" }, body: JSON.stringify(body) });
    expect((await worker.fetch(make("/v1/product-events", { event: "demo_scenario_run" }), env)).status).toBe(202);
    expect((await worker.fetch(make("/v1/beta-interest", { email: "test@example.invalid", intended_integration: "MCP", approximate_monthly_tool_calls: "under_1k" }), env)).status).toBe(429);
    expect(stored).toEqual([{ event: "demo_scenario_run", day: expect.any(String) }]);
  });
  test("waitlist rejects extra fields and accepts only a validated record", async () => {
    const stored: unknown[] = [];
    const beta: BetaRepository = { async recordPublicEvent() { throw new Error("not used"); }, async createInterest(interest) { stored.push(interest); }, async funnel() { throw new Error("not used"); } };
    const worker = createWorker({ createSecurityRepositories: () => ({ beta }) as unknown as SecurityRepositories, createRateLimiter: () => ({ async allow() { return true; } }) });
    const body = { email: "test@example.invalid", intended_integration: "Dify", approximate_monthly_tool_calls: "1k_to_10k" };
    const make = (payload: unknown, origin = "https://gate.example.invalid") => new Request("https://gate.example.invalid/v1/beta-interest", { method: "POST", headers: { origin }, body: JSON.stringify(payload) });
    expect((await worker.fetch(make({ ...body, source_text: "private" }), {} as Env)).status).toBe(400);
    expect((await worker.fetch(make(body, "https://other.example.invalid"), {} as Env)).status).toBe(403);
    expect((await worker.fetch(make(body), {} as Env)).status).toBe(202);
    expect(stored).toEqual([{ ...body, created_at: expect.any(Number) }]);
  });
  test("D1 analytics schema cannot store source, arguments, or credentials", async () => {
    const db = new Database(":memory:", { strict: true });
    for (const name of ["0001_security.sql", "0002_audit_approval.sql", "0003_policy_version_approval_display.sql", "0004_beta_signals.sql"]) db.exec(await Bun.file(`migrations/${name}`).text());
    const columns = db.query("PRAGMA table_info(product_event_counters)").all() as { name: string }[];
    expect(columns.map((row) => row.name)).toEqual(["event_name", "day_utc", "total"]);
    const interestColumns = db.query("PRAGMA table_info(beta_interest)").all() as { name: string }[];
    expect(interestColumns.map((row) => row.name)).toEqual(["email", "intended_integration", "approximate_monthly_tool_calls", "created_at"]);
    expect(() => db.query("INSERT INTO product_event_counters VALUES ('source_text', '2026-10-01', 1)").run()).toThrow();
    db.query("INSERT INTO api_keys (id, principal_id, key_hash, key_prefix, tenant_id, label, status, created_at, revoked_at, daily_ai_limit) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, NULL, ?)").run("fake-key-id", "fake-principal", "a".repeat(64), "aag_test_fake", "demo-acme", "fictional", 1780272000, 2);
    expect(db.query("SELECT total FROM product_event_counters WHERE event_name = 'api_key_created'").get()).toEqual({ total: 1 });
    db.close();
  });
  test("beta funnel summary requires the separate operator credential", async () => {
    const beta: BetaRepository = { async recordPublicEvent() {}, async createInterest() {}, async funnel() { return { demo_scenario_run: 2, developer_quickstart_view: 1, api_key_created: 0, first_evaluation: 0, first_approval_created: 0, first_approval_consumed: 0 }; } };
    const operatorKey = ["obviously", "fake", "operator", "test", "key"].join("-");
    const worker = createWorker({ createSecurityRepositories: () => ({ beta, principals: { async findByKeyHash() { return null; } } }) as unknown as SecurityRepositories, getOperatorSecret: () => operatorKey });
    const url = "https://gate.example.invalid/v1/operator/beta-funnel";
    expect((await worker.fetch(new Request(url), {} as Env)).status).toBe(401);
    const authorized = await worker.fetch(new Request(url, { headers: { authorization: ["Bearer", operatorKey].join(" ") } }), {} as Env);
    expect(authorized.status).toBe(200);
    expect((await authorized.json() as { events: { demo_scenario_run: number } }).events.demo_scenario_run).toBe(2);
  });
});

describe("reproducible evaluation corpus", () => {
  test("fixtures pass offline and live provider is disabled by default", async () => {
    const cases = await Bun.file("evals/cases.json").json() as EvalCase[];
    expect(optionalProvider(false, {})).toBeUndefined();
    expect(() => optionalProvider(true, {})).toThrow();
    const report = await evaluateCorpus(cases);
    expect(report.kind).toBe("fixture_regression");
    expect(report.total).toBeGreaterThanOrEqual(9);
    expect(report.failed).toBe(0);
    expect(new Set(report.rows.map((item) => item.category)).size).toBe(9);
  });
});

describe("release guardrails", () => {
  test("generated Wrangler metadata is normalized without changing bindings", () => {
    const sourcePath = join(tmpdir(), "fictional-project", "wrangler.jsonc");
    const builtPath = join(tmpdir(), "fictional-project", "dist", "agent_action_gate", "wrangler.json");
    const original = { configPath: sourcePath, userConfigPath: sourcePath, ai: { binding: "AI" } };
    const normalized = normalizeWranglerBuildMetadata(original, sourcePath, builtPath);
    expect(normalized.configPath).toBe("../../wrangler.jsonc");
    expect(normalized.userConfigPath).toBe("../../wrangler.jsonc");
    expect(normalized.ai).toEqual({ binding: "AI" });
    expect(() => normalizeWranglerBuildMetadata({ ...original, configPath: "unexpected" }, sourcePath, builtPath)).toThrow();
  });
  test("scanner catches runtime-generated fake credentials and personal paths without printing values", async () => {
    const fixtureDirectory = await mkdtemp(join(tmpdir(), "aag-release-fixture-"));
    const fixturePath = join(fixtureDirectory, "synthetic.txt");
    const token = ["abcdefghi", "jklmnopqr", "stuvwxyz", "1234567890"].join("");
    const bearer = ["Authorization:", "Bearer", token].join(" ");
    const personalPath = ["", "Users", "example", "private", "repo"].join("/");
    const rawAgentKey = ["aag", "test", "synthetic", "fixture", "token", "1234567890"].join("_");
    try {
      await Bun.write(fixturePath, [bearer, personalPath, `CLOUDFLARE_API_TOKEN=${token}`, rawAgentKey].join("\n"));
      const results = scanText("synthetic.txt", await Bun.file(fixturePath).text());
      expect(results.map((item) => item.kind)).toContain("bearer_credential");
      expect(results.map((item) => item.kind)).toContain("personal_absolute_path");
      expect(results.map((item) => item.kind)).toContain("token_literal");
      expect(results.map((item) => item.kind)).toContain("raw_agent_key");
      expect(JSON.stringify(results)).not.toContain(token);
    } finally {
      await rm(fixtureDirectory, { recursive: true, force: true });
    }
  });
  test("demo config has distinct placeholders, bounded rate, and no production D1 ID", async () => {
    const config = await Bun.file("wrangler.demo.example.jsonc").text();
    const production = await Bun.file("wrangler.jsonc").text();
    const migrationConfig = await Bun.file("wrangler.preview-migrations.jsonc").text();
    expect(production).toContain('"database_id": "REPLACE_WITH_PREVIEW_D1_ID"');
    expect(production).toContain('"namespace_id": "REPLACE_WITH_PREVIEW_RATE_NAMESPACE_ID"');
    expect(migrationConfig).toContain('"database_id": "REPLACE_WITH_PREVIEW_D1_ID"');
    const ids = [...production.matchAll(/"database_id"\s*:\s*"([a-f0-9-]{36})"/g)].map((match) => match[1]!);
    expect(ids).toHaveLength(0);
    for (const id of ids) expect(config).not.toContain(id);
    expect(config).toContain('"limit": 5');
    expect(config).toContain("REPLACE_WITH_NEW_DEMO_D1_ID");
    expect(config).not.toContain("OPERATOR_API_KEY");
    expect((await Bun.file("docs/demo-deployment.md").text())).toContain("maximum daily AI quota of 2");
  });
});
