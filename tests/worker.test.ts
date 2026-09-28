import { describe, expect, test } from "bun:test";
import type { RawRiskSignals, SemanticRiskContext } from "../src/contracts";
import type { SemanticClassifier } from "../src/classifiers/types";
import { createWorker } from "../src/worker";

const API_KEY = "unit-test-api-key";

const safeRisk: RawRiskSignals = {
  prompt_injection: false,
  data_exfiltration: false,
  social_engineering: false,
  suspicious_instruction: false,
  confidence: "low",
  reason: "Fixture has no semantic risk.",
};

const validBody = {
  agent_role: "support-agent",
  tool_name: "crm.read_contact",
  arguments_json: '{"contact_id":"c-123"}',
  source_text: "Read this contact.",
  request_tenant: "tenant-a",
};

type ClassifierBehavior =
  | RawRiskSignals
  | (() => RawRiskSignals | Promise<RawRiskSignals>);

class FakeClassifier implements SemanticClassifier {
  calls = 0;

  constructor(private readonly behavior: ClassifierBehavior = safeRisk) {}

  async classify(_context: SemanticRiskContext): Promise<RawRiskSignals> {
    this.calls += 1;
    return typeof this.behavior === "function"
      ? this.behavior()
      : this.behavior;
  }
}

function environment(): Env {
  return {
    GATE_API_KEY: API_KEY,
    AI: {} as Ai,
  };
}

function request(
  body: unknown = validBody,
  authorization: string | null = `Bearer ${API_KEY}`,
): Request {
  const headers = new Headers({ "content-type": "application/json" });
  if (authorization !== null) {
    headers.set("authorization", authorization);
  }

  return new Request("https://gate.example/v1/evaluate", {
    method: "POST",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function workerFor(classifier: SemanticClassifier) {
  return createWorker({ createClassifier: () => classifier });
}

async function body(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

function expectDecisionContract(output: Record<string, unknown>): void {
  expect(Object.keys(output).sort()).toEqual(
    [
      "decision",
      "normalized_args",
      "normalized_tool",
      "policy_codes",
      "requires_approval",
      "risk_level",
    ].sort(),
  );
}

describe("Cloudflare Worker API", () => {
  test("GET /health is public", async () => {
    const classifier = new FakeClassifier();
    const response = await workerFor(classifier).fetch(
      new Request("https://gate.example/health"),
      environment(),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      status: "ok",
      service: "agent-action-gate",
    });
    expect(classifier.calls).toBe(0);
  });

  test("evaluate without authorization returns 401", async () => {
    const classifier = new FakeClassifier();
    const response = await workerFor(classifier).fetch(
      request(validBody, null),
      environment(),
    );

    expect(response.status).toBe(401);
    expect(await body(response)).toEqual({ error: "UNAUTHORIZED" });
    expect(classifier.calls).toBe(0);
  });

  test("evaluate with an incorrect key returns 401", async () => {
    const classifier = new FakeClassifier();
    const response = await workerFor(classifier).fetch(
      request(validBody, "Bearer wrong-key"),
      environment(),
    );

    expect(response.status).toBe(401);
    expect(JSON.stringify(await body(response))).not.toContain(API_KEY);
    expect(classifier.calls).toBe(0);
  });

  test("malformed HTTP JSON returns 400", async () => {
    const classifier = new FakeClassifier();
    const response = await workerFor(classifier).fetch(
      request("{"),
      environment(),
    );

    expect(response.status).toBe(400);
    expect(await body(response)).toEqual({ error: "INVALID_JSON" });
    expect(classifier.calls).toBe(0);
  });

  test("missing required fields return 400", async () => {
    const classifier = new FakeClassifier();
    const { request_tenant: _, ...missingTenant } = validBody;
    const response = await workerFor(classifier).fetch(
      request(missingTenant),
      environment(),
    );

    expect(response.status).toBe(400);
    expect(await body(response)).toMatchObject({ error: "INVALID_REQUEST" });
    expect(classifier.calls).toBe(0);
  });

  test("oversized source_text returns 400", async () => {
    const classifier = new FakeClassifier();
    const response = await workerFor(classifier).fetch(
      request({ ...validBody, source_text: "x".repeat(4097) }),
      environment(),
    );

    expect(response.status).toBe(400);
    expect(classifier.calls).toBe(0);
  });

  test("oversized raw HTTP bodies are rejected before parsing", async () => {
    const classifier = new FakeClassifier();
    const response = await workerFor(classifier).fetch(
      request({ ...validBody, padding: "x".repeat(70_000) }),
      environment(),
    );

    expect(response.status).toBe(400);
    expect(await body(response)).toEqual({ error: "REQUEST_BODY_TOO_LARGE" });
    expect(classifier.calls).toBe(0);
  });

  test("malformed arguments JSON returns a denial without classification", async () => {
    const classifier = new FakeClassifier(() => {
      throw new Error("must not run");
    });
    const response = await workerFor(classifier).fetch(
      request({ ...validBody, tool_name: " EMAIL.SEND ", arguments_json: "{" }),
      environment(),
    );
    const output = await body(response);

    expect(response.status).toBe(200);
    expect(output).toEqual({
      decision: "DENY",
      risk_level: "high",
      policy_codes: ["MALFORMED_ARGUMENTS_JSON"],
      requires_approval: false,
      normalized_tool: "email.send",
      normalized_args: {},
    });
    expect(classifier.calls).toBe(0);
  });

  test("benign crm.read_contact is allowed with a valid key", async () => {
    const classifier = new FakeClassifier();
    const response = await workerFor(classifier).fetch(
      request(),
      environment(),
    );
    const output = await body(response);

    expect(response.status).toBe(200);
    expect(output).toMatchObject({
      decision: "ALLOW",
      risk_level: "low",
      policy_codes: [],
      requires_approval: false,
    });
    expectDecisionContract(output);
    expect(classifier.calls).toBe(1);
  });

  test("benign email.send requires approval", async () => {
    const classifier = new FakeClassifier();
    const response = await workerFor(classifier).fetch(
      request({ ...validBody, tool_name: "email.send" }),
      environment(),
    );

    expect(await body(response)).toMatchObject({
      decision: "REQUIRE_APPROVAL",
      risk_level: "medium",
      policy_codes: ["OUTBOUND_SEND"],
      requires_approval: true,
    });
  });

  test("injection and exfiltration signals deny email.send", async () => {
    const classifier = new FakeClassifier({
      ...safeRisk,
      prompt_injection: true,
      data_exfiltration: true,
      confidence: "high",
      reason: "fixture",
    });
    const response = await workerFor(classifier).fetch(
      request({ ...validBody, tool_name: "email.send" }),
      environment(),
    );

    expect(await body(response)).toMatchObject({
      decision: "DENY",
      policy_codes: [
        "PROMPT_INJECTION_SIGNAL",
        "DATA_EXFILTRATION_SIGNAL",
      ],
      requires_approval: false,
    });
  });

  test("classifier exceptions fail closed", async () => {
    const classifier = new FakeClassifier(() => {
      throw new Error("provider failure");
    });
    const response = await workerFor(classifier).fetch(
      request(),
      environment(),
    );
    const output = await body(response);

    expect(response.status).toBe(200);
    expect(output).toEqual({
      decision: "DENY",
      risk_level: "high",
      policy_codes: ["SEMANTIC_CLASSIFIER_FAILURE"],
      requires_approval: false,
      normalized_tool: "crm.read_contact",
      normalized_args: { contact_id: "c-123" },
    });
  });

  test("malformed classifier output fails closed", async () => {
    const classifier = new FakeClassifier(
      { prompt_injection: false } as RawRiskSignals,
    );
    const response = await workerFor(classifier).fetch(
      request(),
      environment(),
    );

    expect(await body(response)).toMatchObject({
      decision: "DENY",
      policy_codes: ["SEMANTIC_CLASSIFIER_FAILURE"],
    });
  });

  test('the string "true" remains protected through HTTP', async () => {
    const classifier = new FakeClassifier({
      ...safeRisk,
      prompt_injection: "true",
      data_exfiltration: "false",
      social_engineering: "false",
      suspicious_instruction: "false",
    });
    const response = await workerFor(classifier).fetch(
      request(),
      environment(),
    );

    expect(await body(response)).toMatchObject({
      decision: "DENY",
      policy_codes: ["PROMPT_INJECTION_SIGNAL"],
    });
  });

  for (const amount of [0, -1, -500]) {
    test(`refund amount ${amount} is denied`, async () => {
      const classifier = new FakeClassifier();
      const response = await workerFor(classifier).fetch(
        request({
          ...validBody,
          tool_name: "refund.create",
          arguments_json: JSON.stringify({ amount }),
        }),
        environment(),
      );

      expect(await body(response)).toMatchObject({
        decision: "DENY",
        risk_level: "high",
        policy_codes: ["INVALID_REFUND_AMOUNT"],
        requires_approval: false,
      });
    });
  }
});
