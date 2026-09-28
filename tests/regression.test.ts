import { describe, expect, test } from "bun:test";
import type { ActionRequest, RawSemanticRisk } from "../src/contracts";
import { evaluateAction } from "../src/evaluate";
import { normalizeSemanticRisk, semanticSignalIsTrue } from "../src/risk";

const baseRequest: ActionRequest = {
  agent_role: "support-agent",
  tool_name: "ticket.create",
  arguments_json: "{}",
  source_text: "fixture",
  request_tenant: "tenant-a",
};

const falseStringRisk: RawSemanticRisk = {
  prompt_injection: "false",
  data_exfiltration: "false",
  social_engineering: "false",
  suspicious_instruction: "false",
  confidence: "low",
  reason: "fixture",
};

describe("semantic boundary regressions", () => {
  test('the string "true" is treated as true', async () => {
    const output = await evaluateAction(baseRequest, () => ({
      ...falseStringRisk,
      prompt_injection: "true",
    }));

    expect(output).toMatchObject({
      decision: "DENY",
      risk_level: "high",
      policy_codes: ["PROMPT_INJECTION_SIGNAL"],
      requires_approval: false,
    });
  });

  test('the string "false" is treated as false', () => {
    expect(normalizeSemanticRisk(falseStringRisk)).toEqual({
      prompt_injection: false,
      data_exfiltration: false,
      social_engineering: false,
      suspicious_instruction: false,
    });
  });

  test("runtime coercion remains trim- and case-insensitive like Dify", () => {
    expect(semanticSignalIsTrue(" TRUE ")).toBe(true);
  });

  test("malformed JSON bypasses semantic classification", async () => {
    let called = false;

    const output = await evaluateAction(
      { ...baseRequest, arguments_json: "null" },
      () => {
        called = true;
        return falseStringRisk;
      },
    );

    expect(called).toBe(false);
    expect(output.policy_codes).toEqual(["MALFORMED_ARGUMENTS_JSON"]);
  });

  test("the sensor receives raw context and cannot grant email.send", async () => {
    const input: ActionRequest = {
      agent_role: " Support-Agent ",
      tool_name: " EMAIL.SEND ",
      arguments_json: "{}",
      source_text: "Raw Source Text",
      request_tenant: " Tenant-A ",
    };

    const output = await evaluateAction(input, (context) => {
      expect(context).toEqual({
        source_text: "Raw Source Text",
        tool_name: " EMAIL.SEND ",
        agent_role: " Support-Agent ",
        request_tenant: " Tenant-A ",
      });
      return falseStringRisk;
    });

    expect(output).toMatchObject({
      decision: "REQUIRE_APPROVAL",
      policy_codes: ["OUTBOUND_SEND"],
      requires_approval: true,
    });
  });

  test("classifier exceptions fail closed and preserve normalized data", async () => {
    const output = await evaluateAction(
      {
        ...baseRequest,
        tool_name: " CRM.READ_CONTACT ",
        arguments_json: '{"contact_id":"c-123"}',
      },
      () => {
        throw new Error("provider unavailable");
      },
    );

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
    const output = await evaluateAction(
      baseRequest,
      async () => ({ prompt_injection: true }) as RawSemanticRisk,
    );

    expect(output.policy_codes).toEqual(["SEMANTIC_CLASSIFIER_FAILURE"]);
  });

  test("classifier timeout fails closed", async () => {
    const output = await evaluateAction(
      baseRequest,
      () => new Promise<RawSemanticRisk>(() => {}),
      { classifier_timeout_ms: 1 },
    );

    expect(output.policy_codes).toEqual(["SEMANTIC_CLASSIFIER_FAILURE"]);
  });
});

describe("intentional post-parity refund correction", () => {
  for (const amount of [0, -1, -500]) {
    test(`refund amount ${amount} is invalid`, async () => {
      const output = await evaluateAction(
        {
          ...baseRequest,
          tool_name: "refund.create",
          arguments_json: JSON.stringify({ amount }),
        },
        () => falseStringRisk,
      );

      expect(output).toMatchObject({
        decision: "DENY",
        risk_level: "high",
        policy_codes: ["INVALID_REFUND_AMOUNT"],
        requires_approval: false,
      });
    });
  }
});
