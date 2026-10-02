import { describe, expect, test } from "bun:test";
import type {
  ActionRequest,
  RawSemanticRisk,
  SemanticRiskSignals,
} from "../src/contracts";
import { normalizeToolCall } from "../src/normalize";
import { applyPolicy, KNOWN_TOOLS } from "../src/policy";
import { normalizeSemanticRisk } from "../src/risk";

const noRisk: SemanticRiskSignals = {
  prompt_injection: false,
  data_exfiltration: false,
  social_engineering: false,
  suspicious_instruction: false,
};

function normalized(
  toolName: string,
  args: Record<string, unknown> = {},
  requestTenant = "tenant-a",
  includeTargetTenant = true,
) {
  const scopedArgs = includeTargetTenant
    ? { target_tenant: requestTenant, ...args }
    : args;
  const input: ActionRequest = {
    agent_role: "test-agent",
    tool_name: toolName,
    arguments_json: JSON.stringify(scopedArgs),
    source_text: "fixture",
    request_tenant: requestTenant,
  };

  return normalizeToolCall(input);
}

describe("applyPolicy", () => {
  test("emits semantic codes in prototype order", () => {
    const risk: RawSemanticRisk = {
      prompt_injection: true,
      data_exfiltration: true,
      suspicious_instruction: true,
      social_engineering: true,
      confidence: "high",
      reason: "fixture",
    };

    const output = applyPolicy(
      normalized("email.send"),
      normalizeSemanticRisk(risk),
    );

    expect(output).toMatchObject({
      decision: "DENY",
      risk_level: "high",
      policy_codes: [
        "PROMPT_INJECTION_SIGNAL",
        "DATA_EXFILTRATION_SIGNAL",
        "SUSPICIOUS_INSTRUCTION",
        "SOCIAL_ENGINEERING_SIGNAL",
      ],
      requires_approval: false,
    });
  });

  test("social engineering alone does not deny", () => {
    const output = applyPolicy(normalized("crm.read_contact"), {
      ...noRisk,
      social_engineering: true,
    });

    expect(output.decision).toBe("ALLOW");
    expect(output.policy_codes).toEqual([]);
  });

  test("unknown tool has precedence over cross-tenant and semantic risk", () => {
    const output = applyPolicy(
      normalized("unknown.tool", { target_tenant: "tenant-b" }),
      {
        ...noRisk,
        prompt_injection: true,
      },
    );

    expect(output.policy_codes).toEqual(["UNKNOWN_TOOL"]);
  });

  test("cross-tenant has precedence over forbidden-tool and semantic rules", () => {
    const output = applyPolicy(
      normalized("secret.read", { target_tenant: "tenant-b" }),
      {
        ...noRisk,
        data_exfiltration: true,
      },
    );

    expect(output.policy_codes).toEqual(["CROSS_TENANT_ACCESS"]);
  });

  test("forbidden tools have precedence over semantic rules", () => {
    const output = applyPolicy(normalized("customer.export"), {
      ...noRisk,
      data_exfiltration: true,
    });

    expect(output.policy_codes).toEqual(["SENSITIVE_EXPORT"]);
  });

  test("semantic denial has precedence over normal email approval", () => {
    const output = applyPolicy(normalized("email.send"), {
      ...noRisk,
      suspicious_instruction: true,
    });

    expect(output.policy_codes).toEqual(["SUSPICIOUS_INSTRUCTION"]);
    expect(output.requires_approval).toBe(false);
  });

  const refundCases = [
    [50_000, "REQUIRE_APPROVAL", "REFUND_REQUIRES_APPROVAL"],
    [50_001, "DENY", "REFUND_LIMIT_EXCEEDED"],
  ] as const;

  for (const [amountMinor, decision, code] of refundCases) {
    test(`applies the refund boundary for ${amountMinor} minor units`, () => {
      const output = applyPolicy(
        normalized("refund.create", { amount_minor: amountMinor }),
        noRisk,
      );

      expect(output.decision).toBe(decision);
      expect(output.policy_codes).toEqual([code]);
    });
  }

  const invalidRefundArgs: Array<[string, Record<string, unknown>]> = [
    ["missing amount_minor", {}],
    ["legacy amount", { amount: 85 }],
    ["numeric-string amount_minor", { amount_minor: "8500" }],
    ["zero amount_minor", { amount_minor: 0 }],
    ["negative amount_minor", { amount_minor: -1 }],
    ["fractional amount_minor", { amount_minor: 8500.5 }],
    ["unsafe amount_minor", { amount_minor: Number.MAX_SAFE_INTEGER + 1 }],
  ];

  for (const [label, args] of invalidRefundArgs) {
    test(`${label} fails closed`, () => {
      const output = applyPolicy(normalized("refund.create", args), noRisk);

      expect(output).toMatchObject({
        decision: "DENY",
        risk_level: "high",
        policy_codes: ["INVALID_REFUND_AMOUNT"],
        requires_approval: false,
      });
    });
  }

  for (const tool of KNOWN_TOOLS) {
    test(`${tool} requires a nonempty target tenant`, () => {
      const output = applyPolicy(normalized(tool, {}, "tenant-a", false), noRisk);

      expect(output).toMatchObject({
        decision: "DENY",
        risk_level: "high",
        policy_codes: ["MISSING_TARGET_TENANT"],
        requires_approval: false,
      });
    });
  }

  test("a non-string target tenant is treated as missing", () => {
    const output = applyPolicy(
      normalized("crm.read_contact", { target_tenant: 123 }),
      noRisk,
    );

    expect(output.policy_codes).toEqual(["MISSING_TARGET_TENANT"]);
  });

  test("a known tool cannot cross the trusted tenant boundary", () => {
    const output = applyPolicy(
      normalized("crm.read_contact", { target_tenant: "tenant-b" }),
      noRisk,
    );

    expect(output).toMatchObject({
      decision: "DENY",
      risk_level: "critical",
      policy_codes: ["CROSS_TENANT_ACCESS"],
      requires_approval: false,
    });
  });

  test("malformed normalization is denied without semantic risk", () => {
    const malformed = normalizeToolCall({
      agent_role: "test-agent",
      tool_name: " email.send ",
      arguments_json: "[]",
      source_text: "fixture",
      request_tenant: "tenant-a",
    });

    expect(applyPolicy(malformed, null)).toEqual({
      decision: "DENY",
      risk_level: "high",
      policy_codes: ["MALFORMED_ARGUMENTS_JSON"],
      requires_approval: false,
      normalized_tool: "email.send",
      normalized_args: {},
    });
  });
});
