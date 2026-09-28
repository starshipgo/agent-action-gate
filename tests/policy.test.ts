import { describe, expect, test } from "bun:test";
import type {
  ActionRequest,
  RawSemanticRisk,
  SemanticRiskSignals,
} from "../src/contracts";
import { normalizeToolCall } from "../src/normalize";
import { applyPolicy } from "../src/policy";
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
) {
  const input: ActionRequest = {
    agent_role: "test-agent",
    tool_name: toolName,
    arguments_json: JSON.stringify(args),
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
    [500, "REQUIRE_APPROVAL", "REFUND_REQUIRES_APPROVAL"],
    [500.01, "DENY", "REFUND_LIMIT_EXCEEDED"],
  ] as const;

  for (const [amount, decision, code] of refundCases) {
    test(`applies the refund boundary for ${amount}`, () => {
      const output = applyPolicy(
        normalized("refund.create", { amount }),
        noRisk,
      );

      expect(output.decision).toBe(decision);
      expect(output.policy_codes).toEqual([code]);
    });
  }

  test("missing refund amount fails closed", () => {
    const output = applyPolicy(normalized("refund.create"), noRisk);

    expect(output).toMatchObject({
      decision: "DENY",
      risk_level: "high",
      policy_codes: ["INVALID_REFUND_AMOUNT"],
      requires_approval: false,
    });
  });

  test("cross-tenant rule needs both tenant values", () => {
    const missingRequest = applyPolicy(
      normalized("crm.read_contact", { target_tenant: "tenant-b" }, ""),
      noRisk,
    );
    const missingTarget = applyPolicy(
      normalized("crm.read_contact", {}, "tenant-a"),
      noRisk,
    );

    expect(missingRequest.decision).toBe("ALLOW");
    expect(missingTarget.decision).toBe("ALLOW");
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
