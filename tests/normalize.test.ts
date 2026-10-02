import { describe, expect, test } from "bun:test";
import type { ActionRequest } from "../src/contracts";
import { normalizeToolCall } from "../src/normalize";

function request(argumentsJson: string): ActionRequest {
  return {
    agent_role: " Support Agent ",
    tool_name: " EMAIL.SEND ",
    arguments_json: argumentsJson,
    source_text: "unused by normalization",
    request_tenant: " Tenant-A ",
  };
}

describe("normalizeToolCall", () => {
  test("normalizes names and extracts fields while preserving raw args", () => {
    const output = normalizeToolCall(
      request(
        JSON.stringify({
          target_tenant: " TENANT-A ",
          amount_minor: 8550,
          to: " PERSON@EXAMPLE.COM ",
          nested: { keep: "Original Case" },
        }),
      ),
    );

    expect(output.parse_ok).toBe(true);
    expect(output.parse_error).toBe("");
    expect(output.normalized).toEqual({
      agent_role: "support agent",
      tool_name: "email.send",
      request_tenant: "tenant-a",
      target_tenant: "tenant-a",
      amount_minor: 8550,
      recipient: "person@example.com",
      args: {
        target_tenant: " TENANT-A ",
        amount_minor: 8550,
        to: " PERSON@EXAMPLE.COM ",
        nested: { keep: "Original Case" },
      },
    });
  });

  const rejectedJson = [
    ["syntax error", "{"],
    ["null", "null"],
    ["array", "[]"],
    ["string", '"value"'],
    ["number", "42"],
    ["boolean", "true"],
  ] as const;

  for (const [label, value] of rejectedJson) {
    test(`rejects ${label} JSON`, () => {
      const output = normalizeToolCall(request(value));

      expect(output.parse_ok).toBe(false);
      expect(output.parse_error.length).toBeGreaterThan(0);
      expect(output.normalized.args).toEqual({});
      expect(output.normalized.amount_minor).toBeNull();
      expect(output.normalized.target_tenant).toBe("");
      expect(output.normalized.recipient).toBe("");
    });
  }

  const amountMinorCases = [
    ["positive integer", 1250, 1250],
    ["zero", 0, 0],
    ["negative integer", -1250, -1250],
    ["maximum safe integer", Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
    ["numeric string", "1250", null],
    ["fractional number", 12.5, null],
    ["unsafe integer", Number.MAX_SAFE_INTEGER + 1, null],
    ["missing value", undefined, null],
  ] as const;

  for (const [label, value, expected] of amountMinorCases) {
    test(`extracts ${label} amount_minor`, () => {
      const args = value === undefined ? {} : { amount_minor: value };
      const output = normalizeToolCall(request(JSON.stringify(args)));

      expect(output.parse_ok).toBe(true);
      expect(output.normalized.amount_minor).toBe(expected);
    });
  }

  test("does not interpret the legacy amount field", () => {
    const output = normalizeToolCall(
      request(JSON.stringify({ amount: 85, target_tenant: "tenant-a" })),
    );

    expect(output.parse_ok).toBe(true);
    expect(output.normalized.amount_minor).toBeNull();
    expect(output.normalized.args.amount).toBe(85);
  });

  test("ignores non-string tenant and recipient fields", () => {
    const output = normalizeToolCall(
      request(JSON.stringify({ target_tenant: 123, to: ["a@example.com"] })),
    );

    expect(output.parse_ok).toBe(true);
    expect(output.normalized.target_tenant).toBe("");
    expect(output.normalized.recipient).toBe("");
    expect(output.normalized.args).toEqual({
      target_tenant: 123,
      to: ["a@example.com"],
    });
  });
});
