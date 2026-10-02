import { describe, expect, test } from "bun:test";
import { validateEvaluationRequest } from "../src/http/validate-request";

const validRequest = {
  agent_role: "support-agent",
  tool_name: "crm.read_contact",
  arguments_json: "{}",
  source_text: "Read the contact.",
  request_tenant: "tenant-a",
};

describe("validateEvaluationRequest", () => {
  for (const value of [null, [], "body", 42]) {
    test(`rejects non-object body ${JSON.stringify(value)}`, () => {
      expect(validateEvaluationRequest(value).ok).toBe(false);
    });
  }

  for (const field of [
    "agent_role",
    "tool_name",
    "arguments_json",
    "source_text",
  ] as const) {
    test(`rejects missing ${field}`, () => {
      const body: Record<string, unknown> = { ...validRequest };
      delete body[field];

      expect(validateEvaluationRequest(body).ok).toBe(false);
    });
  }

  test("accepts an omitted request_tenant for backwards compatibility", () => {
    const { request_tenant: _omitted, ...body } = validRequest;
    const output = validateEvaluationRequest(body);

    expect(output).toEqual({ ok: true, value: body });
  });

  test("rejects unknown fields", () => {
    expect(
      validateEvaluationRequest({ ...validRequest, unexpected: true }).ok,
    ).toBe(false);
  });

  for (const field of ["agent_role", "tool_name", "request_tenant"] as const) {
    test(`rejects whitespace-only ${field}`, () => {
      expect(
        validateEvaluationRequest({ ...validRequest, [field]: "   " }).ok,
      ).toBe(false);
    });
  }

  const limits = {
    agent_role: 128,
    tool_name: 256,
    arguments_json: 4096,
    source_text: 4096,
    request_tenant: 256,
  } as const;

  for (const [field, limit] of Object.entries(limits)) {
    test(`${field} accepts its exact limit and rejects limit + 1`, () => {
      expect(
        validateEvaluationRequest({
          ...validRequest,
          [field]: "x".repeat(limit),
        }).ok,
      ).toBe(true);
      expect(
        validateEvaluationRequest({
          ...validRequest,
          [field]: "x".repeat(limit + 1),
        }).ok,
      ).toBe(false);
    });
  }

  test("allows empty source_text and arguments_json at the transport layer", () => {
    const output = validateEvaluationRequest({
      ...validRequest,
      source_text: "",
      arguments_json: "",
    });

    expect(output.ok).toBe(true);
  });
});
