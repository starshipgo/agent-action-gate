import type {
  ActionRequest,
  JsonObject,
  NormalizationResult,
  NormalizedToolCall,
} from "./contracts";

function normalizedText(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

function normalizeAmountMinor(args: JsonObject): number | null {
  const amountMinor = args.amount_minor;

  return typeof amountMinor === "number" && Number.isSafeInteger(amountMinor)
    ? amountMinor
    : null;
}

export function normalizeToolCall(input: ActionRequest): NormalizationResult {
  const base = {
    agent_role: normalizedText(input.agent_role),
    tool_name: normalizedText(input.tool_name),
    request_tenant: normalizedText(input.request_tenant),
  };

  let args: JsonObject = {};

  try {
    const parsed: unknown = JSON.parse(String(input.arguments_json ?? ""));

    if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
      throw new Error("arguments_json must be a JSON object");
    }

    args = parsed as JsonObject;
  } catch (error) {
    const normalized: NormalizedToolCall = {
      ...base,
      target_tenant: "",
      amount_minor: null,
      recipient: "",
      args: {},
    };

    return {
      parse_ok: false,
      parse_error: error instanceof Error ? error.message : String(error),
      normalized,
    };
  }

  const normalized: NormalizedToolCall = {
    ...base,
    target_tenant:
      typeof args.target_tenant === "string"
        ? normalizedText(args.target_tenant)
        : "",
    amount_minor: normalizeAmountMinor(args),
    recipient: typeof args.to === "string" ? normalizedText(args.to) : "",
    args,
  };

  return {
    parse_ok: true,
    parse_error: "",
    normalized,
  };
}
