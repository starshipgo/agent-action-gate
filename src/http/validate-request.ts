export interface IncomingEvaluationRequest {
  agent_role: string;
  tool_name: string;
  arguments_json: string;
  source_text: string;
  request_tenant?: string;
}

const REQUEST_FIELDS = [
  "agent_role",
  "tool_name",
  "arguments_json",
  "source_text",
  "request_tenant",
] as const;

const REQUEST_FIELD_SET = new Set<string>(REQUEST_FIELDS);

const MAX_LENGTHS: Record<(typeof REQUEST_FIELDS)[number], number> = {
  agent_role: 128,
  tool_name: 256,
  arguments_json: 4096,
  source_text: 4096,
  request_tenant: 256,
};

const NON_EMPTY_FIELDS = new Set<string>([
  "agent_role",
  "tool_name",
  "request_tenant",
]);

export type RequestValidationResult =
  | { ok: true; value: IncomingEvaluationRequest }
  | { ok: false; errors: string[] };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validateEvaluationRequest(
  value: unknown,
): RequestValidationResult {
  if (!isRecord(value)) {
    return { ok: false, errors: ["body must be a JSON object"] };
  }

  const errors: string[] = [];

  for (const key of Object.keys(value)) {
    if (!REQUEST_FIELD_SET.has(key)) {
      errors.push(`unknown field: ${key}`);
    }
  }

  for (const field of REQUEST_FIELDS) {
    const fieldValue = value[field];

    if (field === "request_tenant" && fieldValue === undefined) {
      continue;
    }

    if (typeof fieldValue !== "string") {
      errors.push(`${field} is required and must be a string`);
      continue;
    }

    if (NON_EMPTY_FIELDS.has(field) && fieldValue.trim() === "") {
      errors.push(`${field} must not be empty`);
    }

    if (fieldValue.length > MAX_LENGTHS[field]) {
      errors.push(`${field} must be at most ${MAX_LENGTHS[field]} characters`);
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  const request: IncomingEvaluationRequest = {
    agent_role: value.agent_role as string,
    tool_name: value.tool_name as string,
    arguments_json: value.arguments_json as string,
    source_text: value.source_text as string,
  };

  if (typeof value.request_tenant === "string") {
    request.request_tenant = value.request_tenant;
  }

  return {
    ok: true,
    value: request,
  };
}
