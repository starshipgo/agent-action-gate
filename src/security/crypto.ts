import type {
  EvaluationResult,
  JsonObject,
  JsonValue,
  NormalizedToolCall,
} from "../contracts";
import { isValidPolicyVersion, POLICY_VERSION } from "../policy-metadata";

const encoder = new TextEncoder();

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));

  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

interface CanonicalEvaluationRequest {
  agent_role: string;
  tool_name: string;
  arguments_json: string;
  source_text: string;
  request_tenant?: string;
}

/** Fixed field order prevents JSON property insertion order from affecting replay. */
export async function hashEvaluationRequest(
  request: CanonicalEvaluationRequest,
  trustedTenant: string,
  policyVersion: string = POLICY_VERSION,
): Promise<string> {
  if (!isValidPolicyVersion(policyVersion)) {
    throw new TypeError("invalid policy version");
  }

  return sha256Hex(
    JSON.stringify({
      contract: "agent-action-gate.evaluate.v2",
      policy_version: policyVersion,
      trusted_tenant: trustedTenant,
      agent_role: request.agent_role,
      tool_name: request.tool_name,
      arguments_json: request.arguments_json,
      source_text: request.source_text,
      request_tenant: request.request_tenant ?? null,
    }),
  );
}

/**
 * RFC-8259-compatible canonical JSON for the values accepted by this project.
 * Object keys are sorted recursively; array order remains significant.
 */
export function canonicalJson(value: JsonValue, depth = 0): string {
  if (depth > 64) {
    throw new TypeError("JSON nesting exceeds canonicalization limit");
  }

  if (typeof value === "number") {
    // This function hashes every transport-valid JSON object, including one
    // that policy will reject for an unsafe integer. JSON itself is represented
    // as finite IEEE-754 numbers here; safe-integer authorization belongs to
    // the deterministic policy layer, not to audit canonicalization.
    if (!Number.isFinite(value)) {
      throw new TypeError("non-finite JSON number cannot be canonicalized");
    }
  }

  if (value === null || typeof value !== "object") {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) {
      throw new TypeError("value is not JSON serializable");
    }
    return serialized;
  }

  if (Array.isArray(value)) {
    return `[${value
      .map((entry) => canonicalJson(entry, depth + 1))
      .join(",")}]`;
  }

  return `{${Object.keys(value)
    .sort()
    .map(
      (key) =>
        `${JSON.stringify(key)}:${canonicalJson(
          value[key] as JsonValue,
          depth + 1,
        )}`,
    )
    .join(",")}}`;
}

export async function hashNormalizedArguments(args: JsonObject): Promise<string> {
  return sha256Hex(`normalized-json-v1:${canonicalJson(args)}`);
}

/** Malformed input is kept distinct from a valid empty normalized object. */
export async function hashMalformedArguments(raw: string): Promise<string> {
  return sha256Hex(`malformed-json-v1:${raw}`);
}

export interface ApprovalHashInput {
  principal_id: string;
  trusted_tenant_id: string;
  normalized: Pick<
    NormalizedToolCall,
    "agent_role" | "tool_name" | "args"
  >;
  source_text: string;
  policy: Pick<
    EvaluationResult,
    "decision" | "risk_level" | "policy_codes" | "requires_approval"
  >;
  policy_version?: string;
}

function assertApprovalJsonSafety(value: JsonValue, depth = 0): void {
  if (depth > 64) {
    throw new TypeError("approval JSON nesting exceeds limit");
  }
  if (
    typeof value === "number" &&
    (!Number.isFinite(value) ||
      (Number.isInteger(value) && !Number.isSafeInteger(value)))
  ) {
    throw new TypeError("approval JSON contains an unsafe number");
  }
  if (Array.isArray(value)) {
    for (const entry of value) assertApprovalJsonSafety(entry, depth + 1);
  } else if (value !== null && typeof value === "object") {
    for (const entry of Object.values(value)) {
      assertApprovalJsonSafety(entry, depth + 1);
    }
  }
}

/**
 * Binds an approval to the authenticated actor, normalized action, original
 * source-text digest, and the exact policy result without persisting raw input.
 */
export async function hashApprovalRequest(
  input: ApprovalHashInput,
): Promise<string> {
  // Approval equality must not rely on lossy JavaScript integer parsing.
  assertApprovalJsonSafety(input.normalized.args);
  const policyVersion = input.policy_version ?? POLICY_VERSION;
  if (!isValidPolicyVersion(policyVersion)) {
    throw new TypeError("invalid policy version");
  }
  const sourceTextHash = await sha256Hex(input.source_text);

  return sha256Hex(
    canonicalJson({
      contract: "agent-action-gate.approval.v2",
      policy_version: policyVersion,
      principal_id: input.principal_id,
      trusted_tenant_id: input.trusted_tenant_id,
      agent_role: input.normalized.agent_role,
      tool_name: input.normalized.tool_name,
      normalized_args: input.normalized.args,
      source_text_hash: sourceTextHash,
      policy: {
        decision: input.policy.decision,
        risk_level: input.policy.risk_level,
        policy_codes: input.policy.policy_codes,
        requires_approval: input.policy.requires_approval,
      },
    }),
  );
}
