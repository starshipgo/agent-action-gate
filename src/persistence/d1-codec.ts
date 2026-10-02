import type { PolicyCode } from "../contracts";
import { isValidPolicyVersion } from "../policy-metadata";

const POLICY_CODES = new Set<PolicyCode>([
  "UNKNOWN_TOOL",
  "MISSING_TARGET_TENANT",
  "CROSS_TENANT_ACCESS",
  "FORBIDDEN_SECRET_ACCESS",
  "SENSITIVE_EXPORT",
  "PROMPT_INJECTION_SIGNAL",
  "DATA_EXFILTRATION_SIGNAL",
  "SUSPICIOUS_INSTRUCTION",
  "SOCIAL_ENGINEERING_SIGNAL",
  "OUTBOUND_SEND",
  "INVALID_REFUND_AMOUNT",
  "REFUND_LIMIT_EXCEEDED",
  "REFUND_REQUIRES_APPROVAL",
  "NO_MATCHING_POLICY",
  "MALFORMED_ARGUMENTS_JSON",
  "SEMANTIC_CLASSIFIER_FAILURE",
]);

export function requiredString(
  row: Record<string, unknown>,
  field: string,
): string {
  const value = row[field];

  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`invalid D1 ${field}`);
  }

  return value;
}

export function nullableString(
  row: Record<string, unknown>,
  field: string,
): string | null {
  const value = row[field];

  if (value === null) {
    return null;
  }

  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`invalid D1 ${field}`);
  }

  return value;
}

export function requiredInteger(
  row: Record<string, unknown>,
  field: string,
): number {
  const value = row[field];

  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`invalid D1 ${field}`);
  }

  return value;
}

export function nullableInteger(
  row: Record<string, unknown>,
  field: string,
): number | null {
  const value = row[field];

  if (value === null) {
    return null;
  }

  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`invalid D1 ${field}`);
  }

  return value;
}

export function parsePolicyCodes(value: unknown): PolicyCode[] {
  if (typeof value !== "string") {
    throw new TypeError("invalid D1 policy_codes_json");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new TypeError("invalid D1 policy_codes_json");
  }

  if (
    !Array.isArray(parsed) ||
    parsed.some(
      (code) => typeof code !== "string" || !POLICY_CODES.has(code as PolicyCode),
    )
  ) {
    throw new TypeError("invalid D1 policy_codes_json");
  }

  return parsed as PolicyCode[];
}

export function queryLimit(value: number | undefined): number {
  if (value === undefined) {
    return 50;
  }

  if (!Number.isSafeInteger(value) || value < 1 || value > 100) {
    throw new RangeError("query limit must be an integer from 1 through 100");
  }

  return value;
}

export function parsePolicyVersion(value: unknown): string {
  if (!isValidPolicyVersion(value)) {
    throw new TypeError("invalid D1 policy_version");
  }

  return value;
}

export function queryUnixSecond(
  value: number | undefined,
  field: string,
): number | undefined {
  if (value === undefined) return undefined;

  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${field} must be a non-negative integer`);
  }

  return value;
}
