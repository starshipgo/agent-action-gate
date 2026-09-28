import type {
  RawRiskSignals,
  RawSemanticSignal,
  SemanticRiskSignals,
} from "./contracts";

const SIGNAL_FIELDS = [
  "prompt_injection",
  "data_exfiltration",
  "social_engineering",
  "suspicious_instruction",
] as const;

const RISK_FIELDS = new Set<string>([
  ...SIGNAL_FIELDS,
  "confidence",
  "reason",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseSemanticSignal(value: unknown): RawSemanticSignal {
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();

    if (normalized === "true" || normalized === "false") {
      return normalized;
    }
  }

  throw new TypeError("semantic risk signal must be a boolean or true/false string");
}

/** Strict runtime validation for the untrusted model-output boundary. */
export function parseRawRiskSignals(value: unknown): RawRiskSignals {
  if (!isRecord(value)) {
    throw new TypeError("semantic classifier output must be an object");
  }

  if (Object.keys(value).some((key) => !RISK_FIELDS.has(key))) {
    throw new TypeError("semantic classifier output contains unknown fields");
  }

  for (const field of RISK_FIELDS) {
    if (!Object.hasOwn(value, field)) {
      throw new TypeError(`semantic classifier output is missing ${field}`);
    }
  }

  const confidence = value.confidence;
  if (
    confidence !== "low" &&
    confidence !== "medium" &&
    confidence !== "high"
  ) {
    throw new TypeError("semantic classifier confidence is invalid");
  }

  if (typeof value.reason !== "string") {
    throw new TypeError("semantic classifier reason must be a string");
  }

  return {
    prompt_injection: parseSemanticSignal(value.prompt_injection),
    data_exfiltration: parseSemanticSignal(value.data_exfiltration),
    social_engineering: parseSemanticSignal(value.social_engineering),
    suspicious_instruction: parseSemanticSignal(value.suspicious_instruction),
    confidence,
    reason: value.reason,
  };
}

/** Mirrors the prototype's defensive runtime conversion. */
export function semanticSignalIsTrue(value: unknown): boolean {
  if (value === true) {
    return true;
  }

  return typeof value === "string" && value.trim().toLowerCase() === "true";
}

export function normalizeSemanticRisk(
  value: unknown,
): SemanticRiskSignals {
  const risk = parseRawRiskSignals(value);

  return {
    prompt_injection: semanticSignalIsTrue(risk.prompt_injection),
    data_exfiltration: semanticSignalIsTrue(risk.data_exfiltration),
    social_engineering: semanticSignalIsTrue(risk.social_engineering),
    suspicious_instruction: semanticSignalIsTrue(risk.suspicious_instruction),
  };
}
