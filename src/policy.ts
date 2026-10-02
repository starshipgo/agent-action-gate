import type {
  EvaluationResult,
  NormalizationResult,
  NormalizedToolCall,
  PolicyCode,
  SemanticRiskSignals,
} from "./contracts";

export const KNOWN_TOOLS: ReadonlySet<string> = new Set([
  "crm.read_contact",
  "ticket.create",
  "email.draft",
  "email.send",
  "refund.create",
  "customer.export",
  "secret.read",
]);

/** Every currently known tool acts on tenant-owned data or capabilities. */
export const TENANT_SCOPED_TOOLS: ReadonlySet<string> = KNOWN_TOOLS;
export const REFUND_LIMIT_MINOR_UNITS = 50_000;

function result(
  normalized: NormalizedToolCall,
  decision: EvaluationResult["decision"],
  riskLevel: EvaluationResult["risk_level"],
  policyCodes: PolicyCode[],
  requiresApproval: boolean,
): EvaluationResult {
  return {
    decision,
    risk_level: riskLevel,
    policy_codes: policyCodes,
    requires_approval: requiresApproval,
    normalized_tool: normalized.tool_name,
    normalized_args: normalized.args,
  };
}

export function rejectSemanticClassifierFailure(
  normalization: NormalizationResult,
): EvaluationResult {
  return result(
    normalization.normalized,
    "DENY",
    "high",
    ["SEMANTIC_CLASSIFIER_FAILURE"],
    false,
  );
}

/**
 * Rules that are authoritative without consulting the semantic sensor. Keeping
 * these separate lets the Worker avoid spending AI quota on calls that cannot
 * pass the deterministic boundary.
 */
export function applyDeterministicPrechecks(
  normalization: NormalizationResult,
): EvaluationResult | null {
  const normalized = normalization.normalized;

  if (!normalization.parse_ok) {
    return result(
      normalized,
      "DENY",
      "high",
      ["MALFORMED_ARGUMENTS_JSON"],
      false,
    );
  }

  const tool = normalized.tool_name;

  if (!KNOWN_TOOLS.has(tool)) {
    return result(normalized, "DENY", "high", ["UNKNOWN_TOOL"], false);
  }

  if (TENANT_SCOPED_TOOLS.has(tool) && normalized.target_tenant === "") {
    return result(
      normalized,
      "DENY",
      "high",
      ["MISSING_TARGET_TENANT"],
      false,
    );
  }

  if (normalized.request_tenant !== normalized.target_tenant) {
    return result(
      normalized,
      "DENY",
      "critical",
      ["CROSS_TENANT_ACCESS"],
      false,
    );
  }

  if (tool === "secret.read") {
    return result(
      normalized,
      "DENY",
      "critical",
      ["FORBIDDEN_SECRET_ACCESS"],
      false,
    );
  }

  if (tool === "customer.export") {
    return result(
      normalized,
      "DENY",
      "critical",
      ["SENSITIVE_EXPORT"],
      false,
    );
  }

  return null;
}

/**
 * The sole decision authority. Branch order intentionally matches the exported
 * Dify policy node because that order defines precedence when rules conflict.
 */
export function applyPolicy(
  normalization: NormalizationResult,
  semanticRisk: SemanticRiskSignals | null,
): EvaluationResult {
  const normalized = normalization.normalized;
  const precheck = applyDeterministicPrechecks(normalization);

  if (precheck !== null) {
    return precheck;
  }

  if (semanticRisk === null) {
    throw new TypeError("semantic risk is required for a valid tool call");
  }

  const tool = normalized.tool_name;

  const strongSemanticRisk =
    semanticRisk.prompt_injection ||
    semanticRisk.data_exfiltration ||
    semanticRisk.suspicious_instruction;

  if (strongSemanticRisk) {
    const codes: PolicyCode[] = [];

    if (semanticRisk.prompt_injection) {
      codes.push("PROMPT_INJECTION_SIGNAL");
    }
    if (semanticRisk.data_exfiltration) {
      codes.push("DATA_EXFILTRATION_SIGNAL");
    }
    if (semanticRisk.suspicious_instruction) {
      codes.push("SUSPICIOUS_INSTRUCTION");
    }
    if (semanticRisk.social_engineering) {
      codes.push("SOCIAL_ENGINEERING_SIGNAL");
    }

    return result(normalized, "DENY", "high", codes, false);
  }

  if (tool === "email.send") {
    return result(
      normalized,
      "REQUIRE_APPROVAL",
      "medium",
      ["OUTBOUND_SEND"],
      true,
    );
  }

  if (tool === "refund.create") {
    if (
      typeof normalized.amount_minor !== "number" ||
      !Number.isSafeInteger(normalized.amount_minor) ||
      normalized.amount_minor <= 0
    ) {
      return result(
        normalized,
        "DENY",
        "high",
        ["INVALID_REFUND_AMOUNT"],
        false,
      );
    }

    if (normalized.amount_minor > REFUND_LIMIT_MINOR_UNITS) {
      return result(
        normalized,
        "DENY",
        "high",
        ["REFUND_LIMIT_EXCEEDED"],
        false,
      );
    }

    return result(
      normalized,
      "REQUIRE_APPROVAL",
      "medium",
      ["REFUND_REQUIRES_APPROVAL"],
      true,
    );
  }

  if (
    tool === "crm.read_contact" ||
    tool === "ticket.create" ||
    tool === "email.draft"
  ) {
    return result(normalized, "ALLOW", "low", [], false);
  }

  return result(
    normalized,
    "DENY",
    "high",
    ["NO_MATCHING_POLICY"],
    false,
  );
}
