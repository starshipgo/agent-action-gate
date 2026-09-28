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
 * The sole decision authority. Branch order intentionally matches the exported
 * Dify policy node because that order defines precedence when rules conflict.
 */
export function applyPolicy(
  normalization: NormalizationResult,
  semanticRisk: SemanticRiskSignals | null,
): EvaluationResult {
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

  if (semanticRisk === null) {
    throw new TypeError("semantic risk is required for a valid tool call");
  }

  const tool = normalized.tool_name;

  if (!KNOWN_TOOLS.has(tool)) {
    return result(normalized, "DENY", "high", ["UNKNOWN_TOOL"], false);
  }

  if (
    normalized.request_tenant &&
    normalized.target_tenant &&
    normalized.request_tenant !== normalized.target_tenant
  ) {
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
      typeof normalized.amount !== "number" ||
      !Number.isFinite(normalized.amount) ||
      normalized.amount <= 0
    ) {
      return result(
        normalized,
        "DENY",
        "high",
        ["INVALID_REFUND_AMOUNT"],
        false,
      );
    }

    if (normalized.amount > 500) {
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
