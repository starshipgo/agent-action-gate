const POLICY_LABELS: Readonly<Record<string, string>> = {
  MALFORMED_ARGUMENTS_JSON: "Malformed tool arguments",
  UNKNOWN_TOOL: "Unknown tool blocked",
  MISSING_TARGET_TENANT: "Target tenant is required",
  CROSS_TENANT_ACCESS: "Cross-tenant access blocked",
  FORBIDDEN_SECRET_ACCESS: "Secret access blocked",
  SENSITIVE_EXPORT: "Sensitive customer export blocked",
  PROMPT_INJECTION_SIGNAL: "Prompt injection detected",
  DATA_EXFILTRATION_SIGNAL: "Possible data exfiltration",
  SUSPICIOUS_INSTRUCTION: "Suspicious instruction detected",
  SOCIAL_ENGINEERING_SIGNAL: "Possible social engineering",
  OUTBOUND_SEND: "Outbound send requires approval",
  INVALID_REFUND_AMOUNT: "Invalid refund amount",
  REFUND_LIMIT_EXCEEDED: "Refund limit exceeded",
  REFUND_REQUIRES_APPROVAL: "Refund requires approval",
  NO_MATCHING_POLICY: "No matching policy",
  SEMANTIC_CLASSIFIER_FAILURE: "Security classifier unavailable",
};

export function policyLabel(code: string): string {
  return POLICY_LABELS[code] ?? code.replaceAll("_", " ").toLowerCase();
}

export function decisionLabel(decision: string | null): string {
  switch (decision) {
    case "ALLOW":
      return "Allowed";
    case "DENY":
      return "Blocked";
    case "REQUIRE_APPROVAL":
      return "Approval required";
    default:
      return "Lifecycle event";
  }
}
