export type Decision = "ALLOW" | "REQUIRE_APPROVAL" | "DENY";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type PolicyCode =
  | "UNKNOWN_TOOL"
  | "MISSING_TARGET_TENANT"
  | "CROSS_TENANT_ACCESS"
  | "FORBIDDEN_SECRET_ACCESS"
  | "SENSITIVE_EXPORT"
  | "PROMPT_INJECTION_SIGNAL"
  | "DATA_EXFILTRATION_SIGNAL"
  | "SUSPICIOUS_INSTRUCTION"
  | "SOCIAL_ENGINEERING_SIGNAL"
  | "OUTBOUND_SEND"
  | "INVALID_REFUND_AMOUNT"
  | "REFUND_LIMIT_EXCEEDED"
  | "REFUND_REQUIRES_APPROVAL"
  | "NO_MATCHING_POLICY"
  | "MALFORMED_ARGUMENTS_JSON"
  | "SEMANTIC_CLASSIFIER_FAILURE";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

/** The five untrusted values accepted at the external boundary. */
export interface ActionRequest {
  agent_role: string;
  tool_name: string;
  arguments_json: string;
  source_text: string;
  request_tenant: string;
}

export interface NormalizedToolCall {
  agent_role: string;
  tool_name: string;
  request_tenant: string;
  target_tenant: string;
  amount_minor: number | null;
  recipient: string;
  args: JsonObject;
}

export type NormalizationResult =
  | {
      parse_ok: true;
      parse_error: "";
      normalized: NormalizedToolCall;
    }
  | {
      parse_ok: false;
      parse_error: string;
      normalized: NormalizedToolCall;
    };

/**
 * Boundary type for Dify-compatible structured output. The string variants are
 * intentional: the prototype returned a schema boolean as the string "true".
 */
export type RawSemanticSignal = boolean | "true" | "false";

export type SemanticConfidence = "low" | "medium" | "high";

export interface RawRiskSignals {
  prompt_injection: RawSemanticSignal;
  data_exfiltration: RawSemanticSignal;
  social_engineering: RawSemanticSignal;
  suspicious_instruction: RawSemanticSignal;
  confidence: SemanticConfidence;
  reason: string;
}

/** Backwards-compatible name retained for Phase 1 callers and fixtures. */
export type RawSemanticRisk = RawRiskSignals;

export interface SemanticRiskSignals {
  prompt_injection: boolean;
  data_exfiltration: boolean;
  social_engineering: boolean;
  suspicious_instruction: boolean;
}

/** Raw values supplied to the semantic sensor, matching the Dify prompt. */
export interface SemanticRiskContext {
  source_text: string;
  tool_name: string;
  agent_role: string;
  request_tenant: string;
}

export type SemanticRiskClassifier = (
  context: SemanticRiskContext,
) => RawRiskSignals | PromiseLike<RawRiskSignals>;

export interface EvaluationResult {
  decision: Decision;
  risk_level: RiskLevel;
  policy_codes: PolicyCode[];
  requires_approval: boolean;
  normalized_tool: string;
  normalized_args: JsonObject;
  /** Present only when a REQUIRE_APPROVAL decision was persisted. */
  approval_id?: string;
  /** ISO-8601 timestamp paired with approval_id. */
  expires_at?: string;
}
