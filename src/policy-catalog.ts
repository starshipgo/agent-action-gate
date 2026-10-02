import type { Decision, PolicyCode } from "./contracts";
import { REFUND_LIMIT_MINOR_UNITS } from "./policy";

export interface PublicPolicyMetadata {
  id: string;
  outcome: Decision;
  summary: string;
  policy_codes: PolicyCode[];
}

/** Read-only product metadata; enforcement remains in the policy engine. */
export const BUILT_IN_POLICY_METADATA: readonly PublicPolicyMetadata[] = [
  {
    id: "malformed-arguments",
    outcome: "DENY",
    summary: "Malformed or non-object tool arguments are blocked.",
    policy_codes: ["MALFORMED_ARGUMENTS_JSON"],
  },
  {
    id: "unknown-tool",
    outcome: "DENY",
    summary: "Unknown tools are blocked.",
    policy_codes: ["UNKNOWN_TOOL"],
  },
  {
    id: "missing-target-tenant",
    outcome: "DENY",
    summary: "Tenant-scoped tools without a target tenant are blocked.",
    policy_codes: ["MISSING_TARGET_TENANT"],
  },
  {
    id: "cross-tenant",
    outcome: "DENY",
    summary: "Cross-tenant access is blocked.",
    policy_codes: ["CROSS_TENANT_ACCESS"],
  },
  {
    id: "secret-access",
    outcome: "DENY",
    summary: "Secret access is blocked.",
    policy_codes: ["FORBIDDEN_SECRET_ACCESS"],
  },
  {
    id: "customer-export",
    outcome: "DENY",
    summary: "Customer exports are blocked.",
    policy_codes: ["SENSITIVE_EXPORT"],
  },
  {
    id: "semantic-attack-signals",
    outcome: "DENY",
    summary:
      "Prompt injection, data exfiltration, or suspicious instructions are blocked; accompanying social-engineering context is reported.",
    policy_codes: [
      "PROMPT_INJECTION_SIGNAL",
      "DATA_EXFILTRATION_SIGNAL",
      "SUSPICIOUS_INSTRUCTION",
      "SOCIAL_ENGINEERING_SIGNAL",
    ],
  },
  {
    id: "email-send",
    outcome: "REQUIRE_APPROVAL",
    summary: "Outbound email requires human approval.",
    policy_codes: ["OUTBOUND_SEND"],
  },
  {
    id: "refund-within-limit",
    outcome: "REQUIRE_APPROVAL",
    summary: `Valid refunds at or below ${REFUND_LIMIT_MINOR_UNITS.toLocaleString("en-US")} minor units require human approval.`,
    policy_codes: ["REFUND_REQUIRES_APPROVAL"],
  },
  {
    id: "invalid-refund",
    outcome: "DENY",
    summary: "Missing, non-integer, zero, or negative refund amounts are blocked.",
    policy_codes: ["INVALID_REFUND_AMOUNT"],
  },
  {
    id: "refund-over-limit",
    outcome: "DENY",
    summary: `Refunds over ${REFUND_LIMIT_MINOR_UNITS.toLocaleString("en-US")} minor units are blocked.`,
    policy_codes: ["REFUND_LIMIT_EXCEEDED"],
  },
  {
    id: "low-risk-tools",
    outcome: "ALLOW",
    summary: "CRM reads, ticket creation, and email drafts are allowed when no higher-priority rule applies.",
    policy_codes: [],
  },
  {
    id: "classifier-failure",
    outcome: "DENY",
    summary: "Unavailable or malformed semantic-classifier output fails closed.",
    policy_codes: ["SEMANTIC_CLASSIFIER_FAILURE"],
  },
  {
    id: "policy-fallback",
    outcome: "DENY",
    summary: "Any call not matched by an explicit policy is blocked.",
    policy_codes: ["NO_MATCHING_POLICY"],
  },
] as const;
