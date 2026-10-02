import type {
  ActionRequest,
  EvaluationResult,
  NormalizationResult,
} from "../contracts";
import { normalizeToolCall } from "../normalize";
import { buildApprovalDisplaySummary } from "./display-summary";
import type {
  ApprovalConsumeResult,
  ApprovalRepository,
  AuditEvent,
  EvaluationPersistenceInput,
  NewApprovalRequest,
} from "../persistence/types";
import { KNOWN_TOOLS } from "../policy";
import { POLICY_VERSION } from "../policy-metadata";
import {
  hashApprovalRequest,
  hashMalformedArguments,
  hashNormalizedArguments,
  sha256Hex,
} from "../security/crypto";
import type { TrustedPrincipal } from "../security/types";

export const APPROVAL_TTL_SECONDS = 10 * 60;

export type SecurityRecordIdKind = "approval" | "audit" | "request";

export interface EvaluationPersistenceArtifacts {
  result: EvaluationResult;
  persistence: EvaluationPersistenceInput;
}

export async function auditToolName(toolName: string): Promise<string> {
  if (KNOWN_TOOLS.has(toolName)) {
    return toolName;
  }

  return `unknown.sha256.${await sha256Hex(toolName)}`;
}

export async function buildEvaluationPersistenceArtifacts(input: {
  request: ActionRequest;
  normalization: NormalizationResult;
  result: EvaluationResult;
  principal: TrustedPrincipal;
  now: number;
  createId: (kind: SecurityRecordIdKind) => string;
}): Promise<EvaluationPersistenceArtifacts> {
  const { request, normalization, principal, now, createId } = input;
  const approvalRequired = input.result.decision === "REQUIRE_APPROVAL";

  if (approvalRequired !== input.result.requires_approval) {
    throw new TypeError("inconsistent approval decision");
  }

  const [argumentsHash, sourceTextHash, persistedToolName] = await Promise.all([
    normalization.parse_ok
      ? hashNormalizedArguments(normalization.normalized.args)
      : hashMalformedArguments(request.arguments_json),
    sha256Hex(request.source_text),
    auditToolName(normalization.normalized.tool_name),
  ]);

  let approval: NewApprovalRequest | null = null;
  let result = input.result;
  let approvalId: string | null = null;

  if (approvalRequired) {
    if (!normalization.parse_ok) {
      throw new TypeError("malformed requests cannot require approval");
    }

    approvalId = createId("approval");
    const expiresAt = now + APPROVAL_TTL_SECONDS;
    const requestHash = await hashApprovalRequest({
      principal_id: principal.principal_id,
      trusted_tenant_id: principal.tenant_id,
      normalized: normalization.normalized,
      source_text: request.source_text,
      policy: input.result,
      policy_version: POLICY_VERSION,
    });

    approval = {
      id: approvalId,
      principal_id: principal.principal_id,
      tenant_id: principal.tenant_id,
      tool_name: normalization.normalized.tool_name,
      request_hash: requestHash,
      risk_level: input.result.risk_level,
      policy_codes: [...input.result.policy_codes],
      policy_version: POLICY_VERSION,
      approval_display: buildApprovalDisplaySummary(normalization.normalized),
      created_at: now,
      expires_at: expiresAt,
    };
    result = {
      ...input.result,
      approval_id: approvalId,
      expires_at: new Date(expiresAt * 1000).toISOString(),
    };
  }

  const event: AuditEvent = {
    id: createId("audit"),
    request_id: createId("request"),
    principal_id: principal.principal_id,
    key_id: principal.key_id,
    tenant_id: principal.tenant_id,
    tool_name: persistedToolName,
    event_type: "EVALUATED",
    decision: input.result.decision,
    risk_level: input.result.risk_level,
    policy_codes: [...input.result.policy_codes],
    arguments_hash: argumentsHash,
    source_text_hash: sourceTextHash,
    approval_id: approvalId,
    policy_version: POLICY_VERSION,
    created_at: now,
  };

  return {
    result,
    persistence: { event, approval },
  };
}

export type ConsumeApprovalWorkflowResult =
  | {
      authorized: true;
      approval_id: string;
      tool_name: string;
      normalized_args: EvaluationResult["normalized_args"];
    }
  | {
      authorized: false;
      error:
        | "APPROVAL_NOT_FOUND"
        | "APPROVAL_NOT_APPROVED"
        | "APPROVAL_REJECTED"
        | "APPROVAL_EXPIRED"
        | "APPROVAL_ALREADY_CONSUMED"
        | "APPROVAL_REQUEST_MISMATCH";
    };

function mapConsumeFailure(
  result: Exclude<ApprovalConsumeResult, { kind: "consumed" }>,
): ConsumeApprovalWorkflowResult {
  switch (result.kind) {
    case "not_found":
    case "ownership_mismatch":
      return { authorized: false, error: "APPROVAL_NOT_FOUND" };
    case "pending":
      return { authorized: false, error: "APPROVAL_NOT_APPROVED" };
    case "rejected":
      return { authorized: false, error: "APPROVAL_REJECTED" };
    case "expired":
      return { authorized: false, error: "APPROVAL_EXPIRED" };
    case "already_consumed":
      return { authorized: false, error: "APPROVAL_ALREADY_CONSUMED" };
    case "request_mismatch":
      return { authorized: false, error: "APPROVAL_REQUEST_MISMATCH" };
  }
}

/**
 * Consumes a stored approval using normalization and stored policy metadata
 * only. This workflow deliberately has no classifier or quota dependency.
 */
export async function consumeApprovedAction(input: {
  approval_id: string;
  request: ActionRequest;
  principal: TrustedPrincipal;
  approvals: ApprovalRepository;
  now: number;
}): Promise<ConsumeApprovalWorkflowResult> {
  const approval = await input.approvals.findById(
    input.approval_id,
    input.now,
  );

  if (
    approval === null ||
    approval.principal_id !== input.principal.principal_id ||
    approval.tenant_id !== input.principal.tenant_id
  ) {
    return { authorized: false, error: "APPROVAL_NOT_FOUND" };
  }

  if (approval.status === "PENDING") {
    return { authorized: false, error: "APPROVAL_NOT_APPROVED" };
  }
  if (approval.status === "REJECTED") {
    return { authorized: false, error: "APPROVAL_REJECTED" };
  }
  if (approval.status === "EXPIRED") {
    return { authorized: false, error: "APPROVAL_EXPIRED" };
  }
  if (approval.status === "CONSUMED") {
    return { authorized: false, error: "APPROVAL_ALREADY_CONSUMED" };
  }

  // A human decision made under another policy version has no authority under
  // the current policy, even when every request field still matches.
  if (approval.policy_version !== POLICY_VERSION) {
    return { authorized: false, error: "APPROVAL_REQUEST_MISMATCH" };
  }

  const normalization = normalizeToolCall(input.request);
  let requestHash: string;

  try {
    requestHash = await hashApprovalRequest({
      principal_id: input.principal.principal_id,
      trusted_tenant_id: input.principal.tenant_id,
      normalized: normalization.normalized,
      source_text: input.request.source_text,
      policy: {
        decision: "REQUIRE_APPROVAL",
        risk_level: approval.risk_level,
        policy_codes: approval.policy_codes,
        requires_approval: true,
      },
      policy_version: POLICY_VERSION,
    });
  } catch {
    return { authorized: false, error: "APPROVAL_REQUEST_MISMATCH" };
  }

  if (requestHash !== approval.request_hash) {
    return { authorized: false, error: "APPROVAL_REQUEST_MISMATCH" };
  }

  const consumed = await input.approvals.consume({
    id: input.approval_id,
    principal_id: input.principal.principal_id,
    tenant_id: input.principal.tenant_id,
    request_hash: requestHash,
    now: input.now,
  });

  if (consumed.kind !== "consumed") {
    return mapConsumeFailure(consumed);
  }

  // Do not authorize an action from a repository implementation that cannot
  // prove its CONSUMED lifecycle event was durably appended. The D1 adapter
  // gets this guarantee from the same-statement trigger; this runtime check
  // keeps injected adapters and future implementations fail closed too.
  if (consumed.audit_persisted !== true) {
    throw new Error("approval consumption audit was not persisted");
  }

  return {
    authorized: true,
    approval_id: consumed.approval.id,
    tool_name: consumed.approval.tool_name,
    normalized_args: normalization.normalized.args,
  };
}
