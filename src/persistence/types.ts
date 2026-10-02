import type {
  Decision,
  EvaluationResult,
  PolicyCode,
  RiskLevel,
} from "../contracts";
import type { ApprovalDisplaySummary } from "../approvals/display-summary";

export type AuditEventType =
  | "EVALUATED"
  | "APPROVED"
  | "REJECTED"
  | "EXPIRED"
  | "CONSUMED"
  | "CONSUME_MISMATCH";

/**
 * An append-only, sanitized security event. Hash fields contain lowercase
 * SHA-256 hex; they must never contain their source values.
 */
export interface AuditEvent {
  id: string;
  request_id: string;
  principal_id: string;
  key_id: string | null;
  tenant_id: string;
  tool_name: string;
  event_type: AuditEventType;
  decision: Decision | null;
  risk_level: RiskLevel | null;
  policy_codes: PolicyCode[];
  arguments_hash: string | null;
  source_text_hash: string | null;
  approval_id: string | null;
  policy_version: string;
  created_at: number;
}

export interface AuditQuery {
  tenant_id?: string;
  decision?: Decision;
  tool_name?: string;
  /** Inclusive Unix-second lower bound. */
  created_from?: number;
  /** Exclusive Unix-second upper bound. */
  created_to?: number;
  limit?: number;
}

export interface AuditRepository {
  append(event: AuditEvent): Promise<void>;
  list(query: AuditQuery): Promise<AuditEvent[]>;
}

export type ApprovalStatus =
  | "PENDING"
  | "APPROVED"
  | "REJECTED"
  | "EXPIRED"
  | "CONSUMED";

/**
 * Approval rows contain no raw request object or source text. approval_display
 * contains only tool-specific allowlisted presentation fields; request_hash
 * alone binds the full request, trusted identity, and policy result.
 */
export interface ApprovalRequest {
  id: string;
  principal_id: string;
  tenant_id: string;
  tool_name: string;
  request_hash: string;
  risk_level: RiskLevel;
  policy_codes: PolicyCode[];
  policy_version: string;
  /** Untrusted presentation metadata. Never use this as authorization input. */
  approval_display: ApprovalDisplaySummary;
  status: ApprovalStatus;
  created_at: number;
  expires_at: number;
  decided_at: number | null;
  decided_by: string | null;
  consumed_at: number | null;
}

export type NewApprovalRequest = Pick<
  ApprovalRequest,
  | "id"
  | "principal_id"
  | "tenant_id"
  | "tool_name"
  | "request_hash"
  | "risk_level"
  | "policy_codes"
  | "policy_version"
  | "approval_display"
  | "created_at"
  | "expires_at"
>;

export interface ApprovalQuery {
  status?: ApprovalStatus;
  tenant_id?: string;
  limit?: number;
  now: number;
}

export interface ApprovalDecisionInput {
  id: string;
  decision: "APPROVED" | "REJECTED";
  decided_by: string;
  now: number;
}

/**
 * A successful approval transition is valid only when its corresponding
 * append-only lifecycle audit event was persisted in the same operation.
 * Implementations must reject on audit failure rather than returning one of
 * these successful variants without this marker.
 */
export type ApprovalDecisionResult =
  | {
      kind: "decided";
      approval: ApprovalRequest;
      audit_persisted: true;
    }
  | { kind: "not_found" }
  | { kind: "expired"; approval: ApprovalRequest }
  | { kind: "conflict"; approval: ApprovalRequest };

export interface ApprovalConsumeInput {
  id: string;
  principal_id: string;
  tenant_id: string;
  request_hash: string;
  now: number;
}

export type ApprovalConsumeResult =
  | {
      kind: "consumed";
      approval: ApprovalRequest;
      audit_persisted: true;
    }
  | { kind: "not_found" }
  | { kind: "ownership_mismatch" }
  | { kind: "request_mismatch"; approval: ApprovalRequest }
  | { kind: "pending"; approval: ApprovalRequest }
  | { kind: "rejected"; approval: ApprovalRequest }
  | { kind: "expired"; approval: ApprovalRequest }
  | { kind: "already_consumed"; approval: ApprovalRequest };

export interface ApprovalRepository {
  create(input: NewApprovalRequest): Promise<ApprovalRequest>;
  findById(id: string, now: number): Promise<ApprovalRequest | null>;
  decide(input: ApprovalDecisionInput): Promise<ApprovalDecisionResult>;
  consume(input: ApprovalConsumeInput): Promise<ApprovalConsumeResult>;
  list(query: ApprovalQuery): Promise<ApprovalRequest[]>;
}

export interface EvaluationPersistenceInput {
  event: AuditEvent;
  approval: NewApprovalRequest | null;
  idempotency?: {
    principal_id: string;
    idempotency_key_hash: string;
    request_hash: string;
    owner_token: string;
    response: EvaluationResult;
    now: number;
  } | null;
}

/** Persists an evaluated audit event and any pending approval as one unit. */
export interface EvaluationPersistenceRepository {
  persist(
    input: EvaluationPersistenceInput,
  ): Promise<{ approval: ApprovalRequest | null }>;
}

export interface WorkflowRepositories {
  audit: AuditRepository;
  approvals: ApprovalRepository;
  evaluations: EvaluationPersistenceRepository;
}
