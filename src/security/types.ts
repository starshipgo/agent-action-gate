import type { EvaluationResult } from "../contracts";
import type { WorkflowRepositories } from "../persistence/types";
import type { BetaRepository } from "../product/beta";

export interface TrustedPrincipal {
  principal_id: string;
  tenant_id: string;
  key_id: string;
  daily_ai_limit: number;
}

export interface ApiKeyRecord extends TrustedPrincipal {
  status: "active" | "revoked";
}

export type ApiKeyStatus = ApiKeyRecord["status"];

/** Internal metadata. key_hash is accepted only on create and never returned. */
export interface ApiKeyMetadata extends ApiKeyRecord {
  key_prefix: string;
  label: string;
  created_at: number;
  revoked_at: number | null;
}

export interface NewApiKeyRecord {
  key_id: string;
  principal_id: string;
  tenant_id: string;
  daily_ai_limit: number;
  key_prefix: string;
  label: string;
  created_at: number;
  key_hash: string;
}

export interface ApiKeyListQuery {
  tenant_id?: string;
  status?: ApiKeyStatus;
  limit?: number;
}

export type ApiKeyCreateResult =
  | { kind: "created"; api_key: ApiKeyMetadata }
  | { kind: "principal_tenant_conflict" }
  | { kind: "conflict" };

export type ApiKeyRevokeResult =
  | { kind: "revoked"; api_key: ApiKeyMetadata }
  | { kind: "not_found" }
  | { kind: "already_revoked"; api_key: ApiKeyMetadata };

export interface ApiKeyManagementRepository {
  list(query: ApiKeyListQuery): Promise<ApiKeyMetadata[]>;
  create(input: NewApiKeyRecord): Promise<ApiKeyCreateResult>;
  revoke(keyId: string, revokedAt: number): Promise<ApiKeyRevokeResult>;
}

export interface OperatorOverviewMetrics {
  allowed: number;
  blocked: number;
  approval_required: number;
  pending_approvals: number;
  ai_quota_used_today: number;
  ai_daily_limit: number;
}

export interface OperatorOverviewRepository {
  getMetrics(dayUtc: string, nowUnixSeconds: number): Promise<OperatorOverviewMetrics>;
}

export interface PrincipalRepository {
  findByKeyHash(keyHash: string): Promise<ApiKeyRecord | null>;
}

export type AiQuotaResult =
  | { allowed: true; used: number; limit: number }
  | { allowed: false; limit: number };

export interface AiQuotaRepository {
  tryConsume(
    principal: TrustedPrincipal,
    dayUtc: string,
    nowUnixSeconds: number,
  ): Promise<AiQuotaResult>;
}

export interface IdempotencyClaimInput {
  principal_id: string;
  idempotency_key_hash: string;
  request_hash: string;
  /** Defaults to the current immutable policy version at the repository. */
  policy_version?: string;
  owner_token: string;
  now: number;
  expires_at: number;
  lease_expires_at: number;
}

/**
 * Persisted idempotency metadata deliberately omits normalized_tool and
 * normalized_args. The exact hash-matched request is normalized again at the
 * Worker boundary on replay.
 */
export type StoredEvaluationResult = Omit<
  EvaluationResult,
  "normalized_tool" | "normalized_args"
>;

export type IdempotencyClaimResult =
  | { kind: "acquired"; owner_token: string }
  | { kind: "replay"; response: StoredEvaluationResult }
  | { kind: "conflict" }
  | { kind: "in_progress" };

export interface IdempotencyCompletionInput {
  principal_id: string;
  idempotency_key_hash: string;
  request_hash: string;
  /** Defaults to the current immutable policy version at the repository. */
  policy_version?: string;
  owner_token: string;
  response: EvaluationResult;
  now: number;
}

export interface IdempotencyRepository {
  claim(input: IdempotencyClaimInput): Promise<IdempotencyClaimResult>;
  complete(input: IdempotencyCompletionInput): Promise<boolean>;
  abandon(input: {
    principal_id: string;
    idempotency_key_hash: string;
    request_hash: string;
    owner_token: string;
  }): Promise<void>;
}

export interface CoreSecurityRepositories {
  principals: PrincipalRepository;
  quota: AiQuotaRepository;
  idempotency: IdempotencyRepository;
}

export interface SecurityRepositories
  extends CoreSecurityRepositories,
    WorkflowRepositories {
  /** Optional only so focused core tests can inject the pre-Step-7 shape. */
  apiKeys?: ApiKeyManagementRepository;
  /** Optional only so focused core tests can inject the pre-Step-7 shape. */
  overview?: OperatorOverviewRepository;
  /** Optional for older injected test repositories. */
  beta?: BetaRepository;
}

export interface BurstRateLimiter {
  allow(principalId: string): Promise<boolean>;
}
