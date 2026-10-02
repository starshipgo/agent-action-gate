import {
  buildEvaluationPersistenceArtifacts,
  consumeApprovedAction,
  type SecurityRecordIdKind,
} from "./approvals/workflow";
import type { SemanticClassifier } from "./classifiers/types";
import { WorkersAiSemanticClassifier } from "./classifiers/workers-ai";
import type { ActionRequest, Decision, EvaluationResult } from "./contracts";
import {
  evaluatePreparedAction,
  prepareEvaluation,
} from "./evaluate";
import { validateEvaluationRequest } from "./http/validate-request";
import { normalizeToolCall } from "./normalize";
import type {
  ApprovalRequest,
  ApprovalStatus,
  AuditEvent,
} from "./persistence/types";
import { createD1WorkflowRepositories } from "./persistence/d1-workflow-repositories";
import { BUILT_IN_POLICY_METADATA } from "./policy-catalog";
import { D1BetaRepository } from "./product/d1";
import { parseBetaInterest, parsePublicEvent } from "./product/beta";
import { POLICY_VERSION } from "./policy-metadata";
import { issueApiKeyMaterial } from "./security/api-key-issuance";
import { authenticateRequest } from "./security/authenticate";
import { CloudflareBurstRateLimiter } from "./security/cloudflare-rate-limiter";
import { hashEvaluationRequest, sha256Hex } from "./security/crypto";
import { createD1OperatorRepositories } from "./security/d1-operator-repositories";
import { createD1SecurityRepositories } from "./security/d1-repositories";
import {
  authenticateOperator,
  authenticateOperatorCredential,
  extractOperatorBearerCredential,
} from "./security/operator-auth";
import {
  authenticateOperatorSession,
  clearOperatorSessionCookie,
  issueOperatorSession,
} from "./security/operator-session";
import type {
  ApiKeyListQuery,
  ApiKeyMetadata,
  BurstRateLimiter,
  IdempotencyClaimInput,
  SecurityRepositories,
  TrustedPrincipal,
} from "./security/types";

export interface WorkerDependencies {
  createClassifier?: (env: Env) => SemanticClassifier;
  /** Inject all repositories in tests; production composes the two D1 layers. */
  createSecurityRepositories?: (env: Env) => SecurityRepositories;
  createRateLimiter?: (env: Env) => BurstRateLimiter;
  now?: () => Date;
  createOwnerToken?: () => string;
  /** Creates non-secret IDs for approvals and audit records. */
  createRecordId?: (kind: SecurityRecordIdKind) => string;
  /** Reads the dedicated operator secret binding; never use agent API keys here. */
  getOperatorSecret?: (env: Env) => string | undefined;
  /** Supplies a non-secret audit identity for an operator decision. */
  getOperatorIdentity?: (env: Env) => string;
}

const MAX_REQUEST_BODY_BYTES = 64 * 1024;
const MAX_IDEMPOTENCY_KEY_LENGTH = 256;
const IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60;
const IDEMPOTENCY_LEASE_SECONDS = 60;
const MAX_API_KEY_DAILY_AI_LIMIT = 1_000_000;
const MAX_AUDIT_TIMESTAMP = 4_102_444_800; // 2100-01-01 UTC
const MAX_AUDIT_WINDOW_SECONDS = 90 * 24 * 60 * 60;

type JsonBodyResult =
  | { ok: true; value: unknown }
  | { ok: false; error: "INVALID_JSON" | "REQUEST_BODY_TOO_LARGE" };

interface ActiveIdempotencyClaim {
  principal_id: string;
  idempotency_key_hash: string;
  request_hash: string;
  owner_token: string;
}

type ApprovalRouteAction = "approve" | "reject" | "consume";

const APPROVAL_STATUSES: ReadonlySet<ApprovalStatus> = new Set([
  "PENDING",
  "APPROVED",
  "REJECTED",
  "EXPIRED",
  "CONSUMED",
]);
const DECISIONS: ReadonlySet<Decision> = new Set([
  "ALLOW",
  "REQUIRE_APPROVAL",
  "DENY",
]);
const APPROVAL_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const CANONICAL_TENANT_PATTERN = /^[a-z0-9._-]{1,128}$/;

function jsonResponse(
  value: unknown,
  status: number,
  extraHeaders?: Record<string, string>,
): Response {
  const headers = new Headers(extraHeaders);
  headers.set("cache-control", "no-store");
  headers.set("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
  headers.set("referrer-policy", "no-referrer");
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");

  return Response.json(value, { status, headers });
}

async function readJsonBody(request: Request): Promise<JsonBodyResult> {
  const declaredLength = request.headers.get("content-length");
  if (
    declaredLength !== null &&
    /^\d+$/.test(declaredLength) &&
    Number(declaredLength) > MAX_REQUEST_BODY_BYTES
  ) {
    return { ok: false, error: "REQUEST_BODY_TOO_LARGE" };
  }

  if (request.body === null) {
    return { ok: false, error: "INVALID_JSON" };
  }

  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let byteLength = 0;
  let text = "";

  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }

      byteLength += chunk.value.byteLength;
      if (byteLength > MAX_REQUEST_BODY_BYTES) {
        await reader.cancel();
        return { ok: false, error: "REQUEST_BODY_TOO_LARGE" };
      }

      text += decoder.decode(chunk.value, { stream: true });
    }

    text += decoder.decode();
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false, error: "INVALID_JSON" };
  }
}

function unixSeconds(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}

function utcDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function trustedActionRequest(
  incoming: {
    agent_role: string;
    tool_name: string;
    arguments_json: string;
    source_text: string;
  },
  principal: TrustedPrincipal,
): ActionRequest {
  return {
    agent_role: incoming.agent_role,
    tool_name: incoming.tool_name,
    arguments_json: incoming.arguments_json,
    source_text: incoming.source_text,
    request_tenant: principal.tenant_id,
  };
}

async function abandonClaim(
  repositories: SecurityRepositories,
  claim: ActiveIdempotencyClaim | null,
): Promise<void> {
  if (claim === null) {
    return;
  }

  try {
    await repositories.idempotency.abandon(claim);
  } catch {
    // Keeping a pending claim is safer than exposing an unaudited decision.
    // It can only delay a retry; it cannot authorize an action.
  }
}

function approvalRoute(
  pathname: string,
): { approvalId: string; action: ApprovalRouteAction } | null {
  const match = /^\/v1\/approvals\/([^/]+)\/(approve|reject|consume)$/.exec(
    pathname,
  );
  if (match === null || !APPROVAL_ID_PATTERN.test(match[1]!)) {
    return null;
  }

  return {
    approvalId: match[1]!,
    action: match[2]! as ApprovalRouteAction,
  };
}

function apiKeyRevokeRoute(pathname: string): string | null {
  const match = /^\/v1\/api-keys\/([^/]+)\/revoke$/.exec(pathname);
  const keyId = match?.[1];
  return keyId !== undefined && /^[A-Za-z0-9._:-]{1,128}$/.test(keyId)
    ? keyId
    : null;
}

function singleQueryValue(
  url: URL,
  name: string,
): { ok: true; value: string | undefined } | { ok: false } {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) {
    return { ok: false };
  }

  return { ok: true, value: values[0] };
}

function hasOnlyQueryParameters(
  url: URL,
  allowed: ReadonlySet<string>,
): boolean {
  for (const name of url.searchParams.keys()) {
    if (!allowed.has(name)) {
      return false;
    }
  }
  return true;
}

function parseLimit(
  value: string | undefined,
): { ok: true; value: number | undefined } | { ok: false } {
  if (value === undefined) {
    return { ok: true, value: undefined };
  }
  if (!/^[1-9]\d*$/.test(value)) {
    return { ok: false };
  }

  const limit = Number(value);
  return Number.isSafeInteger(limit) && limit <= 100
    ? { ok: true, value: limit }
    : { ok: false };
}

function parseUnixTimestamp(
  value: string | undefined,
): { ok: true; value: number | undefined } | { ok: false } {
  if (value === undefined) return { ok: true, value: undefined };
  if (!/^(0|[1-9]\d*)$/.test(value)) return { ok: false };

  const timestamp = Number(value);
  return Number.isSafeInteger(timestamp) && timestamp <= MAX_AUDIT_TIMESTAMP
    ? { ok: true, value: timestamp }
    : { ok: false };
}

function parseAuditQuery(url: URL):
  | {
      ok: true;
      value: {
        tenant_id?: string;
        decision?: Decision;
        tool_name?: string;
        created_from?: number;
        created_to?: number;
        limit?: number;
      };
    }
  | { ok: false } {
  if (
    !hasOnlyQueryParameters(
      url,
      new Set([
        "tenant_id",
        "decision",
        "tool_name",
        "created_from",
        "created_to",
        "limit",
      ]),
    )
  ) {
    return { ok: false };
  }
  const tenant = singleQueryValue(url, "tenant_id");
  const decision = singleQueryValue(url, "decision");
  const tool = singleQueryValue(url, "tool_name");
  const createdFrom = singleQueryValue(url, "created_from");
  const createdTo = singleQueryValue(url, "created_to");
  const limit = singleQueryValue(url, "limit");
  if (
    !tenant.ok ||
    !decision.ok ||
    !tool.ok ||
    !createdFrom.ok ||
    !createdTo.ok ||
    !limit.ok
  ) {
    return { ok: false };
  }
  if (
    (tenant.value !== undefined && !CANONICAL_TENANT_PATTERN.test(tenant.value)) ||
    (decision.value !== undefined && !DECISIONS.has(decision.value as Decision)) ||
    (tool.value !== undefined &&
      (tool.value.length === 0 ||
        tool.value.length > 256 ||
        tool.value !== tool.value.trim().toLowerCase()))
  ) {
    return { ok: false };
  }

  const parsedLimit = parseLimit(limit.value);
  const parsedFrom = parseUnixTimestamp(createdFrom.value);
  const parsedTo = parseUnixTimestamp(createdTo.value);
  if (!parsedLimit.ok || !parsedFrom.ok || !parsedTo.ok) {
    return { ok: false };
  }
  if (
    parsedFrom.value !== undefined &&
    parsedTo.value !== undefined &&
    (parsedFrom.value >= parsedTo.value ||
      parsedTo.value - parsedFrom.value > MAX_AUDIT_WINDOW_SECONDS)
  ) {
    return { ok: false };
  }

  return {
    ok: true,
    value: {
      ...(tenant.value === undefined ? {} : { tenant_id: tenant.value }),
      ...(decision.value === undefined
        ? {}
        : { decision: decision.value as Decision }),
      ...(tool.value === undefined ? {} : { tool_name: tool.value }),
      ...(parsedFrom.value === undefined
        ? {}
        : { created_from: parsedFrom.value }),
      ...(parsedTo.value === undefined ? {} : { created_to: parsedTo.value }),
      ...(parsedLimit.value === undefined ? {} : { limit: parsedLimit.value }),
    },
  };
}

function parseApiKeyQuery(url: URL):
  | { ok: true; value: ApiKeyListQuery }
  | { ok: false } {
  if (!hasOnlyQueryParameters(url, new Set(["tenant_id", "status", "limit"]))) {
    return { ok: false };
  }

  const tenant = singleQueryValue(url, "tenant_id");
  const status = singleQueryValue(url, "status");
  const limit = singleQueryValue(url, "limit");
  if (!tenant.ok || !status.ok || !limit.ok) return { ok: false };
  if (
    (tenant.value !== undefined && !CANONICAL_TENANT_PATTERN.test(tenant.value)) ||
    (status.value !== undefined &&
      status.value !== "active" &&
      status.value !== "revoked")
  ) {
    return { ok: false };
  }

  const parsedLimit = parseLimit(limit.value);
  if (!parsedLimit.ok) return { ok: false };

  return {
    ok: true,
    value: {
      ...(tenant.value === undefined ? {} : { tenant_id: tenant.value }),
      ...(status.value === undefined ? {} : { status: status.value }),
      ...(parsedLimit.value === undefined ? {} : { limit: parsedLimit.value }),
    },
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function hasExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  return (
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

interface ApiKeyCreateBody {
  tenant_id: string;
  label: string;
  daily_ai_limit: number;
}

function validUnpaddedText(value: unknown, maxLength: number): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= maxLength &&
    value === value.trim() &&
    !/\p{Cc}/u.test(value)
  );
}

function parseApiKeyCreateBody(value: unknown): ApiKeyCreateBody | null {
  if (
    !isObject(value) ||
    !hasExactKeys(value, ["tenant_id", "label", "daily_ai_limit"]) ||
    typeof value.tenant_id !== "string" ||
    !CANONICAL_TENANT_PATTERN.test(value.tenant_id) ||
    !validUnpaddedText(value.label, 200) ||
    typeof value.daily_ai_limit !== "number" ||
    !Number.isSafeInteger(value.daily_ai_limit) ||
    value.daily_ai_limit < 0 ||
    value.daily_ai_limit > MAX_API_KEY_DAILY_AI_LIMIT
  ) {
    return null;
  }

  return {
    tenant_id: value.tenant_id,
    label: value.label,
    daily_ai_limit: value.daily_ai_limit,
  };
}

function parseApprovalQuery(url: URL):
  | { ok: true; value: { status?: ApprovalStatus; tenant_id?: string; limit?: number } }
  | { ok: false } {
  if (!hasOnlyQueryParameters(url, new Set(["status", "tenant_id", "limit"]))) {
    return { ok: false };
  }
  const status = singleQueryValue(url, "status");
  const tenant = singleQueryValue(url, "tenant_id");
  const limit = singleQueryValue(url, "limit");
  if (!status.ok || !tenant.ok || !limit.ok) {
    return { ok: false };
  }
  if (
    (status.value !== undefined &&
      !APPROVAL_STATUSES.has(status.value as ApprovalStatus)) ||
    (tenant.value !== undefined && !CANONICAL_TENANT_PATTERN.test(tenant.value))
  ) {
    return { ok: false };
  }

  const parsedLimit = parseLimit(limit.value);
  if (!parsedLimit.ok) {
    return { ok: false };
  }

  return {
    ok: true,
    value: {
      ...(status.value === undefined
        ? { status: "PENDING" as const }
        : { status: status.value as ApprovalStatus }),
      ...(tenant.value === undefined ? {} : { tenant_id: tenant.value }),
      ...(parsedLimit.value === undefined ? {} : { limit: parsedLimit.value }),
    },
  };
}

function publicApproval(approval: ApprovalRequest) {
  return {
    approval_id: approval.id,
    principal_id: approval.principal_id,
    tenant_id: approval.tenant_id,
    tool_name: approval.tool_name,
    risk_level: approval.risk_level,
    policy_codes: approval.policy_codes,
    policy_version: approval.policy_version,
    approval_display: approval.approval_display,
    status: approval.status,
    created_at: approval.created_at,
    expires_at: approval.expires_at,
    decided_at: approval.decided_at,
    consumed_at: approval.consumed_at,
  };
}

/** The query API returns the already-sanitized repository shape only. */
function publicAudit(event: AuditEvent) {
  return {
    id: event.id,
    request_id: event.request_id,
    principal_id: event.principal_id,
    key_id: event.key_id,
    tenant_id: event.tenant_id,
    tool_name: event.tool_name,
    event_type: event.event_type,
    decision: event.decision,
    risk_level: event.risk_level,
    policy_codes: event.policy_codes,
    policy_version: event.policy_version,
    arguments_hash: event.arguments_hash,
    source_text_hash: event.source_text_hash,
    approval_id: event.approval_id,
    created_at: event.created_at,
  };
}

/** Deliberately excludes principal_id and every credential/hash field. */
function publicApiKey(apiKey: ApiKeyMetadata) {
  return {
    key_id: apiKey.key_id,
    key_prefix: apiKey.key_prefix,
    tenant_id: apiKey.tenant_id,
    label: apiKey.label,
    status: apiKey.status,
    created_at: apiKey.created_at,
    revoked_at: apiKey.revoked_at,
    daily_ai_limit: apiKey.daily_ai_limit,
  };
}

function consumeFailureStatus(error: string): number {
  switch (error) {
    case "APPROVAL_REJECTED":
      return 403;
    case "APPROVAL_EXPIRED":
      return 410;
    case "APPROVAL_ALREADY_CONSUMED":
    case "APPROVAL_REQUEST_MISMATCH":
    case "APPROVAL_NOT_APPROVED":
      return 409;
    case "APPROVAL_NOT_FOUND":
      return 404;
    default:
      return 503;
  }
}

function defaultRepositories(env: Env): SecurityRepositories {
  // The security core and workflow repositories are kept independently
  // testable, then composed only at the Worker boundary.
  return {
    ...createD1SecurityRepositories(env.DB),
    ...createD1WorkflowRepositories(env.DB),
    ...createD1OperatorRepositories(env.DB),
    beta: new D1BetaRepository(env.DB),
  };
}

function defaultOperatorSecret(env: Env): string | undefined {
  // The generated Env declaration is intentionally not hand-edited for a
  // secret. Wrangler supplies this binding after a human configures it.
  return (env as Env & { OPERATOR_API_KEY?: string }).OPERATOR_API_KEY;
}

function defaultOperatorIdentity(env: Env): string {
  const configured = (env as Env & { OPERATOR_ID?: string }).OPERATOR_ID;
  return configured ?? "preview-operator";
}

function validOperatorIdentity(value: string): boolean {
  return (
    value.length >= 1 &&
    value.length <= 128 &&
    value === value.trim()
  );
}

function hasSameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (origin === null) return false;

  try {
    const parsedOrigin = new URL(origin);
    return (
      origin === parsedOrigin.origin &&
      parsedOrigin.origin === new URL(request.url).origin
    );
  } catch {
    return false;
  }
}

function isStateChanging(method: string): boolean {
  return method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
}

export function createWorker(dependencies: WorkerDependencies = {}) {
  const createClassifier =
    dependencies.createClassifier ??
    ((env: Env) => new WorkersAiSemanticClassifier(env.AI));
  const createRepositories =
    dependencies.createSecurityRepositories ?? defaultRepositories;
  const createRateLimiter =
    dependencies.createRateLimiter ??
    ((env: Env) => new CloudflareBurstRateLimiter(env.EVALUATE_RATE_LIMITER));
  const currentTime = dependencies.now ?? (() => new Date());
  const createOwnerToken = dependencies.createOwnerToken ?? (() => crypto.randomUUID());
  const createRecordId = dependencies.createRecordId ?? (() => crypto.randomUUID());
  const getOperatorSecret =
    dependencies.getOperatorSecret ?? defaultOperatorSecret;
  const getOperatorIdentity =
    dependencies.getOperatorIdentity ?? defaultOperatorIdentity;

  async function authenticateAgent(
    request: Request,
    env: Env,
    repositories: SecurityRepositories,
  ): Promise<TrustedPrincipal | Response> {
    try {
      const operatorAuthentication = await authenticateOperator(
        request,
        getOperatorSecret(env),
      );
      // An operator secret is never accepted as a tenant Agent credential,
      // even if a deployment accidentally attempts to reuse the same value.
      if (operatorAuthentication.ok) {
        return jsonResponse({ error: "UNAUTHORIZED" }, 401);
      }
    } catch {
      return jsonResponse({ error: "AUTHENTICATION_UNAVAILABLE" }, 503);
    }

    const authentication = await authenticateRequest(
      request,
      repositories.principals,
    );
    if (!authentication.ok) {
      return authentication.reason === "unavailable"
        ? jsonResponse({ error: "AUTHENTICATION_UNAVAILABLE" }, 503)
        : jsonResponse({ error: "UNAUTHORIZED" }, 401);
    }

    return authentication.principal;
  }

  async function authenticateOperatorRequest(
    request: Request,
    env: Env,
    repositories: SecurityRepositories,
  ): Promise<Response | null> {
    try {
      const agentAuthentication = await authenticateRequest(
        request,
        repositories.principals,
      );
      // An active tenant Agent key never gains operator authority, even if an
      // unsafe deployment accidentally configured the same secret value.
      if (agentAuthentication.ok) {
        return jsonResponse({ error: "UNAUTHORIZED" }, 401);
      }
      if (agentAuthentication.reason === "unavailable") {
        return jsonResponse({ error: "AUTHENTICATION_UNAVAILABLE" }, 503);
      }

      const operatorAuthentication = await authenticateOperator(
        request,
        getOperatorSecret(env),
      );
      if (operatorAuthentication.ok) {
        const supplied = extractOperatorBearerCredential(request);
        if (
          supplied === null ||
          (await repositories.principals.findByKeyHash(
            await sha256Hex(supplied),
          )) !== null
        ) {
          return jsonResponse({ error: "UNAUTHORIZED" }, 401);
        }
        const suppliedOrigin = request.headers.get("origin");
        if (isStateChanging(request.method) && suppliedOrigin !== null && !hasSameOrigin(request)) {
          return jsonResponse({ error: "ORIGIN_FORBIDDEN" }, 403);
        }
        return null;
      }

      const sessionAuthenticated = await authenticateOperatorSession(
        request,
        getOperatorSecret(env),
        unixSeconds(currentTime()),
      );
      if (sessionAuthenticated) {
        if (isStateChanging(request.method) && !hasSameOrigin(request)) {
          return jsonResponse({ error: "ORIGIN_FORBIDDEN" }, 403);
        }
        return null;
      }

      return operatorAuthentication.reason === "unavailable"
        ? jsonResponse({ error: "OPERATOR_AUTHENTICATION_UNAVAILABLE" }, 503)
        : jsonResponse({ error: "UNAUTHORIZED" }, 401);
    } catch {
      return jsonResponse({ error: "OPERATOR_AUTHENTICATION_UNAVAILABLE" }, 503);
    }
  }

  async function readTrustedActionRequest(
    request: Request,
    principal: TrustedPrincipal,
  ): Promise<ActionRequest | Response> {
    const body = await readJsonBody(request);
    if (!body.ok) {
      return jsonResponse({ error: body.error }, 400);
    }

    const validation = validateEvaluationRequest(body.value);
    if (!validation.ok) {
      return jsonResponse(
        { error: "INVALID_REQUEST", details: validation.errors },
        400,
      );
    }

    const incoming = validation.value;
    if (
      incoming.request_tenant !== undefined &&
      incoming.request_tenant !== principal.tenant_id
    ) {
      return jsonResponse({ error: "TENANT_MISMATCH" }, 403);
    }

    return trustedActionRequest(incoming, principal);
  }

  async function handleEvaluation(
    request: Request,
    env: Env,
    repositories: SecurityRepositories,
  ): Promise<Response> {
    const principal = await authenticateAgent(request, env, repositories);
    if (principal instanceof Response) {
      return principal;
    }

    if (request.method !== "POST") {
      return jsonResponse(
        { error: "METHOD_NOT_ALLOWED" },
        405,
        { allow: "POST" },
      );
    }

    try {
      if (!(await createRateLimiter(env).allow(principal.principal_id))) {
        return jsonResponse({ error: "RATE_LIMIT_EXCEEDED" }, 429);
      }
    } catch {
      return jsonResponse({ error: "RATE_LIMIT_UNAVAILABLE" }, 503);
    }

    const rawBody = await readJsonBody(request);
    if (!rawBody.ok) {
      return jsonResponse({ error: rawBody.error }, 400);
    }

    const validation = validateEvaluationRequest(rawBody.value);
    if (!validation.ok) {
      return jsonResponse(
        { error: "INVALID_REQUEST", details: validation.errors },
        400,
      );
    }

    const incoming = validation.value;
    if (
      incoming.request_tenant !== undefined &&
      incoming.request_tenant !== principal.tenant_id
    ) {
      return jsonResponse({ error: "TENANT_MISMATCH" }, 403);
    }

    const trustedRequest = trustedActionRequest(incoming, principal);
    const idempotencyKey = request.headers.get("idempotency-key");
    if (
      idempotencyKey !== null &&
      (idempotencyKey.trim() === "" ||
        idempotencyKey.length > MAX_IDEMPOTENCY_KEY_LENGTH)
    ) {
      return jsonResponse({ error: "INVALID_IDEMPOTENCY_KEY" }, 400);
    }

    let activeClaim: ActiveIdempotencyClaim | null = null;
    if (idempotencyKey !== null) {
      const now = unixSeconds(currentTime());

      try {
        const [idempotencyKeyHash, requestHash] = await Promise.all([
          sha256Hex(idempotencyKey),
          hashEvaluationRequest(incoming, principal.tenant_id),
        ]);
        const claimInput: IdempotencyClaimInput = {
          principal_id: principal.principal_id,
          idempotency_key_hash: idempotencyKeyHash,
          request_hash: requestHash,
          owner_token: createOwnerToken(),
          now,
          expires_at: now + IDEMPOTENCY_TTL_SECONDS,
          lease_expires_at: now + IDEMPOTENCY_LEASE_SECONDS,
        };
        const claim = await repositories.idempotency.claim(claimInput);

        if (claim.kind === "replay") {
          const replayNormalization = normalizeToolCall(trustedRequest);
          const replayResponse: EvaluationResult = {
            ...claim.response,
            normalized_tool: replayNormalization.normalized.tool_name,
            normalized_args: replayNormalization.normalized.args,
          };
          return jsonResponse(replayResponse, 200);
        }
        if (claim.kind === "conflict") {
          return jsonResponse({ error: "IDEMPOTENCY_KEY_REUSE" }, 409);
        }
        if (claim.kind === "in_progress") {
          return jsonResponse(
            { error: "IDEMPOTENCY_REQUEST_IN_PROGRESS" },
            409,
            { "retry-after": String(IDEMPOTENCY_LEASE_SECONDS) },
          );
        }

        activeClaim = {
          principal_id: claimInput.principal_id,
          idempotency_key_hash: claimInput.idempotency_key_hash,
          request_hash: claimInput.request_hash,
          owner_token: claim.owner_token,
        };
      } catch {
        return jsonResponse({ error: "IDEMPOTENCY_UNAVAILABLE" }, 503);
      }
    }

    const prepared = prepareEvaluation(trustedRequest);
    // `PreparedEvaluation` intentionally omits normalization for immediate
    // deterministic decisions. Re-normalizing this immutable request lets the
    // audit record cover both deterministic and semantic paths identically.
    const normalization = normalizeToolCall(trustedRequest);

    let result: EvaluationResult;
    if (prepared.kind === "complete") {
      result = prepared.result;
    } else {
      const quotaTime = currentTime();
      try {
        const quota = await repositories.quota.tryConsume(
          principal,
          utcDay(quotaTime),
          unixSeconds(quotaTime),
        );

        if (!quota.allowed) {
          await abandonClaim(repositories, activeClaim);
          return jsonResponse({ error: "DAILY_AI_QUOTA_EXCEEDED" }, 429);
        }
      } catch {
        await abandonClaim(repositories, activeClaim);
        return jsonResponse({ error: "AI_QUOTA_UNAVAILABLE" }, 503);
      }

      result = await evaluatePreparedAction(prepared, (context) =>
        createClassifier(env).classify(context),
      );
    }

    const decisionNow = unixSeconds(currentTime());
    try {
      const artifacts = await buildEvaluationPersistenceArtifacts({
        request: trustedRequest,
        normalization,
        result,
        principal,
        now: decisionNow,
        createId: createRecordId,
      });
      await repositories.evaluations.persist({
        ...artifacts.persistence,
        idempotency:
          activeClaim === null
            ? null
            : {
                ...activeClaim,
                response: artifacts.result,
                now: decisionNow,
              },
      });

      return jsonResponse(artifacts.result, 200);
    } catch {
      // A decision without its required audit record is never returned as an
      // authorization. No guarded tool can execute from this failure response.
      await abandonClaim(repositories, activeClaim);
      return jsonResponse(
        {
          error:
            activeClaim === null
              ? "AUDIT_PERSISTENCE_UNAVAILABLE"
              : "IDEMPOTENCY_UNAVAILABLE",
        },
        503,
      );
    }
  }

  async function handleApprovalConsume(
    request: Request,
    env: Env,
    approvalId: string,
    repositories: SecurityRepositories,
  ): Promise<Response> {
    const principal = await authenticateAgent(request, env, repositories);
    if (principal instanceof Response) {
      return principal;
    }
    if (request.method !== "POST") {
      return jsonResponse(
        { error: "METHOD_NOT_ALLOWED" },
        405,
        { allow: "POST" },
      );
    }

    const trustedRequest = await readTrustedActionRequest(request, principal);
    if (trustedRequest instanceof Response) {
      return trustedRequest;
    }

    try {
      const outcome = await consumeApprovedAction({
        approval_id: approvalId,
        request: trustedRequest,
        principal,
        approvals: repositories.approvals,
        now: unixSeconds(currentTime()),
      });
      if (!outcome.authorized) {
        return jsonResponse(
          { error: outcome.error },
          consumeFailureStatus(outcome.error),
        );
      }

      return jsonResponse(outcome, 200);
    } catch {
      // The D1 conditional transition and its lifecycle audit trigger are one
      // database operation. Any persistence failure therefore authorizes none.
      return jsonResponse({ error: "APPROVAL_CONSUME_UNAVAILABLE" }, 503);
    }
  }

  async function handleApprovalDecision(
    request: Request,
    env: Env,
    approvalId: string,
    decision: "APPROVED" | "REJECTED",
    repositories: SecurityRepositories,
  ): Promise<Response> {
    const authenticationFailure = await authenticateOperatorRequest(
      request,
      env,
      repositories,
    );
    if (authenticationFailure !== null) {
      return authenticationFailure;
    }
    if (request.method !== "POST") {
      return jsonResponse(
        { error: "METHOD_NOT_ALLOWED" },
        405,
        { allow: "POST" },
      );
    }

    const operatorId = getOperatorIdentity(env);
    if (!validOperatorIdentity(operatorId)) {
      return jsonResponse({ error: "OPERATOR_IDENTITY_UNAVAILABLE" }, 503);
    }

    try {
      const outcome = await repositories.approvals.decide({
        id: approvalId,
        decision,
        decided_by: operatorId,
        now: unixSeconds(currentTime()),
      });

      if (outcome.kind === "not_found") {
        return jsonResponse({ error: "APPROVAL_NOT_FOUND" }, 404);
      }
      if (outcome.kind === "expired") {
        return jsonResponse({ error: "APPROVAL_EXPIRED" }, 410);
      }
      if (outcome.kind === "conflict") {
        return jsonResponse(
          { error: "APPROVAL_NOT_PENDING", status: outcome.approval.status },
          409,
        );
      }

      // A decision without an append-only lifecycle audit record must never
      // be treated as an approved or rejected operator action.
      if (outcome.audit_persisted !== true) {
        return jsonResponse({ error: "APPROVAL_DECISION_UNAVAILABLE" }, 503);
      }

      return jsonResponse({ approval: publicApproval(outcome.approval) }, 200);
    } catch {
      return jsonResponse({ error: "APPROVAL_DECISION_UNAVAILABLE" }, 503);
    }
  }

  async function handleAuditList(
    request: Request,
    env: Env,
    url: URL,
    repositories: SecurityRepositories,
  ): Promise<Response> {
    const authenticationFailure = await authenticateOperatorRequest(
      request,
      env,
      repositories,
    );
    if (authenticationFailure !== null) {
      return authenticationFailure;
    }
    if (request.method !== "GET") {
      return jsonResponse(
        { error: "METHOD_NOT_ALLOWED" },
        405,
        { allow: "GET" },
      );
    }

    const query = parseAuditQuery(url);
    if (!query.ok) {
      return jsonResponse({ error: "INVALID_QUERY" }, 400);
    }

    try {
      const events = await repositories.audit.list(query.value);
      return jsonResponse({ audit_events: events.map(publicAudit) }, 200);
    } catch {
      return jsonResponse({ error: "AUDIT_UNAVAILABLE" }, 503);
    }
  }

  async function handleApprovalList(
    request: Request,
    env: Env,
    url: URL,
    repositories: SecurityRepositories,
  ): Promise<Response> {
    const authenticationFailure = await authenticateOperatorRequest(
      request,
      env,
      repositories,
    );
    if (authenticationFailure !== null) {
      return authenticationFailure;
    }
    if (request.method !== "GET") {
      return jsonResponse(
        { error: "METHOD_NOT_ALLOWED" },
        405,
        { allow: "GET" },
      );
    }

    const query = parseApprovalQuery(url);
    if (!query.ok) {
      return jsonResponse({ error: "INVALID_QUERY" }, 400);
    }

    try {
      const approvals = await repositories.approvals.list({
        ...query.value,
        now: unixSeconds(currentTime()),
      });
      return jsonResponse(
        { approvals: approvals.map(publicApproval) },
        200,
      );
    } catch {
      return jsonResponse({ error: "APPROVALS_UNAVAILABLE" }, 503);
    }
  }

  async function handleOperatorSession(
    request: Request,
    env: Env,
    repositories: SecurityRepositories,
  ): Promise<Response> {
    if (request.method === "DELETE") {
      const authenticationFailure = await authenticateOperatorRequest(
        request,
        env,
        repositories,
      );
      if (authenticationFailure !== null) return authenticationFailure;

      return jsonResponse(
        { authenticated: false },
        200,
        { "set-cookie": clearOperatorSessionCookie() },
      );
    }

    if (request.method !== "POST") {
      return jsonResponse(
        { error: "METHOD_NOT_ALLOWED" },
        405,
        { allow: "POST, DELETE" },
      );
    }

    // Session issuance is a browser state-changing operation. Requiring an
    // exact Origin prevents a cross-site form or fetch from minting a cookie,
    // while command-line operators can continue to use bearer authentication
    // directly on the operator APIs.
    if (!hasSameOrigin(request)) {
      return jsonResponse({ error: "ORIGIN_FORBIDDEN" }, 403);
    }

    const body = await readJsonBody(request);
    if (
      !body.ok ||
      !isObject(body.value) ||
      !hasExactKeys(body.value, ["operator_api_key"]) ||
      typeof body.value.operator_api_key !== "string" ||
      body.value.operator_api_key.length > 1_024
    ) {
      return jsonResponse(
        { error: body.ok ? "INVALID_REQUEST" : body.error },
        400,
      );
    }

    const supplied = body.value.operator_api_key;
    const configured = getOperatorSecret(env);
    try {
      // A credential present in the Agent-key table never acquires operator
      // authority, even under an unsafe secret-binding configuration.
      const agentRecord = await repositories.principals.findByKeyHash(
        await sha256Hex(supplied),
      );
      if (agentRecord !== null) {
        return jsonResponse({ error: "INVALID_OPERATOR_KEY" }, 401);
      }

      const authentication = await authenticateOperatorCredential(
        supplied,
        configured,
      );
      if (!authentication.ok) {
        return authentication.reason === "unavailable"
          ? jsonResponse({ error: "OPERATOR_AUTHENTICATION_UNAVAILABLE" }, 503)
          : jsonResponse({ error: "INVALID_OPERATOR_KEY" }, 401);
      }
      if (configured === undefined) {
        return jsonResponse(
          { error: "OPERATOR_AUTHENTICATION_UNAVAILABLE" },
          503,
        );
      }

      const session = await issueOperatorSession(
        configured,
        unixSeconds(currentTime()),
      );
      return jsonResponse(
        {
          authenticated: true,
          expires_at: new Date(session.expires_at * 1_000).toISOString(),
        },
        200,
        { "set-cookie": session.cookie },
      );
    } catch {
      return jsonResponse({ error: "OPERATOR_AUTHENTICATION_UNAVAILABLE" }, 503);
    }
  }

  async function handleOperatorOverview(
    request: Request,
    env: Env,
    url: URL,
    repositories: SecurityRepositories,
  ): Promise<Response> {
    const authenticationFailure = await authenticateOperatorRequest(
      request,
      env,
      repositories,
    );
    if (authenticationFailure !== null) return authenticationFailure;
    if (request.method !== "GET") {
      return jsonResponse({ error: "METHOD_NOT_ALLOWED" }, 405, { allow: "GET" });
    }
    if (url.search !== "") return jsonResponse({ error: "INVALID_QUERY" }, 400);
    if (repositories.overview === undefined) {
      return jsonResponse({ error: "OVERVIEW_UNAVAILABLE" }, 503);
    }

    const now = currentTime();
    try {
      const [metrics, recentActivity] = await Promise.all([
        repositories.overview.getMetrics(utcDay(now), unixSeconds(now)),
        repositories.audit.list({ limit: 10 }),
      ]);
      return jsonResponse(
        {
          policy_version: POLICY_VERSION,
          metrics: {
            allowed: metrics.allowed,
            blocked: metrics.blocked,
            pending_approvals: metrics.pending_approvals,
            approval_required: metrics.approval_required,
            ai_quota_usage: {
              used_today: metrics.ai_quota_used_today,
              daily_limit: metrics.ai_daily_limit,
            },
          },
          recent_activity: recentActivity.map(publicAudit),
        },
        200,
      );
    } catch {
      return jsonResponse({ error: "OVERVIEW_UNAVAILABLE" }, 503);
    }
  }

  async function handleApiKeys(
    request: Request,
    env: Env,
    url: URL,
    repositories: SecurityRepositories,
  ): Promise<Response> {
    const authenticationFailure = await authenticateOperatorRequest(
      request,
      env,
      repositories,
    );
    if (authenticationFailure !== null) return authenticationFailure;
    if (repositories.apiKeys === undefined) {
      return jsonResponse({ error: "API_KEYS_UNAVAILABLE" }, 503);
    }

    if (request.method === "GET") {
      const query = parseApiKeyQuery(url);
      if (!query.ok) return jsonResponse({ error: "INVALID_QUERY" }, 400);
      try {
        const apiKeys = await repositories.apiKeys.list(query.value);
        return jsonResponse({ api_keys: apiKeys.map(publicApiKey) }, 200);
      } catch {
        return jsonResponse({ error: "API_KEYS_UNAVAILABLE" }, 503);
      }
    }

    if (request.method !== "POST") {
      return jsonResponse(
        { error: "METHOD_NOT_ALLOWED" },
        405,
        { allow: "GET, POST" },
      );
    }
    if (url.search !== "") return jsonResponse({ error: "INVALID_QUERY" }, 400);

    const rawBody = await readJsonBody(request);
    if (!rawBody.ok) return jsonResponse({ error: rawBody.error }, 400);
    const body = parseApiKeyCreateBody(rawBody.value);
    if (body === null) return jsonResponse({ error: "INVALID_REQUEST" }, 400);

    try {
      const issued = await issueApiKeyMaterial();
      const result = await repositories.apiKeys.create({
        ...body,
        principal_id: `aagp_${crypto.randomUUID()}`,
        key_id: issued.key_id,
        key_hash: issued.key_hash,
        key_prefix: issued.key_prefix,
        created_at: unixSeconds(currentTime()),
      });
      if (result.kind === "principal_tenant_conflict") {
        return jsonResponse({ error: "PRINCIPAL_TENANT_CONFLICT" }, 409);
      }
      if (result.kind === "conflict") {
        return jsonResponse({ error: "API_KEY_CONFLICT" }, 409);
      }

      // This is the only response that contains the raw key. Storage received
      // only its SHA-256 digest and the non-secret display prefix.
      return jsonResponse(
        {
          api_key: publicApiKey(result.api_key),
          raw_api_key: issued.raw_api_key,
        },
        201,
      );
    } catch {
      return jsonResponse({ error: "API_KEYS_UNAVAILABLE" }, 503);
    }
  }

  async function handleApiKeyRevoke(
    request: Request,
    env: Env,
    keyId: string,
    repositories: SecurityRepositories,
  ): Promise<Response> {
    const authenticationFailure = await authenticateOperatorRequest(
      request,
      env,
      repositories,
    );
    if (authenticationFailure !== null) return authenticationFailure;
    if (request.method !== "POST") {
      return jsonResponse({ error: "METHOD_NOT_ALLOWED" }, 405, { allow: "POST" });
    }
    if (new URL(request.url).search !== "") {
      return jsonResponse({ error: "INVALID_QUERY" }, 400);
    }
    if (repositories.apiKeys === undefined) {
      return jsonResponse({ error: "API_KEYS_UNAVAILABLE" }, 503);
    }

    try {
      const result = await repositories.apiKeys.revoke(
        keyId,
        unixSeconds(currentTime()),
      );
      if (result.kind === "not_found") {
        return jsonResponse({ error: "API_KEY_NOT_FOUND" }, 404);
      }
      if (result.kind === "already_revoked") {
        return jsonResponse({ error: "API_KEY_ALREADY_REVOKED" }, 409);
      }
      return jsonResponse({ api_key: publicApiKey(result.api_key) }, 200);
    } catch {
      return jsonResponse({ error: "API_KEYS_UNAVAILABLE" }, 503);
    }
  }

  async function handlePolicies(
    request: Request,
    env: Env,
    url: URL,
    repositories: SecurityRepositories,
  ): Promise<Response> {
    const authenticationFailure = await authenticateOperatorRequest(
      request,
      env,
      repositories,
    );
    if (authenticationFailure !== null) return authenticationFailure;
    if (request.method !== "GET") {
      return jsonResponse({ error: "METHOD_NOT_ALLOWED" }, 405, { allow: "GET" });
    }
    if (url.search !== "") return jsonResponse({ error: "INVALID_QUERY" }, 400);

    return jsonResponse(
      {
        policy_version: POLICY_VERSION,
        policies: BUILT_IN_POLICY_METADATA,
      },
      200,
    );
  }

  async function handlePublicBeta(request: Request, env: Env, repositories: SecurityRepositories, kind: "event" | "interest"): Promise<Response> {
    if (request.method !== "POST") return jsonResponse({ error: "METHOD_NOT_ALLOWED" }, 405, { allow: "POST" });
    if (!hasSameOrigin(request)) return jsonResponse({ error: "ORIGIN_FORBIDDEN" }, 403);
    if (new URL(request.url).search !== "") return jsonResponse({ error: "INVALID_QUERY" }, 400);
    // CF-Connecting-IP is supplied by the platform. Hash it so the limiter
    // never sees an address; the fallback is one shared conservative bucket.
    try {
      const bucket = `public-beta:${await sha256Hex(request.headers.get("cf-connecting-ip") ?? "unknown")}`;
      if (!(await createRateLimiter(env).allow(bucket))) return jsonResponse({ error: "RATE_LIMIT_EXCEEDED" }, 429);
    } catch { return jsonResponse({ error: "RATE_LIMIT_UNAVAILABLE" }, 503); }
    const parsed = await readJsonBody(request);
    if (!parsed.ok) return jsonResponse({ error: parsed.error }, 400);
    if (repositories.beta === undefined) return jsonResponse({ error: "BETA_UNAVAILABLE" }, 503);
    try {
      if (kind === "event") {
        const event = parsePublicEvent(parsed.value);
        if (event === null) return jsonResponse({ error: "INVALID_REQUEST" }, 400);
        await repositories.beta.recordPublicEvent(event, utcDay(currentTime()));
        return jsonResponse({ recorded: true }, 202);
      }
      const interest = parseBetaInterest(parsed.value, unixSeconds(currentTime()));
      if (interest === null) return jsonResponse({ error: "INVALID_REQUEST" }, 400);
      await repositories.beta.createInterest(interest);
      return jsonResponse({ recorded: true }, 202);
    } catch { return jsonResponse({ error: "BETA_UNAVAILABLE" }, 503); }
  }

  async function handleBetaFunnel(request: Request, env: Env, repositories: SecurityRepositories): Promise<Response> {
    const failure = await authenticateOperatorRequest(request, env, repositories);
    if (failure !== null) return failure;
    if (request.method !== "GET") return jsonResponse({ error: "METHOD_NOT_ALLOWED" }, 405, { allow: "GET" });
    if (new URL(request.url).search !== "") return jsonResponse({ error: "INVALID_QUERY" }, 400);
    if (repositories.beta === undefined) return jsonResponse({ error: "BETA_UNAVAILABLE" }, 503);
    try { return jsonResponse({ events: await repositories.beta.funnel() }, 200); }
    catch { return jsonResponse({ error: "BETA_UNAVAILABLE" }, 503); }
  }

  return {
    async fetch(request: Request, env: Env): Promise<Response> {
      const url = new URL(request.url);

      if (url.pathname === "/health" && request.method === "GET") {
        return jsonResponse(
          { status: "ok", service: "agent-action-gate" },
          200,
        );
      }

      const route = approvalRoute(url.pathname);
      const apiKeyId = apiKeyRevokeRoute(url.pathname);
      const knownRoute =
        url.pathname === "/v1/evaluate" ||
        url.pathname === "/v1/audit" ||
        url.pathname === "/v1/approvals" ||
        url.pathname === "/v1/operator/session" ||
        url.pathname === "/v1/operator/overview" ||
        url.pathname === "/v1/api-keys" ||
        url.pathname === "/v1/policies" ||
        url.pathname === "/v1/product-events" ||
        url.pathname === "/v1/beta-interest" ||
        url.pathname === "/v1/operator/beta-funnel" ||
        route !== null ||
        apiKeyId !== null;
      if (!knownRoute) {
        return jsonResponse({ error: "NOT_FOUND" }, 404);
      }

      let repositories: SecurityRepositories;
      try {
        repositories = createRepositories(env);
      } catch {
        return jsonResponse({ error: "SECURITY_STATE_UNAVAILABLE" }, 503);
      }

      if (url.pathname === "/v1/evaluate") {
        return handleEvaluation(request, env, repositories);
      }
      if (url.pathname === "/v1/product-events") return handlePublicBeta(request, env, repositories, "event");
      if (url.pathname === "/v1/beta-interest") return handlePublicBeta(request, env, repositories, "interest");
      if (url.pathname === "/v1/operator/beta-funnel") return handleBetaFunnel(request, env, repositories);
      if (url.pathname === "/v1/operator/session") {
        return handleOperatorSession(request, env, repositories);
      }
      if (url.pathname === "/v1/operator/overview") {
        return handleOperatorOverview(request, env, url, repositories);
      }
      if (url.pathname === "/v1/audit") {
        return handleAuditList(request, env, url, repositories);
      }
      if (url.pathname === "/v1/approvals") {
        return handleApprovalList(request, env, url, repositories);
      }
      if (url.pathname === "/v1/api-keys") {
        return handleApiKeys(request, env, url, repositories);
      }
      if (apiKeyId !== null) {
        return handleApiKeyRevoke(request, env, apiKeyId, repositories);
      }
      if (url.pathname === "/v1/policies") {
        return handlePolicies(request, env, url, repositories);
      }

      if (route === null) {
        return jsonResponse({ error: "NOT_FOUND" }, 404);
      }
      if (route.action === "consume") {
        return handleApprovalConsume(
          request,
          env,
          route.approvalId,
          repositories,
        );
      }

      return handleApprovalDecision(
        request,
        env,
        route.approvalId,
        route.action === "approve" ? "APPROVED" : "REJECTED",
        repositories,
      );
    },
  } satisfies ExportedHandler<Env>;
}

export default createWorker();
