export type Decision = "ALLOW" | "REQUIRE_APPROVAL" | "DENY";
export type ApprovalStatus =
  | "PENDING"
  | "APPROVED"
  | "REJECTED"
  | "EXPIRED"
  | "CONSUMED";

export interface OverviewMetric {
  label: string;
  value: number;
}

export interface RecentActivity {
  id: string;
  event_type: string;
  decision: Decision | null;
  tool_name: string;
  tenant_id: string;
  policy_codes: string[];
  created_at: number;
}

export interface Overview {
  policy_version: string;
  metrics: {
    allowed: number;
    blocked: number;
    pending_approvals: number;
    approval_required: number;
    ai_quota_usage: {
      used_today: number;
      daily_limit: number;
    };
  };
  recent_activity: AuditEvent[];
}

export interface Approval {
  approval_id: string;
  principal_id: string;
  tenant_id: string;
  tool_name: string;
  risk_level: string;
  policy_codes: string[];
  policy_version: string;
  approval_display:
    | { kind: "email_send"; recipient: string; subject?: string; has_attachments: boolean }
    | { kind: "refund_create"; amount_minor: number; currency?: string; order_id?: string }
    | { kind: "generic" };
  status: ApprovalStatus;
  created_at: number;
  expires_at: number;
  decided_at: number | null;
  consumed_at: number | null;
}

export interface AuditEvent {
  id: string;
  request_id: string;
  principal_id: string;
  key_id: string | null;
  tenant_id: string;
  tool_name: string;
  event_type: string;
  decision: Decision | null;
  risk_level: string | null;
  policy_codes: string[];
  approval_id: string | null;
  policy_version: string;
  created_at: number;
}

export interface ApiKeyMetadata {
  key_id: string;
  key_prefix: string;
  tenant_id: string;
  label: string;
  status: "active" | "revoked";
  created_at: number;
  revoked_at: number | null;
  daily_ai_limit: number;
}

export interface PolicyMetadata {
  id: string;
  outcome: Decision;
  summary: string;
  policy_codes: string[];
}

interface ErrorEnvelope {
  error?: unknown;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function requestJson<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers();
  headers.set("accept", "application/json");
  if (init.body !== undefined && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }

  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "same-origin",
    redirect: "error",
  });

  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    if (response.ok) {
      throw new ApiError("The server returned an unreadable response.", 502, "INVALID_RESPONSE");
    }
  }

  if (!response.ok) {
    const envelope: ErrorEnvelope = isRecord(body) ? body : {};
    const code = typeof envelope.error === "string" ? envelope.error : "REQUEST_FAILED";
    throw new ApiError(readableError(code), response.status, code);
  }

  return body as T;
}

function readableError(code: string): string {
  switch (code) {
    case "UNAUTHORIZED":
      return "Your operator session is no longer valid.";
    case "INVALID_OPERATOR_KEY":
      return "That operator key was not accepted.";
    case "APPROVAL_NOT_PENDING":
      return "This approval has already been decided.";
    case "APPROVAL_EXPIRED":
      return "This approval has expired.";
    case "ORIGIN_FORBIDDEN":
      return "The request origin was rejected.";
    default:
      return "The request could not be completed.";
  }
}

function queryString(values: Record<string, string | number | undefined>): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "") {
      query.set(key, String(value));
    }
  }
  const encoded = query.toString();
  return encoded === "" ? "" : `?${encoded}`;
}

export const api = {
  betaFunnel() {
    return requestJson<{ events: Record<"demo_scenario_run" | "developer_quickstart_view" | "api_key_created" | "first_evaluation" | "first_approval_created" | "first_approval_consumed", number> }>("/v1/operator/beta-funnel");
  },
  createSession(operatorKey: string) {
    return requestJson<{ authenticated: true; expires_at: string }>(
      "/v1/operator/session",
      {
        method: "POST",
        body: JSON.stringify({ operator_api_key: operatorKey }),
      },
    );
  },

  deleteSession() {
    return requestJson<{ authenticated: false }>("/v1/operator/session", {
      method: "DELETE",
    });
  },

  overview() {
    return requestJson<Overview>("/v1/operator/overview");
  },

  approvals(filters: { status?: ApprovalStatus; tenant_id?: string; limit?: number } = {}) {
    return requestJson<{ approvals: Approval[] }>(
      `/v1/approvals${queryString(filters)}`,
    );
  },

  decideApproval(approvalId: string, action: "approve" | "reject") {
    return requestJson<{ approval: Approval }>(
      `/v1/approvals/${encodeURIComponent(approvalId)}/${action}`,
      { method: "POST" },
    );
  },

  audit(filters: {
    decision?: Decision;
    tool_name?: string;
    tenant_id?: string;
    created_from?: number;
    created_to?: number;
    limit?: number;
  }) {
    return requestJson<{ audit_events: AuditEvent[] }>(
      `/v1/audit${queryString(filters)}`,
    );
  },

  apiKeys() {
    return requestJson<{ api_keys: ApiKeyMetadata[] }>("/v1/api-keys");
  },

  createApiKey(input: {
    tenant_id: string;
    label: string;
    daily_ai_limit: number;
  }) {
    return requestJson<{ api_key: ApiKeyMetadata; raw_api_key: string }>(
      "/v1/api-keys",
      { method: "POST", body: JSON.stringify(input) },
    );
  },

  revokeApiKey(keyId: string) {
    return requestJson<{ api_key: ApiKeyMetadata }>(
      `/v1/api-keys/${encodeURIComponent(keyId)}/revoke`,
      { method: "POST" },
    );
  },

  policies() {
    return requestJson<{ policy_version: string; policies: PolicyMetadata[] }>(
      "/v1/policies",
    );
  },
};
