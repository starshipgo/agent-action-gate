/** Small, server-side-only HTTP client. It never executes tools or stores keys. */
export type Decision = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export interface ActionRequest {
  agent_role: string;
  tool_name: string;
  arguments_json: string;
  source_text: string;
  request_tenant: string;
}
interface DecisionBase {
  risk_level: RiskLevel;
  policy_codes: string[];
  normalized_tool: string;
  normalized_args: Record<string, unknown>;
}
export type EvaluationResult =
  | (DecisionBase & { decision: "ALLOW"; requires_approval: false; approval_id?: never })
  | (DecisionBase & { decision: "DENY"; requires_approval: false; approval_id?: never })
  | (DecisionBase & { decision: "REQUIRE_APPROVAL"; requires_approval: true; approval_id: string; expires_at: string });
export type ConsumeResult = { authorized: true; approval_id: string; tool_name: string; normalized_args: Record<string, unknown> };

export class GateHttpError extends Error {
  constructor(readonly status: number, readonly code: string) { super(`Agent Action Gate request failed: ${code} (${status})`); }
}

export class AgentActionGate {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly request: typeof fetch;

  constructor(options: { baseUrl: string; apiKey: string; fetch?: typeof fetch }) {
    const url = new URL(options.baseUrl);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.protocol !== "https:" && !(local && url.protocol === "http:")) throw new TypeError("HTTPS is required outside loopback development");
    if (url.username || url.password || url.search || url.hash) throw new TypeError("baseUrl must not contain credentials or query data");
    if (!options.apiKey || /[\r\n]/.test(options.apiKey)) throw new TypeError("invalid apiKey");
    this.baseUrl = url.origin + url.pathname.replace(/\/$/, "");
    this.apiKey = options.apiKey;
    this.request = options.fetch ?? fetch;
  }

  async evaluate(input: ActionRequest, options: { idempotencyKey?: string } = {}): Promise<EvaluationResult> {
    const headers: Record<string, string> = this.headers();
    if (options.idempotencyKey) headers["idempotency-key"] = options.idempotencyKey;
    const value = await this.post("/v1/evaluate", input, headers);
    if (!isObject(value) || !["ALLOW", "DENY", "REQUIRE_APPROVAL"].includes(String(value.decision)) || !Array.isArray(value.policy_codes) || !value.policy_codes.every((code) => typeof code === "string") || typeof value.normalized_tool !== "string" || !isObject(value.normalized_args) || !["low", "medium", "high", "critical"].includes(String(value.risk_level))) throw new TypeError("invalid evaluation response");
    if (value.decision === "REQUIRE_APPROVAL") {
      if (value.requires_approval !== true || typeof value.approval_id !== "string" || typeof value.expires_at !== "string") throw new TypeError("invalid approval response");
    } else if (value.requires_approval !== false) throw new TypeError("invalid decision response");
    return value as unknown as EvaluationResult;
  }

  /** Authorization only. The caller must separately decide whether/how to execute. */
  async consumeApproval(approvalId: string, exactOriginalRequest: ActionRequest): Promise<ConsumeResult> {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(approvalId)) throw new TypeError("invalid approval id");
    const value = await this.post(`/v1/approvals/${approvalId}/consume`, exactOriginalRequest, this.headers());
    if (!isObject(value) || value.authorized !== true || value.approval_id !== approvalId || typeof value.tool_name !== "string" || !isObject(value.normalized_args)) throw new TypeError("invalid consume response");
    return value as unknown as ConsumeResult;
  }

  private headers(): Record<string, string> { return { "authorization": `Bearer ${this.apiKey}`, "content-type": "application/json" }; }
  private async post(path: string, body: unknown, headers: Record<string, string>): Promise<unknown> {
    const response = await this.request(`${this.baseUrl}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    const payload: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      const code = isObject(payload) && typeof payload.error === "string" ? payload.error : "HTTP_ERROR";
      throw new GateHttpError(response.status, code);
    }
    return payload;
  }
}

function isObject(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
