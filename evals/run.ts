import type { ActionRequest, RawRiskSignals, SemanticRiskContext } from "../src/contracts";
import { evaluateAction } from "../src/evaluate";

export interface EvalCase { id: string; category: string; mode: "deterministic" | "semantic_fixture"; tool: string; args?: Record<string, unknown>; raw_args?: string; source: string; signals: Partial<RawRiskSignals>; expected: "ALLOW" | "DENY" | "REQUIRE_APPROVAL"; policy_code?: string; }
export interface EvalRow { id: string; category: string; mode: EvalCase["mode"]; expected: EvalCase["expected"]; actual: EvalCase["expected"]; passed: boolean; policy_codes: string[]; }
const benign: RawRiskSignals = { prompt_injection: false, data_exfiltration: false, social_engineering: false, suspicious_instruction: false, confidence: "low", reason: "Local fixture." };

/** Fixture mode never makes a network call. A provider is an explicit injection. */
export async function evaluateCorpus(cases: readonly EvalCase[], provider?: (context: SemanticRiskContext) => Promise<RawRiskSignals>) {
  const rows: EvalRow[] = [];
  for (const item of cases) {
    const input: ActionRequest = { agent_role: "test_agent", tool_name: item.tool, arguments_json: item.raw_args ?? JSON.stringify(item.args ?? {}), source_text: item.source, request_tenant: "eval-tenant" };
    const result = await evaluateAction(input, provider ?? (() => ({ ...benign, ...item.signals })));
    rows.push({ id: item.id, category: item.category, mode: item.mode, expected: item.expected, actual: result.decision, passed: result.decision === item.expected && (item.policy_code === undefined || result.policy_codes.some((code) => code === item.policy_code)), policy_codes: result.policy_codes });
  }
  return { kind: provider ? "provider_observation" : "fixture_regression", measured_semantic_accuracy: provider ? null : "not_measured", total: rows.length, passed: rows.filter((row) => row.passed).length, failed: rows.filter((row) => !row.passed).length, rows };
}

/** Explicit opt-in to an operator-supplied compatible provider endpoint. */
export function optionalProvider(enabled: boolean, env: Record<string, string | undefined> = Bun.env): ((context: SemanticRiskContext) => Promise<RawRiskSignals>) | undefined {
  if (!enabled) return undefined;
  if (env.AAG_EVAL_LIVE !== "1" || !env.AAG_EVAL_PROVIDER_URL || !env.AAG_EVAL_PROVIDER_TOKEN) throw new Error("Live evaluation requires --live, AAG_EVAL_LIVE=1, provider URL and token");
  const endpoint = new URL(env.AAG_EVAL_PROVIDER_URL);
  if (endpoint.protocol !== "https:") throw new Error("Provider URL must use HTTPS");
  return async (context) => {
    const response = await fetch(endpoint, { method: "POST", headers: { "authorization": `Bearer ${env.AAG_EVAL_PROVIDER_TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(context) });
    if (!response.ok) throw new Error(`Provider status ${response.status}`);
    const data: unknown = await response.json();
    const output = typeof data === "object" && data !== null && "response" in data ? data.response : data;
    if (typeof output !== "object" || output === null) throw new TypeError("invalid provider signals");
    return output as RawRiskSignals;
  };
}

if (import.meta.main) {
  const cases = await Bun.file(new URL("./cases.json", import.meta.url)).json() as EvalCase[];
  const live = Bun.argv.includes("--live");
  const report = await evaluateCorpus(cases, optionalProvider(live));
  await Bun.write(new URL("./report.json", import.meta.url), JSON.stringify(report, null, 2) + "\n");
  process.stdout.write(`Evaluation corpus: ${report.passed}/${report.total} passed (${report.kind})\n`);
  if (report.failed > 0) process.exitCode = 1;
}
