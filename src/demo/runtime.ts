import type { EvaluationResult, JsonObject, SemanticRiskSignals } from "../contracts";
import { evaluatePreparedAction, prepareEvaluation } from "../evaluate";
import { normalizeToolCall } from "../normalize";
import { normalizeSemanticRisk } from "../risk";
import { DEMO_SCENARIOS, DEMO_TENANT, type DemoScenarioId } from "./scenarios";

const CONTACTS = Object.freeze({
  "demo-contact-1": Object.freeze({ id: "demo-contact-1", name: "Alex Example", email: "alex@example.invalid" }),
});

export interface DemoRun {
  scenario_id: DemoScenarioId;
  input: { agent_role: string; tool_name: string; arguments_json: string; source_text: string; request_tenant: string };
  normalized: { agent_role: string; tool_name: string; request_tenant: string; target_tenant: string; amount_minor: number | null; recipient: string };
  semantic: { evaluated: boolean; signals: SemanticRiskSignals | null; confidence: string | null; reason: string | null };
  result: EvaluationResult;
  fake_effect: string | null;
}

function scenarioById(id: string) {
  const scenario = DEMO_SCENARIOS.find((item) => item.id === id);
  if (scenario === undefined) throw new TypeError("unknown demo scenario");
  return scenario;
}

/** Fixed data only. This module has no network, secret, Worker, or real-tool imports. */
function fakeToolEffect(tool: string, args: JsonObject): string {
  if (tool === "crm.read_contact") {
    const id = args.contact_id;
    if (id !== "demo-contact-1") throw new TypeError("unknown fictional contact");
    const contact = CONTACTS[id];
    return `Fake CRM: ${contact.name} (${contact.email}).`;
  }
  if (tool === "email.send") return "Fake email sender: message recorded in this browser only; nothing was sent.";
  if (tool === "refund.create") return "Fake refund executor: no payment or account was changed.";
  throw new TypeError("demo tool is not available");
}

export async function runDemoScenario(id: DemoScenarioId): Promise<DemoRun> {
  const scenario = scenarioById(id);
  const prepared = prepareEvaluation(scenario.input);
  // All scenarios use fixed fake tenants. The cross-tenant case exists only to
  // demonstrate denial and can never reach a fake executor.
  const normalized = normalizeToolCall(scenario.input).normalized;
  const evaluated = prepared.kind === "needs_semantic";
  const result = evaluated
    ? await evaluatePreparedAction(prepared, () => scenario.risk)
    : prepared.result;
  const signals = evaluated ? normalizeSemanticRisk(scenario.risk) : null;
  const fakeEffect = result.decision === "ALLOW" && normalized.target_tenant === DEMO_TENANT
    ? fakeToolEffect(result.normalized_tool, result.normalized_args)
    : null;

  return {
    scenario_id: scenario.id,
    input: { ...scenario.input },
    normalized: {
      agent_role: normalized.agent_role,
      tool_name: normalized.tool_name,
      request_tenant: normalized.request_tenant,
      target_tenant: normalized.target_tenant,
      amount_minor: normalized.amount_minor,
      recipient: normalized.recipient,
    },
    semantic: {
      evaluated,
      signals,
      confidence: evaluated ? scenario.risk.confidence : null,
      reason: evaluated ? scenario.risk.reason : null,
    },
    result,
    fake_effect: fakeEffect,
  };
}

/** Explicit sandbox-only approval simulation; never changes a real approval. */
export async function simulateFakeApproval(id: DemoScenarioId): Promise<string> {
  const run = await runDemoScenario(id);
  if (run.result.decision !== "REQUIRE_APPROVAL" || run.normalized.target_tenant !== DEMO_TENANT) {
    throw new TypeError("scenario is not approval eligible");
  }
  return fakeToolEffect(run.result.normalized_tool, run.result.normalized_args);
}
