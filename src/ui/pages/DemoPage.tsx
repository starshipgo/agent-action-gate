import { useState } from "react";
import { DEMO_SCENARIOS, type DemoScenarioId } from "../../demo/scenarios";
import { runDemoScenario, simulateFakeApproval, type DemoRun } from "../../demo/runtime";
import { recordPublicEvent } from "../telemetry";

export function DemoPage({ onHome, onQuickstart }: { onHome: () => void; onQuickstart: () => void }) {
  const [run, setRun] = useState<DemoRun | null>(null);
  const [fakeEffect, setFakeEffect] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function start(id: DemoScenarioId) {
    setError(null);
    setFakeEffect(null);
    try {
      setRun(await runDemoScenario(id));
      recordPublicEvent("demo_scenario_run");
    } catch {
      setError("This fixed demo scenario could not be evaluated.");
    }
  }

  async function simulate() {
    if (run === null) return;
    try {
      setFakeEffect(await simulateFakeApproval(run.scenario_id));
    } catch {
      setError("Fake approval simulation was not available.");
    }
  }

  return <main className="public-page">
    <nav className="public-nav"><button className="brand brand-button" onClick={onHome}>Agent Action Gate</button><button className="button button-secondary" onClick={onQuickstart}>Developer quickstart</button></nav>
    <div className="demo-banner" role="status">Demo environment — no real external actions are executed.</div>
    <p className="eyebrow">Fixed, fictional sandbox</p>
    <h1>Watch a proposed tool call meet the gate.</h1>
    <p>Six bounded scenarios use demo tenants, fictional records, fixture-based semantic signals, and fake executors. No API key or AI call is needed.</p>
    <div className="demo-grid">{DEMO_SCENARIOS.map((scenario) => <article className="demo-card" key={scenario.id}>
      <h2>{scenario.title}</h2><p>{scenario.description}</p>
      <button className="button button-primary" onClick={() => void start(scenario.id)}>Run scenario</button>
    </article>)}</div>
    {error && <p role="alert" className="danger-text">{error}</p>}
    {run && <section className="demo-trace" aria-live="polite">
      <h2>Decision trace: {DEMO_SCENARIOS.find((item) => item.id === run.scenario_id)?.title}</h2>
      <ol className="demo-stages">
        <li><h3>Input</h3><p>{run.input.agent_role} proposes <code>{run.input.tool_name}</code> for demo tenant <code>{run.input.request_tenant}</code>.</p><blockquote>{run.input.source_text}</blockquote><pre>{run.input.arguments_json}</pre></li>
        <li><h3>Normalize</h3><p>Tool: <code>{run.normalized.tool_name}</code>; target tenant: <code>{run.normalized.target_tenant}</code>; amount (minor units): {run.normalized.amount_minor ?? "n/a"}; recipient: {run.normalized.recipient || "n/a"}.</p></li>
        <li><h3>Semantic signals</h3>{run.semantic.evaluated ? <pre>{JSON.stringify(run.semantic.signals, null, 2)}</pre> : <p>Skipped: deterministic rule decided first.</p>}<p>Fixture signals are sensor evidence, never authorization.</p></li>
        <li><h3>Deterministic policy</h3><p>Codes: {run.result.policy_codes.join(", ")}. Risk: {run.result.risk_level}.</p></li>
        <li><h3>Final authorization</h3><strong>{run.result.decision}</strong><p>{run.fake_effect ?? "No fake tool action was performed."}</p>
          {run.result.decision === "REQUIRE_APPROVAL" && <button className="button button-secondary" onClick={() => void simulate()}>Simulate fake approval and action</button>}
          {fakeEffect && <p>{fakeEffect}</p>}
        </li>
      </ol>
      <p className="muted">This trace shows structured signals and policy evidence, not model reasoning or chain-of-thought.</p>
    </section>}
  </main>;
}
