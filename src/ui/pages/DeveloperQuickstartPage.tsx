import { useEffect, useState } from "react";
import { recordPublicEvent } from "../telemetry";

const curlExample = `curl -X POST "$BASE_URL/v1/evaluate" \\
  -H "Authorization: Bearer $TEST_AGENT_KEY" \\
  -H 'Content-Type: application/json' \\
  -d '{"agent_role":"support_agent","tool_name":"crm.read_contact","arguments_json":"{\\"contact_id\\":\\"example-1\\",\\"target_tenant\\":\\"your-test-tenant\\"}","source_text":"Read a test contact","request_tenant":"your-test-tenant"}'`;

const tsExample = `import { AgentActionGate } from "@agent-action-gate/sdk";

const gate = new AgentActionGate({
  baseUrl: process.env.GATE_BASE_URL!,
  apiKey: process.env.TEST_AGENT_KEY!,
});
const result = await gate.evaluate({
  agent_role: "support_agent",
  tool_name: "crm.read_contact",
  arguments_json: JSON.stringify({ contact_id: "example-1", target_tenant: "your-test-tenant" }),
  source_text: "Read a test contact",
  request_tenant: "your-test-tenant",
});
if (result.decision === "ALLOW") { /* separately execute your guarded tool */ }
else if (result.decision === "REQUIRE_APPROVAL") { /* queue human review; do not execute */ }
else { /* deny and stop */ }`;

type Integration = "MCP" | "Dify" | "custom_agent" | "other";
type Volume = "under_1k" | "1k_to_10k" | "10k_to_100k" | "over_100k";

export function DeveloperQuickstartPage({ onHome, onDemo }: { onHome: () => void; onDemo: () => void }) {
  const [email, setEmail] = useState("");
  const [integration, setIntegration] = useState<Integration>("custom_agent");
  const [volume, setVolume] = useState<Volume>("under_1k");
  const [status, setStatus] = useState("");
  useEffect(() => { recordPublicEvent("developer_quickstart_view"); }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setStatus("Submitting…");
    try {
      const response = await fetch("/v1/beta-interest", { method: "POST", headers: { "content-type": "application/json" }, credentials: "same-origin", body: JSON.stringify({ email, intended_integration: integration, approximate_monthly_tool_calls: volume }) });
      setStatus(response.ok ? "Interest recorded. No email will be sent automatically." : "Unable to record interest right now.");
    } catch { setStatus("Unable to record interest right now."); }
  }

  return <main className="public-page">
    <nav className="public-nav"><button className="brand brand-button" onClick={onHome}>Agent Action Gate</button><button className="button button-secondary" onClick={onDemo}>Try demo</button></nav>
    <p className="eyebrow">Developer quickstart · beta v0.1</p><h1>Put the gate before execution.</h1>
    <p>Create a tenant-bound test key in the operator console, store it in your server environment as <code>TEST_AGENT_KEY</code>, then call the evaluation endpoint from your server. Never put an API key in browser code.</p>
    <ol className="quickstart-steps"><li><strong>Create a test tenant key.</strong> An operator issues a key scoped to your test tenant with a small daily AI quota.</li><li><strong>Evaluate each proposed action.</strong> The gate returns ALLOW, DENY, or REQUIRE_APPROVAL.</li><li><strong>Handle the decision.</strong> Execute only ALLOW; stop on DENY; pause on REQUIRE_APPROVAL. Approval requires an operator, followed by a one-time consume using the exact original request.</li><li><strong>Optional MCP adapter.</strong> Wrap the actual tool handler so it cannot be called before evaluation and, where needed, approval consumption.</li></ol>
    <h2>HTTP example</h2><pre>{curlExample}</pre><h2>TypeScript SDK example</h2><pre>{tsExample}</pre>
    <p>The SDK source lives in <code>packages/sdk/</code> and is not published yet; link it locally for this import. See <code>docs/quickstart.md</code>, <code>docs/mcp-integration.md</code>, and <code>docs/dify-integration.md</code> for complete flow details.</p>
    <section className="beta-pricing"><p className="eyebrow">Proposed beta structure · not final pricing</p><div className="demo-grid"><article className="demo-card"><h2>Free / Sandbox</h2><p>Public fixture demo and a small evaluation quota for testing.</p></article><article className="demo-card"><h2>Developer Beta</h2><p>Higher quota, audit, human approval workflow, and MCP/HTTP SDK integration.</p></article></div><p>No paid plan or checkout is available yet.</p></section>
    <section className="beta-interest"><h2>Beta interest</h2><p>Only your email, intended integration, approximate call-volume band, and submission time are stored. No marketing email is sent.</p><form onSubmit={(event) => void submit(event)}><label>Email <input type="email" required maxLength={254} value={email} onChange={(event) => setEmail(event.target.value.trim().toLowerCase())} /></label><label>Integration <select value={integration} onChange={(event) => setIntegration(event.target.value as Integration)}><option value="MCP">MCP</option><option value="Dify">Dify</option><option value="custom_agent">Custom agent</option><option value="other">Other</option></select></label><label>Approximate monthly tool calls <select value={volume} onChange={(event) => setVolume(event.target.value as Volume)}><option value="under_1k">Under 1,000</option><option value="1k_to_10k">1,000–10,000</option><option value="10k_to_100k">10,000–100,000</option><option value="over_100k">Over 100,000</option></select></label><button className="button button-primary" type="submit">Register interest</button></form><p role="status">{status}</p></section>
  </main>;
}
