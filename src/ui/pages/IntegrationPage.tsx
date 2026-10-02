import { useState } from "react";
import { CopyButton, PageHeader } from "../components";
import { BlockIcon, CheckIcon, ClockIcon, CodeIcon } from "../icons";

const EXAMPLES = {
  HTTP: `curl --request POST https://your-gate.example/v1/evaluate \\
  --header 'Authorization: Bearer <agent-key>' \\
  --header 'Content-Type: application/json' \\
  --header 'Idempotency-Key: <unique-request-id>' \\
  --data '{
    "agent_role": "support_agent",
    "tool_name": "crm.read_contact",
    "arguments_json": "{\\"contact_id\\":\\"contact-42\\",\\"target_tenant\\":\\"acme\\"}",
    "source_text": "Look up the customer record",
    "request_tenant": "acme"
  }'`,
  TypeScript: `const response = await fetch("https://your-gate.example/v1/evaluate", {
  method: "POST",
  headers: {
    Authorization: \`Bearer \${process.env.AGENT_ACTION_GATE_KEY}\`,
    "Content-Type": "application/json",
    "Idempotency-Key": crypto.randomUUID(),
  },
  body: JSON.stringify({
    agent_role: "support_agent",
    tool_name: "crm.read_contact",
    arguments_json: JSON.stringify({
      contact_id: "contact-42",
      target_tenant: "acme",
    }),
    source_text: "Look up the customer record",
    request_tenant: "acme",
  }),
});

const result = await response.json();

if (result.decision === "ALLOW") {
  // Execute only through your guarded tool runner.
}`,
  MCP: `import { createLocalMcpJsonRpcHandler } from
  "./src/integrations/local-mcp-server";

// runner and executors are trusted server-side adapters owned by your host.
const mcp = createLocalMcpJsonRpcHandler({
  runner,
  executors,
  getTrustedContext: () => ({
    agent_role: "support_agent",
    request_tenant: "acme",
    source_text: "Trusted host context",
  }),
});

// Connect your chosen stdio or HTTP transport to mcp.handle(request).
const response = await mcp.handle({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: {
    name: "crm_read_contact",
    arguments: { contact_id: "contact-42", target_tenant: "acme" },
  },
});`,
} as const;

type ExampleKind = keyof typeof EXAMPLES;

export function IntegrationPage() {
  const [active, setActive] = useState<ExampleKind>("HTTP");

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Agent integration"
        title="Put the gate before the tool"
        description="Submit proposed actions for a decision, then honor the result before any external side effect."
      />
      <section className="decision-contract">
        <article className="contract-allow">
          <CheckIcon />
          <div><strong>ALLOW</strong><p>Execute the normalized tool call through the guarded runner.</p></div>
        </article>
        <article className="contract-deny">
          <BlockIcon />
          <div><strong>DENY</strong><p>Do not execute. Treat the policy codes as machine-readable reasons.</p></div>
        </article>
        <article className="contract-approval">
          <ClockIcon />
          <div><strong>REQUIRE_APPROVAL</strong><p>Pause. Execute only after valid one-time approval consumption succeeds.</p></div>
        </article>
      </section>

      <section className="panel code-panel">
        <header className="code-header">
          <div><CodeIcon /><div><span className="panel-kicker">Quick start</span><h2>Request an authorization decision</h2></div></div>
          <CopyButton value={EXAMPLES[active]} label="Copy example" />
        </header>
        <div className="code-tabs" role="tablist" aria-label="Integration language">
          {(Object.keys(EXAMPLES) as ExampleKind[]).map((kind) => (
            <button
              role="tab"
              aria-selected={active === kind}
              className={active === kind ? "active" : ""}
              type="button"
              key={kind}
              onClick={() => setActive(kind)}
            >
              {kind}
            </button>
          ))}
        </div>
        <pre aria-label={`${active} integration example`}><code>{EXAMPLES[active]}</code></pre>
        <footer>
          Examples use placeholders only. Keep agent keys in your server-side secret manager, never in browser code or source control.
        </footer>
      </section>

      <section className="integration-notes">
        <article><span>01</span><div><h3>Send intent, not execution</h3><p>The proposed tool name, JSON arguments, source context, and tenant go to the gate first.</p></div></article>
        <article><span>02</span><div><h3>Honor the deterministic result</h3><p>Semantic classification contributes risk signals. It cannot turn a blocked action into an allow.</p></div></article>
        <article><span>03</span><div><h3>Keep side effects guarded</h3><p>Do not expose direct tool implementations to an agent that could bypass the authorization result.</p></div></article>
      </section>
    </div>
  );
}
