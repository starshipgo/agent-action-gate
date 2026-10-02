# Developer quickstart (beta v0.1)

Agent Action Gate decides whether a proposed tool call may proceed. It never executes your tool automatically. First try the browser's fixed-fixture `/demo`; it requires no key, calls no AI model, and performs no real external action.

## 1. Create a tenant-bound test key

An operator signs into `/console`, opens **API keys**, and creates a key for a dedicated test tenant with a small daily AI quota. Copy the raw key once into a server-side secret store. Do not place it in browser code or commit it. The caller's trusted tenant comes from the key; the `request_tenant` field is checked against it.

## 2. Evaluate before execution

```sh
export BASE_URL='https://your-preview-worker.example'
# Set AAG_API_KEY privately in your shell or secret manager; never commit it.
curl -sS "$BASE_URL/v1/evaluate" \
  -H "Authorization: Bearer $AAG_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"agent_role":"support_agent","tool_name":"crm.read_contact","arguments_json":"{\"contact_id\":\"fictional-1\",\"target_tenant\":\"your-test-tenant\"}","source_text":"Read a test contact","request_tenant":"your-test-tenant"}'
```

The response contains `decision`, `risk_level`, `policy_codes`, `requires_approval`, `normalized_tool`, and `normalized_args`. `ALLOW` permits your separately guarded tool handler to run. `DENY` means stop. `REQUIRE_APPROVAL` means stop and await a human; it is **not** permission to execute.

```ts
import { AgentActionGate } from "@agent-action-gate/sdk";

const gate = new AgentActionGate({
  baseUrl: process.env.GATE_BASE_URL!,
  apiKey: process.env.AAG_API_KEY!,
});
const request = {
  agent_role: "support_agent",
  tool_name: "email.send",
  arguments_json: JSON.stringify({ to: "fictional@example.invalid", target_tenant: "your-test-tenant" }),
  source_text: "Send a fictional update",
  request_tenant: "your-test-tenant",
};
const result = await gate.evaluate(request, { idempotencyKey: crypto.randomUUID() });
switch (result.decision) {
  case "ALLOW": /* separately invoke your allowlisted handler */ break;
  case "DENY": /* stop */ break;
  case "REQUIRE_APPROVAL": /* save result.approval_id; do not execute */ break;
}
```

The SDK source is currently in `packages/sdk/` and is **not published to a package registry**. Link or copy that local package into your server-side project before using the package-name import above.

## 3. Human approval and consume

An operator reviews the pending approval in `/console/approvals` and approves or rejects it. Operator credentials are separate from Agent keys. After approval, the Agent calls `gate.consumeApproval(approvalId, exactOriginalRequest)`; the original request fields must match the approved request binding. Only `authorized: true` may reach the guarded tool handler, and consumption is one-time. A second consume returns an HTTP 409 error. Keep the execution handler behind this step, and use external idempotency where possible; the gate cannot guarantee exactly-once behavior of an external provider after an ambiguous timeout.

## 4. Optional MCP

See [MCP integration](mcp-integration.md). For an existing Dify workflow, see [Dify integration](dify-integration.md). Beta interest can be registered on `/quickstart` with only email, integration choice, approximate monthly call-volume band, and submission time. No email is sent automatically.
