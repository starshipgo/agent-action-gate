# Agent Action Gate TypeScript SDK (local beta source)

This dependency-free package is not published. Link it from this repository into a server-side TypeScript project. The key must stay server-side; never import a configured client into browser code.

`new AgentActionGate({ baseUrl, apiKey })` exposes only:

- `evaluate(action, { idempotencyKey? })` → typed `ALLOW | DENY | REQUIRE_APPROVAL` result.
- `consumeApproval(approvalId, exactOriginalRequest)` → a one-time authorization result after an operator approves.

Non-2xx responses throw `GateHttpError` with HTTP status and stable server code. `REQUIRE_APPROVAL` is never auto-executed. The SDK performs no external tool side effect and cannot approve requests. See [developer quickstart](../../docs/quickstart.md) for a complete example.
