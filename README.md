# Agent Action Gate

Runtime authorization for AI agents before high-impact tools execute.

Agent Action Gate is a **security-focused prototype and beta runtime authorization control plane**. It checks a proposed tool call before an application can run an external action. It is not a production-ready security guarantee or a substitute for least-privilege tool design.

```text
Agent proposes a tool call
          ↓
     Action Gate
          ↓
  ALLOW / REQUIRE_APPROVAL / DENY
          ↓
Guarded tool adapter (only after authorization)
```

An agent can be influenced by user text, retrieved documents, or tool output. A model's decision to call a tool is therefore not, by itself, permission to read tenant data, send an email, or issue a refund. The gate normalizes the request, checks tenant and tool policy, uses structured semantic-risk signals as a **sensor only**, and returns a deterministic decision. Unknowns and classifier failures fail closed.

## Try the fixed demo

The `/demo` route offers six one-click scenarios: a safe CRM read, an outbound email requiring approval, an injection/exfiltration attempt, a cross-tenant attempt, and refunds below and above the policy limit. It uses fictional tenants, one bounded fictional contact, fixture signals, and in-memory fake executors. It has no real tool credentials or external side effects. The UI displays **“Demo environment — no real external actions are executed.”**

Demo screenshot: _to be added before publication_. Live demo URL: _not published_. A future live demo must use [isolated resources and low limits](docs/demo-deployment.md); the checked-in demo configuration is a placeholder, not a deployment.

## Architecture in brief

1. A server-side Agent key identifies the tenant. The supplied `request_tenant` cannot override that trusted identity.
2. The request is normalized, including `arguments_json`, tool name, target tenant, recipient, and integer minor-unit refund amount.
3. A Workers AI classifier can contribute structured prompt-injection, exfiltration, and suspicious-instruction signals. It cannot grant access.
4. The [deterministic policy](src/policy.ts) is the sole authority for `ALLOW`, `REQUIRE_APPROVAL`, or `DENY`.
5. Approval-required actions pause for a separate operator. A successful one-time consume must match the original request before a guarded adapter may execute it.
6. D1 stores tenant-bound key hashes, exact AI quota and idempotency state, approval state, and privacy-limited append-only audit evidence. Cloudflare Rate Limiting provides separate burst control.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), and [security evaluation](docs/security-evaluation.md) for the detailed trust boundaries and residual risks. The original [Dify workflow](dify/agent-action-gate.dify.yml) remains the behavioral reference for the native TypeScript core.

## Developer quickstart

Read the [full quickstart](docs/quickstart.md) for key creation, the three decisions, exact-request approval consumption, and copyable HTTP/TypeScript examples. The small [SDK](packages/sdk/README.md) is local source and is not published to a package registry. Integration guides cover [MCP](docs/mcp-integration.md) and [Dify](docs/dify-integration.md); this project has no official Dify partnership or certification.

Server-side request shape for `POST /v1/evaluate`:

```json
{
  "agent_role": "support_agent",
  "tool_name": "crm.read_contact",
  "arguments_json": "{\"contact_id\":\"fictional-1\",\"target_tenant\":\"test-tenant\"}",
  "source_text": "Read a fictional contact",
  "request_tenant": "test-tenant"
}
```

`ALLOW` permits a separately guarded tool handler to run. `DENY` stops. `REQUIRE_APPROVAL` stops until an operator approves and the Agent consumes a matching, unexpired approval once. The SDK never auto-executes tools.

## Security properties and limits

- Tenant authority comes from a hashed, tenant-bound Agent key; Agent and operator credentials are separate.
- The model is a security sensor, not an authorization authority. The string `"true"` boundary regression has a deterministic test.
- Malformed arguments, unknown tools, cross-tenant targets, forbidden secret reads and exports, and classifier failures fail closed.
- Refund policy uses integer minor units. Email sends and bounded refunds require human approval.
- Idempotency and policy versioning bind retries and approvals to the request's authorization context.
- Audit records retain allowlisted metadata and hashes, not raw source text, full arguments, or credentials.
- The guarded MCP example has no operator authority and cannot execute approval-required actions before consumption.

These are tested controls, not claims that all prompt injection or downstream tool misuse is prevented. A classifier can miss an attack; a human can approve a harmful request; a valid one-time grant does not guarantee exactly-once delivery by an external email or payment provider. The shared operator secret is a beta boundary, not enterprise identity. Review the [residual risks](docs/threat-model.md) before connecting real systems. A non-production Cloudflare Preview smoke test with Workers AI was reported by the project owner; no production deployment or customer adoption is claimed.

## Local development and evidence

Prerequisites: Bun and the dependencies declared in `package.json`. Do not add real credentials to source or run remote migrations as part of local verification.
The checked-in Wrangler configs use placeholders for remote Preview resources.
For future authorized Preview work, put actual identifiers in ignored
`wrangler.preview.local.jsonc` and `wrangler.preview-migrations.local.jsonc`
files; neither belongs in a public commit.

```sh
bun install
bun test
bunx tsc --noEmit
bunx wrangler types --check
bun run build
bun run eval
bun run public-release-check
git diff --check
```

The default tests and [adversarial evaluation corpus](evals/README.md) use local fixtures and do not call a paid model. The generated [evaluation report](evals/report.json) records fixture regression results, **not** measured classifier accuracy. The build checks frontend assets for secret material and normalizes machine-specific paths in generated Wrangler metadata. `public-release-check` scans repository content, built assets, and Git history for obvious credentials and personal paths; a zero-finding result is a necessary check, not a guarantee of privacy.

The `/quickstart` page has proposed Free/Sandbox and Developer Beta copy, but there is no billing integration or finalized price. First-party aggregate beta counters and a minimal, rate-limited interest form are described in the [proposed beta plan](docs/beta-plan.md). No third-party tracker or marketing platform is included.

Security reports should use the private channel described in [SECURITY.md](SECURITY.md). Its contact method must be configured before publication. Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md).
