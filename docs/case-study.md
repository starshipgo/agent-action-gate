# Case study: Agent Action Gate

## Problem and prototype

Agent models can propose tool calls that read tenant data, send email, or move money. A persuasive model response is not a trustworthy authorization decision. The first prototype was a Dify visual workflow: it normalized a proposed call, classified semantic risk, then applied policy to produce `ALLOW`, `REQUIRE_APPROVAL`, or `DENY`. The exported DSL remains in `dify/agent-action-gate.dify.yml` as a behavioral specification.

## Native migration and a boundary regression

The prototype was migrated into Bun/TypeScript with normalization, semantic boundary parsing, deterministic policy, and golden tests. A concrete regression emerged when a schema boolean arrived at runtime as the string `"true"`; a plain truthiness or strict-boolean assumption could mis-handle the signal. The native boundary explicitly accepts `true`/`false` and `"true"`/`"false"`, with a regression test. Semantic output is a **sensor**, never authority: it can raise risk, but cannot grant access. Malformed JSON, unknown tools, tenant mismatches, and classifier failures fail closed.

## Hardening and approval

The Worker derives tenant identity from a hashed, tenant-bound Agent API key instead of trusting the caller's tenant field. Burst rate limiting reduces short spikes; D1-backed daily AI quota does exact accounting. Idempotency binds a retry key to the request and current policy version. Refund amounts use integer minor units to avoid floating-point ambiguity. High-impact email and bounded refunds require approval by a separate operator credential. Approval stores a hash of the exact request and can be consumed only once, by the original principal, before expiry. This addresses approval time-of-check/time-of-use substitution, but not every failure mode of a downstream provider.

## Evidence and integrations

Append-only audit records retain decisions, safe policy codes, tenant and tool metadata, hashes of source and arguments, and lifecycle events—not raw prompts, full arguments, or keys. The guarded MCP example keeps tool handlers behind evaluation and, where needed, one-time approval consumption. A React operator console presents sanitized activity, approvals, API-key management, and policy version without exposing secret material. Local deterministic tests cover the core and Worker paths. The project owner reports a successful non-production Cloudflare Preview smoke test with Workers AI; no production or customer outcome is claimed.

## Residual risks

The semantic classifier can miss attacks or flag benign requests; fixture tests do not measure real detection accuracy. Rate limiting is not exact quota accounting. Operator authentication is a shared-key beta boundary, not enterprise identity. Audit hashes may still be correlatable for known source text. A successful one-time consume is an authorization event, not an exactly-once guarantee for external email, refunds, or other side effects after ambiguous network failures. A live demo needs separate resources and human review before release. No adoption, customer outcomes, or performance benchmark is claimed.
