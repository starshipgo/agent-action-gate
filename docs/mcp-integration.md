# MCP integration

The repository's guarded MCP adapter places Agent Action Gate before a local tool handler. Keep the handler unreachable through any other MCP tool registration or direct route. Pass the proposed tool name, serialized arguments, source text, role, and tenant to `POST /v1/evaluate` with a server-held tenant-bound key.

- On `ALLOW`, the adapter may invoke the allowlisted handler once.
- On `DENY`, it must stop and return the policy codes.
- On `REQUIRE_APPROVAL`, it must stop, surface the approval ID to an operator, and later call `/v1/approvals/{id}/consume` with the exact original request before any execution.

The consume response is authorization, not an execution receipt. External tools need their own idempotency or reconciliation for ambiguous failures. Never give an Agent key operator authority, and never put the key in model-visible text or a browser bundle. The SDK offers explicit `evaluate` and `consumeApproval` methods; it has no automatic tool executor.
