# Security evaluation

This document records evidence that can be reproduced from the repository. It
does not claim a penetration test, formal verification, or benchmark result.

## Prototype-to-native migration

The exported Dify workflow in `dify/agent-action-gate.dify.yml` was treated as
the behavioral specification for normalization, semantic signals, policy
precedence, and the output contract. The native Bun + TypeScript core separates
the semantic sensor from the deterministic policy authority. Golden cases
exercise normal, approval-required, forbidden, cross-tenant, unknown-tool,
malformed-JSON, and semantic-attack paths.

## Boundary regression: `"true"` versus `true`

The Dify prototype exposed a runtime boundary defect: structured output that
was declared boolean arrived as the string `"true"`. The native risk boundary
accepts only booleans and the strings `"true"` / `"false"`, normalizes them,
and has regression tests proving that string `"true"` remains a denial signal.
The policy engine never relies on JavaScript truthiness for classifier fields.

## Fail-closed classifier behavior

Tests cover classifier exceptions, timeout, missing or malformed envelopes,
and invalid structured fields. These paths return a deterministic denial with
`SEMANTIC_CLASSIFIER_FAILURE`. Malformed arguments and deterministic
preconditions bypass the classifier entirely, limiting both cost and exposure.

## Tenant and credential isolation

Worker tests establish that:

- tenant authority comes from the authenticated Agent principal;
- a supplied compatibility tenant cannot override that authority;
- known tools require a matching normalized target tenant;
- one principal cannot receive API keys for different tenants;
- Agent credentials cannot exercise operator endpoints; and
- operator credentials cannot be used as tenant Agent credentials.

Raw Agent keys are returned once on issuance. Persistence stores SHA-256 hashes
and display prefixes only. Browser operator login exchanges the operator key
for a signed, expiring, HttpOnly cookie and does not place the key in Web
Storage, IndexedDB, or URLs.

## Quota and replay controls

The daily AI quota uses one conditional D1 upsert with `RETURNING`; tests cover
the exact boundary and concurrent access to the final unit. A Cloudflare
rate-limit binding provides a separate burst-control layer.

Idempotency claims are principal-scoped and store an allowlisted response
envelope without normalized arguments. The request digest includes trusted
tenant context and policy version. Tests cover exact replay, changed-request
conflicts, claim ownership, expiry replacement, and incompatible policy
versions.

## Human approval binding

For an approval-required decision, the gate stores:

- an opaque approval identifier;
- trusted principal and tenant;
- normalized tool;
- decision metadata and immutable policy version;
- an exact request hash; and
- a tool-specific, allowlisted display projection.

The hash binds the principal, tenant, normalized arguments, source-text digest,
policy result, and policy version. Consumption recomputes it from the Agent's
resubmitted request. Tests cover changed recipients, changed refund amounts,
different principals and tenants, stale policy versions, and attempts to treat
the display projection as authority.

The display projection is privacy-limited: email bodies and attachment
contents are absent; arbitrary unknown-tool arguments are never copied; raw
source text is never stored.

## One-time consumption and guarded execution

D1 conditionally performs `APPROVED -> CONSUMED` and emits its lifecycle audit
event in the same statement. Concurrency tests prove that only one competing
consumer receives `authorized=true`; replays receive the stable
`APPROVAL_ALREADY_CONSUMED` conflict.

The guarded runner is the only example path that invokes a supplied tool
executor. Unit tests show zero executions for denial, pending approval,
rejected/expired/mismatched approvals, malformed gate responses, and replay.
The local MCP adapter exposes no approval capability and routes schema-valid
tool calls through this runner.

This is one-time authorization, not end-to-end exactly-once execution. A real
adapter must use a downstream idempotency key or transactional outbox to handle
crashes and lost responses around an external side effect.

## Audit integrity and privacy

Every returned decision requires a persisted audit event. Audit rows contain
allowlisted metadata plus hashes of normalized arguments and source text, not
the raw values. Unknown tool names are reduced to a hash sentinel. D1 triggers
reject update, delete, and replacement of audit evidence. Approval lifecycle
transitions append their audit event atomically.

Tests inspect public query projections and database rows for absence of raw
source text, arguments, bearer material, and normalized replay payloads. The
operator console renders stable policy codes with readable labels without
removing the codes from the API.

## Reproduction

All verification is local and uses fakes for Workers AI and tool executors:

```sh
bun test
bunx tsc --noEmit
bunx wrangler types --check
bun run build
AAG_LOCAL_D1_DIR="$(mktemp -d /tmp/aag-local-d1.XXXXXX)"
bunx wrangler d1 migrations apply DB --local --persist-to "$AAG_LOCAL_D1_DIR"
git diff --check
```

The test and assertion totals are recorded in [the portfolio summary](portfolio-summary.md).
They are regression counts, not a security or performance benchmark.
