# Agent Action Gate

Agent Action Gate is a deployable Cloudflare Worker API for evaluating proposed
AI-agent tool calls before execution. Its deterministic Bun + TypeScript policy
engine remains isolated from the Worker transport and from the Workers AI
semantic-risk sensor.

This phase adds the API transport and production classifier adapter, but it has
not been deployed. There is still no UI, database, ORM, queue, billing system,
or dashboard.

## Security architecture

The request path is:

```text
HTTP authentication and shape validation
  -> tool-call normalization
  -> semantic sensor (valid arguments only)
  -> deterministic policy authority
  -> six-field security decision
```

The semantic classifier is a sensor only. It cannot return an authorization
decision. The deterministic policy module is the only code that constructs
`ALLOW`, `REQUIRE_APPROVAL`, or `DENY` results.

Malformed `arguments_json` bypasses semantic classification and returns
`MALFORMED_ARGUMENTS_JSON`. If classification throws, times out, or returns an
invalid shape, evaluation fails closed with `SEMANTIC_CLASSIFIER_FAILURE` while
preserving normalized tool and argument data.

Model output is validated at runtime even though Workers AI is asked for JSON
Schema structured output. Signals accept booleans and the defensive string
forms `"true"` / `"false"`; this retains the original regression protection.

## HTTP API

### `GET /health`

Public health check:

```json
{
  "status": "ok",
  "service": "agent-action-gate"
}
```

### `POST /v1/evaluate`

Authenticate with the bearer key and send a JSON body, conventionally as:

```http
Authorization: Bearer <GATE_API_KEY>
Content-Type: application/json
```

Request body:

```json
{
  "agent_role": "support-agent",
  "tool_name": "crm.read_contact",
  "arguments_json": "{\"contact_id\":\"c-123\"}",
  "source_text": "Look up this contact.",
  "request_tenant": "tenant-a"
}
```

Transport validation requires all fields to be strings. `agent_role`,
`tool_name`, and `request_tenant` must also be non-empty after trimming. Limits
are 128, 256, 4096, 4096, and 256 characters respectively in the order above.
Unknown fields are rejected.

The Worker also caps the raw request body at 64 KiB before JSON parsing. That is
large enough for the worst-case escaped form of every contract field at its
maximum length, while preventing oversized unknown data from reaching the JSON
parser.

Malformed HTTP JSON or an invalid transport shape returns HTTP 400. Missing or
incorrect authorization returns HTTP 401. A transport-valid request always
returns HTTP 200 with exactly:

- `decision`
- `risk_level`
- `policy_codes`
- `requires_approval`
- `normalized_tool`
- `normalized_args`

An empty or malformed `arguments_json` string is a tool-call security failure,
not a transport failure, so it returns HTTP 200 with a deterministic denial.

## Deterministic policy order

Policy order defines precedence:

| Order | Condition | Result |
| --- | --- | --- |
| 1 | Unknown tool | `DENY / high / UNKNOWN_TOOL` |
| 2 | Both tenants present and unequal | `DENY / critical / CROSS_TENANT_ACCESS` |
| 3 | `secret.read` | `DENY / critical / FORBIDDEN_SECRET_ACCESS` |
| 4 | `customer.export` | `DENY / critical / SENSITIVE_EXPORT` |
| 5 | Injection, exfiltration, or suspicious-instruction signal | `DENY / high` with matching signal codes; append `SOCIAL_ENGINEERING_SIGNAL` when also true |
| 6 | `email.send` | `REQUIRE_APPROVAL / medium / OUTBOUND_SEND` |
| 7 | `refund.create`, amount missing, non-finite, or ≤ 0 | `DENY / high / INVALID_REFUND_AMOUNT` |
| 8 | `refund.create`, amount over 500 | `DENY / high / REFUND_LIMIT_EXCEEDED` |
| 9 | `refund.create`, 0 < amount ≤ 500 | `REQUIRE_APPROVAL / medium / REFUND_REQUIRES_APPROVAL` |
| 10 | `crm.read_contact`, `ticket.create`, `email.draft` | `ALLOW / low` |
| 11 | Defensive fallback | `DENY / high / NO_MATCHING_POLICY` |

Social engineering alone does not trigger denial; it adds a signal code only
when at least one strong semantic signal is also true.

## Workers AI

The production adapter uses the `AI` binding and model:

```text
@cf/meta/llama-3.3-70b-instruct-fp8-fast
```

It uses non-streaming JSON Schema mode with all six risk fields required and
`additionalProperties: false`. The fixed system instruction declares the model
a signal classifier only, treats `source_text` as untrusted data, forbids
following its instructions, and forbids authorization decisions. The model is
never asked for chain-of-thought.

Cloudflare documentation describes both object-valued and JSON-string response
envelopes for this path, so the adapter accepts either representation and then
applies the same strict runtime validation. Tests use fakes and never invoke the
real binding.

## Configuration and commands

Install development tooling and regenerate Cloudflare types:

```sh
bun install
bun run cf-typegen
```

For a future production deployment—not for the Preview smoke test—set the
production secret through Wrangler; never place it in `wrangler.jsonc`:

```sh
bunx wrangler secret put GATE_API_KEY
```

For local development, place a non-production value in `.dev.vars`; that file
is ignored. `wrangler dev` may make remote, billable Workers AI calls.

For a non-production Cloudflare Preview, Wrangler does not inherit bindings
from the top level, so `wrangler.jsonc` repeats the `AI` binding under
`previews`. Supply the Preview key through a temporary, permission-restricted
`--secrets-file`; never add its value to the configuration. Because this
workspace has no Git branch for Wrangler to derive a name from, pass an
explicit Preview `--name`.

After Wrangler prints the Preview URL, run the live smoke checks with the key
in the environment (the script never prints it):

```sh
BASE_URL='https://<preview-url>' GATE_API_KEY="$GATE_API_KEY" \
  ./scripts/smoke-test.sh
```

The smoke test checks public health, unauthorized rejection, a benign `ALLOW`,
and a malicious semantic-risk `DENY`. It uses `curl` and Bun, not `jq`.

Verification commands:

```sh
bun test
bunx tsc --noEmit
bun run cf-typegen:check
bun run inspect:dify
```

Wrangler-generated `worker-configuration.d.ts` is retained so CI and editors use
the same compatibility-date-specific Worker and binding types. Runtime
dependencies remain zero; Wrangler, TypeScript, and Bun types are development
dependencies only.

## Project layout

```text
src/
  classifiers/      provider-neutral interface and Workers AI adapter
  http/             transport request validation
  contracts.ts      core boundary and result types
  normalize.ts      tool-call normalization
  risk.ts           runtime semantic-output validation and coercion
  policy.ts         sole deterministic decision authority
  evaluate.ts       classifier orchestration and fail-closed timeout
  worker.ts         authenticated Cloudflare Worker transport
golden/             archived-parity input/risk/output fixtures
tests/              core, adapter, transport, and regression tests
scripts/            Bun-native Dify inspector and Preview smoke test
```

## Intentional divergences from archived Dify V0.1

The archived workflow is now at `dify/agent-action-gate.dify.yml`; its logic was
not edited.

1. Dify treated all finite refund amounts at or below 500—including zero and
   negatives—as approval-required. The native source of truth now rejects
   amounts ≤ 0 as `INVALID_REFUND_AMOUNT`.
2. Dify had no deterministic classifier-failure response. Native evaluation now
   denies classifier exceptions, timeout, invalid structured output, and JSON
   mode failure with `SEMANTIC_CLASSIFIER_FAILURE`.
3. The archived malformed-input End node publishes `decision` under the typo
   `descision`. The native API consistently returns the correct `decision` key.

The Phase 1 golden cases remain as parity fixtures; targeted regression tests
lock the deliberate post-parity changes.

## Remaining security boundaries

- `GATE_API_KEY` authenticates a caller but does not establish tenant identity.
  Until trusted principal/tenant claims exist, `request_tenant` is caller-supplied
  and the cross-tenant rule is not a complete authorization boundary. The
  preserved rule also compares tenants only when a string `target_tenant` is
  present, so omission or a non-string target does not trigger that denial.
- Refund amounts use JavaScript numbers, not exact decimal or minor-unit
  arithmetic. Define a currency representation before using this policy for
  production financial settlement.
- There is no rate limiting, replay prevention, or per-principal key rotation in
  this phase, so AI-cost abuse controls are still needed before public exposure.
- The provider-neutral timeout currently does not propagate an `AbortSignal` to
  Workers AI, so an already-started invocation may continue after the denial.
- `source_text` is sent to Workers AI. Review Cloudflare data-governance and
  observability settings before sending sensitive production content.
