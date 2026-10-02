# Agent Action Gate architecture

Agent Action Gate is a runtime authorization boundary for proposed AI-agent
tool calls. The deterministic TypeScript policy engine is the authorization
authority. The semantic classifier contributes risk signals but cannot grant
access.

## Evolution

```mermaid
flowchart LR
  A[Dify security prototype] --> B[Native Bun + TypeScript core]
  B --> C[Golden parity and regressions]
  C --> D[Cloudflare Worker API]
  D --> E[Tenant identity, quota, and replay controls]
  E --> F[Append-only audit and exact-request approvals]
  F --> G[Guarded execution and MCP enforcement]
  G --> H[Operator console]
```

The exported Dify workflow remains the original behavioral reference. The
native implementation makes the trust boundaries explicit, adds regression
coverage for runtime coercion defects, and places persistence and operator
workflows around the policy core.

## Runtime topology

```mermaid
flowchart TB
  subgraph Browser[Operator browser]
    SPA[React operator console]
  end

  subgraph Cloudflare[One Cloudflare application]
    Assets[Workers Static Assets]
    Worker[Cloudflare Worker API]
    Policy[Deterministic policy engine]
    Sensor[Workers AI semantic sensor]
    D1[(D1)]
    Rate[Rate-limit binding]
  end

  Agent[Agent or guarded MCP host]
  Tool[External tool adapter]

  SPA -->|same-origin HTTPS + HttpOnly session| Worker
  SPA --> Assets
  Agent -->|tenant-bound Agent API key| Worker
  Worker --> Rate
  Worker --> Policy
  Worker --> Sensor
  Worker --> D1
  Worker -->|decision or one-time grant| Agent
  Agent -->|guarded adapter after grant| Tool
```

The SPA has no backend of its own. It calls the same-origin Worker and never
receives Cloudflare credentials. The operator key is submitted once to create
a short-lived signed cookie; it is not placed in browser storage or URLs.

## Authorization flow

```mermaid
sequenceDiagram
  participant A as Agent
  participant G as Gate
  participant P as Policy
  participant O as Human operator
  participant T as Guarded tool adapter

  A->>G: Proposed tool call
  G->>P: Normalized request + semantic signals
  P-->>G: ALLOW / DENY / REQUIRE_APPROVAL
  alt ALLOW
    G-->>A: Explicit ALLOW
    A->>T: Execute through guarded adapter
  else DENY
    G-->>A: DENY; no execution
  else REQUIRE_APPROVAL
    G-->>A: Pending approval ID
    O->>G: Review safe summary and approve/reject
    A->>G: Consume with exact original request
    G-->>A: One-time authorized=true or stable failure
    A->>T: Execute only after successful consume
  end
```

An approval decision is not an execution grant. The Agent must resubmit the
exact original request, and consumption must atomically transition the stored
approval once. The external adapter still needs its own idempotency key or
transactional outbox because a database grant cannot make an external side
effect exactly once across process and network failures.

## Identity and trust boundaries

- Agent API keys are tenant-bound. D1 stores their SHA-256 hashes and safe
  display prefixes, not raw credentials.
- `request_tenant` is compatibility input only. The authenticated principal is
  the tenant authority.
- Operator authority is separate from Agent authority. Agent credentials
  cannot approve, reject, query operator data, or manage keys.
- Browser operator sessions are short-lived, signed, `HttpOnly`, `Secure`, and
  `SameSite=Strict`. Same-origin validation protects cookie-authenticated
  state changes.
- Direct operator bearer authentication remains available for controlled CLI
  and smoke-test use.

## Policy versioning

The build exposes one immutable `POLICY_VERSION`. It is included in evaluation
and approval bindings and persisted with audit and approval records. This
prevents an idempotent response or approval created under one policy version
from silently becoming authority under another. A version change is an
explicit authorization-context change, not presentation metadata.

## Approval privacy and human context

The immutable request hash remains the approval and consumption authority.
`approval_display_json` is a separate, tool-specific, allowlisted projection
for human review:

- `email.send`: recipient, optional subject, and whether attachments are
  present; never the body or attachment contents.
- `refund.create`: minor-unit amount and optional currency/order identifier.
- Other tools: a generic summary with no arbitrary argument dump.

The display object is untrusted presentation data. Editing it cannot alter the
bound request, and authorization code never compares or executes from it. Raw
`source_text` is not stored.

## Persistence

```mermaid
erDiagram
  API_KEYS ||--o{ DAILY_AI_USAGE : consumes
  API_KEYS ||--o{ IDEMPOTENCY_RECORDS : scopes
  API_KEYS ||--o{ AUDIT_EVENTS : identifies
  APPROVAL_REQUESTS ||--o{ AUDIT_EVENTS : lifecycle

  API_KEYS {
    text id
    text key_hash
    text key_prefix
    text tenant_id
    text status
  }
  IDEMPOTENCY_RECORDS {
    text principal_id
    text request_hash
    text policy_version
    text response_json
  }
  AUDIT_EVENTS {
    text event_type
    text policy_version
    text arguments_hash
    text source_text_hash
  }
  APPROVAL_REQUESTS {
    text request_hash
    text policy_version
    text approval_display_json
    text status
  }
```

Audit history is append-only. Approval identity fields, including policy
version and display projection, are immutable after insertion. Valid lifecycle
transitions append audit evidence in the same D1 statement.

## Operator surface

The console provides:

- an overview backed by bounded aggregate queries;
- a pending-approval inbox with confirmation before approval;
- a filtered audit timeline;
- one-time API-key issuance and revocation;
- a read-only rendering of the built-in policy; and
- integration guidance for HTTP, TypeScript, and MCP callers.

The UI maps stable policy codes to readable labels without removing the
machine code from API data. It renders server data as text and uses no
third-party analytics or trackers.
