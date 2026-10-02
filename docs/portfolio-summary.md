# Portfolio summary

- Designed a runtime authorization gateway for AI-agent tool execution: semantic-risk classification is a sensor, while deterministic policy alone authorizes or denies.
- Migrated a Dify visual workflow into native Bun/TypeScript with golden and regression tests, including a string `"true"` versus boolean `true` boundary bug.
- Implemented tenant-bound hashed API keys, burst limiting, exact daily AI quota, idempotency, integer minor-unit refunds, exact-request human approval, one-time consumption, append-only privacy-conscious audit, and guarded MCP execution.
- Built a React operator console for approvals, audit, API-key management, and policy visibility; added a fixed-fixture public demo and small explicit HTTP SDK.
- The owner reports validating the architecture in a non-production Cloudflare Preview with Workers AI. No production deployment or customer adoption is claimed.
- Latest local `bun test` run: **256 passing tests, 0 failures, 932 assertions** across 20 files. The separate fixture-based adversarial corpus passed 12/12 cases; this is not a measured semantic-detection accuracy result.
