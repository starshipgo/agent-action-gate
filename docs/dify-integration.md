# Dify integration (independent project)

Agent Action Gate began as a Dify visual workflow and was migrated into a native TypeScript authorization core. It is not an official Dify partnership, integration, or certification.

A Dify workflow can propose a tool call, then send the proposed `agent_role`, `tool_name`, `arguments_json`, `source_text`, and `request_tenant` to a **server-side** adapter. The adapter holds a tenant-bound Agent key and calls `POST /v1/evaluate`. Place the actual high-impact tool execution *after* this check, behind a branch that handles `ALLOW`, `DENY`, and `REQUIRE_APPROVAL` separately. Never let a Dify node execute the same tool directly through another path.

For `REQUIRE_APPROVAL`, pause the workflow, have an operator decide through the console, then use `/v1/approvals/{id}/consume` with the exact original proposed request. Only successful one-time consumption may lead to execution. Do not treat a model's explanation, a `social_engineering` flag alone, or a user-controlled tenant field as authorization. The server derives trusted tenant identity from the API key.
