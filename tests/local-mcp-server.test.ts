import { describe, expect, test } from "bun:test";
import type { ActionRequest, JsonValue } from "../src/contracts";
import type {
  ActionGateClient,
  ApprovalConsumptionResult,
  GuardEvaluation,
} from "../src/integrations/guarded-tool-runner";
import { createGuardedToolRunner } from "../src/integrations/guarded-tool-runner";
import { createLocalMcpJsonRpcHandler } from "../src/integrations/local-mcp-server";
import type { DemoToolExecutors } from "../src/integrations/local-mcp-tools";

class FakeProtocolGate implements ActionGateClient {
  requests: ActionRequest[] = [];

  constructor(public evaluation: GuardEvaluation) {}

  async evaluate(request: ActionRequest): Promise<GuardEvaluation> {
    this.requests.push(request);
    return this.evaluation;
  }

  async consumeApproval(): Promise<ApprovalConsumptionResult> {
    return { authorized: false, error: "APPROVAL_NOT_APPROVED" };
  }
}

function executors(calls: string[]): DemoToolExecutors {
  const fake =
    (name: string) =>
    (): JsonValue => {
      calls.push(name);
      return { tool: name };
    };

  return {
    "crm.read_contact": fake("crm.read_contact"),
    "email.send": fake("email.send"),
    "refund.create": fake("refund.create"),
  };
}

const allow: GuardEvaluation = {
  decision: "ALLOW",
  risk_level: "low",
  policy_codes: [],
  requires_approval: false,
  normalized_tool: "crm.read_contact",
  normalized_args: { contact_id: "c-1", target_tenant: "acme" },
};

describe("local MCP JSON-RPC handler", () => {
  test("supports initialize without starting a transport", async () => {
    const gate = new FakeProtocolGate(allow);
    const handler = createLocalMcpJsonRpcHandler({
      runner: createGuardedToolRunner(gate),
      executors: executors([]),
      getTrustedContext: () => ({
        agent_role: "support_agent",
        source_text: "Read one contact.",
        request_tenant: "acme",
      }),
    });

    expect(
      await handler.handle({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18" },
      }),
    ).toEqual({
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: { listChanged: false } },
        serverInfo: {
          name: "agent-action-gate-local",
          version: "0.1.0",
        },
      },
    });
    expect(gate.requests).toHaveLength(0);
  });

  test("tools/call flows through the gate and uses host-injected context", async () => {
    const gate = new FakeProtocolGate({
      ...allow,
      normalized_args: {
        contact_id: "c-1",
        target_tenant: "acme",
      },
    });
    const executionCalls: string[] = [];
    const handler = createLocalMcpJsonRpcHandler({
      runner: createGuardedToolRunner(gate),
      executors: executors(executionCalls),
      getTrustedContext: () => ({
        agent_role: "support_agent",
        source_text: "Read one contact.",
        request_tenant: "acme",
      }),
    });

    const response = await handler.handle({
      jsonrpc: "2.0",
      id: "call-1",
      method: "tools/call",
      params: {
        name: "crm_read_contact",
        arguments: {
          contact_id: "c-1",
          target_tenant: "acme",
        },
      },
    });

    expect(gate.requests).toEqual([
      {
        agent_role: "support_agent",
        tool_name: "crm.read_contact",
        arguments_json: '{"contact_id":"c-1","target_tenant":"acme"}',
        source_text: "Read one contact.",
        request_tenant: "acme",
      },
    ]);
    expect(executionCalls).toEqual(["crm.read_contact"]);
    expect(response).toMatchObject({
      jsonrpc: "2.0",
      id: "call-1",
      result: {
        structuredContent: {
          status: "executed",
          tool_name: "crm.read_contact",
        },
      },
    });
  });

  test("tools/call rejects a model-supplied host tenant before the gate", async () => {
    const gate = new FakeProtocolGate(allow);
    const executionCalls: string[] = [];
    const handler = createLocalMcpJsonRpcHandler({
      runner: createGuardedToolRunner(gate),
      executors: executors(executionCalls),
      getTrustedContext: () => ({
        agent_role: "support_agent",
        source_text: "Read one contact.",
        request_tenant: "acme",
      }),
    });

    const response = await handler.handle({
      jsonrpc: "2.0",
      id: "invalid-call-1",
      method: "tools/call",
      params: {
        name: "crm_read_contact",
        arguments: {
          contact_id: "c-1",
          target_tenant: "acme",
          request_tenant: "model-controlled-tenant",
        },
      },
    });

    expect(response).toEqual({
      jsonrpc: "2.0",
      id: "invalid-call-1",
      result: {
        content: [
          {
            type: "text",
            text: "Tool arguments did not match the declared schema.",
          },
        ],
        structuredContent: {
          status: "invalid_arguments",
          error: "INVALID_TOOL_ARGUMENTS",
        },
        isError: true,
      },
    });
    expect(gate.requests).toHaveLength(0);
    expect(executionCalls).toHaveLength(0);
  });

  test("tools/list and RPC methods expose no operator authority", async () => {
    const gate = new FakeProtocolGate(allow);
    const executionCalls: string[] = [];
    const handler = createLocalMcpJsonRpcHandler({
      runner: createGuardedToolRunner(gate),
      executors: executors(executionCalls),
      getTrustedContext: () => ({
        agent_role: "support_agent",
        source_text: "Call a tool.",
        request_tenant: "acme",
      }),
    });

    const list = await handler.handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    });
    const operatorTool = await handler.handle({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "approval_approve", arguments: {} },
    });
    const operatorMethod = await handler.handle({
      jsonrpc: "2.0",
      id: 4,
      method: "approvals/approve",
      params: {},
    });

    expect(list).toMatchObject({
      result: {
        tools: [
          { name: "crm_read_contact" },
          { name: "email_send" },
          { name: "refund_create" },
        ],
      },
    });
    expect(JSON.stringify(list)).not.toContain("approve");
    expect(JSON.stringify(list)).not.toContain("reject");
    expect(operatorTool).toEqual({
      jsonrpc: "2.0",
      id: 3,
      error: { code: -32602, message: "Invalid params" },
    });
    expect(operatorMethod).toEqual({
      jsonrpc: "2.0",
      id: 4,
      error: { code: -32601, message: "Method not found" },
    });
    expect(gate.requests).toHaveLength(0);
    expect(executionCalls).toHaveLength(0);
  });
});
