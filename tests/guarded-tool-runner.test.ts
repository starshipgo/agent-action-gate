import { describe, expect, test } from "bun:test";
import type {
  ActionRequest,
  EvaluationResult,
  JsonObject,
} from "../src/contracts";
import {
  createGuardedToolRunner,
  type ActionGateClient,
  type ApprovalConsumeError,
  type ApprovalConsumptionResult,
  type GuardEvaluation,
} from "../src/integrations/guarded-tool-runner";

const request: ActionRequest = {
  agent_role: "support_agent",
  tool_name: "crm.read_contact",
  arguments_json: '{"contact_id":"c-123","target_tenant":"acme"}',
  source_text: "Read the requested CRM contact.",
  request_tenant: "acme",
};

const approvalRequest: ActionRequest = {
  ...request,
  tool_name: "email.send",
  arguments_json:
    '{"to":"customer@example.com","target_tenant":"acme"}',
};

function evaluation(
  decision: EvaluationResult["decision"],
): GuardEvaluation {
  if (decision === "ALLOW") {
    return {
      decision,
      risk_level: "low",
      policy_codes: [],
      requires_approval: false,
      normalized_tool: "crm.read_contact",
      normalized_args: {
        contact_id: "c-123",
        target_tenant: "acme",
      },
    };
  }

  if (decision === "REQUIRE_APPROVAL") {
    return {
      decision,
      risk_level: "medium",
      policy_codes: ["OUTBOUND_SEND"],
      requires_approval: true,
      approval_id: "approval-1",
      expires_at: "2026-09-30T00:10:00.000Z",
      normalized_tool: "email.send",
      normalized_args: {
        to: "customer@example.com",
        target_tenant: "acme",
      },
    };
  }

  return {
    decision,
    risk_level: "high",
    policy_codes: ["PROMPT_INJECTION_SIGNAL"],
    requires_approval: false,
    normalized_tool: "email.send",
    normalized_args: {
      to: "attacker@example.com",
      target_tenant: "acme",
    },
  };
}

class FakeGate implements ActionGateClient {
  evaluateCalls = 0;
  consumeCalls = 0;
  consumed = false;
  consumeFailure: ApprovalConsumeError | null = null;
  consumedApprovalId: string | null = null;
  consumedToolName: string | null = null;
  consumedArgs: JsonObject | null = null;
  repeatSuccessfulConsumption = false;

  constructor(public nextEvaluation: GuardEvaluation) {}

  async evaluate(_request: ActionRequest): Promise<GuardEvaluation> {
    this.evaluateCalls += 1;
    return this.nextEvaluation;
  }

  async consumeApproval(input: {
    approval_id: string;
    request: ActionRequest;
  }): Promise<ApprovalConsumptionResult> {
    this.consumeCalls += 1;

    if (this.consumeFailure !== null) {
      return { authorized: false, error: this.consumeFailure };
    }

    if (this.consumed && !this.repeatSuccessfulConsumption) {
      return {
        authorized: false,
        error: "APPROVAL_ALREADY_CONSUMED",
      };
    }

    this.consumed = true;
    return {
      authorized: true,
      approval_id: this.consumedApprovalId ?? input.approval_id,
      tool_name: this.consumedToolName ?? input.request.tool_name,
      normalized_args:
        this.consumedArgs ??
        (JSON.parse(input.request.arguments_json) as JsonObject),
    };
  }
}

describe("guarded tool execution", () => {
  test("ALLOW invokes the executor exactly once with normalized gate output", async () => {
    const gate = new FakeGate(evaluation("ALLOW"));
    const runner = createGuardedToolRunner(gate);
    const calls: unknown[] = [];

    const result = await runner.execute({
      request,
      toolExecutor: (call) => {
        calls.push(call);
        return { contact_name: "Ada" };
      },
    });

    expect(result).toMatchObject({
      outcome: "executed",
      authorization: "POLICY_ALLOW",
      tool_name: "crm.read_contact",
      result: { contact_name: "Ada" },
    });
    expect(calls).toEqual([
      {
        tool_name: "crm.read_contact",
        normalized_args: {
          contact_id: "c-123",
          target_tenant: "acme",
        },
      },
    ]);
    expect(gate.evaluateCalls).toBe(1);
    expect(gate.consumeCalls).toBe(0);
  });

  test("DENY never invokes the executor", async () => {
    const gate = new FakeGate(evaluation("DENY"));
    const runner = createGuardedToolRunner(gate);
    let executions = 0;

    const result = await runner.execute({
      request,
      toolExecutor: () => {
        executions += 1;
        return null;
      },
    });

    expect(result.outcome).toBe("denied");
    expect(executions).toBe(0);
  });

  test("REQUIRE_APPROVAL returns approval metadata without execution", async () => {
    const gate = new FakeGate(evaluation("REQUIRE_APPROVAL"));
    const runner = createGuardedToolRunner(gate);
    let executions = 0;

    const result = await runner.execute({
      request: approvalRequest,
      toolExecutor: () => {
        executions += 1;
        return null;
      },
    });

    expect(result).toMatchObject({
      outcome: "approval_pending",
      approval_id: "approval-1",
      expires_at: "2026-09-30T00:10:00.000Z",
    });
    expect(executions).toBe(0);
  });

  test("REQUIRE_APPROVAL without persisted approval metadata fails closed", async () => {
    const complete = evaluation("REQUIRE_APPROVAL");
    const {
      approval_id: _approvalId,
      expires_at: _expiresAt,
      ...incomplete
    } = complete;
    const gate = new FakeGate(incomplete);
    const runner = createGuardedToolRunner(gate);
    let executions = 0;

    const result = await runner.execute({
      request: approvalRequest,
      toolExecutor: () => {
        executions += 1;
        return null;
      },
    });

    expect(result).toEqual({
      outcome: "gate_error",
      approval_id: null,
      error: "INVALID_GATE_RESPONSE",
    });
    expect(executions).toBe(0);
  });

  test("successful consumption executes once and replay executes zero additional times", async () => {
    const gate = new FakeGate(evaluation("REQUIRE_APPROVAL"));
    const runner = createGuardedToolRunner(gate);
    let executions = 0;
    const toolExecutor = () => {
      executions += 1;
      return { delivered: true };
    };

    const first = await runner.consumeAndExecute({
      approval_id: "approval-1",
      request: approvalRequest,
      toolExecutor,
    });
    const replay = await runner.consumeAndExecute({
      approval_id: "approval-1",
      request: approvalRequest,
      toolExecutor,
    });

    expect(first).toMatchObject({
      outcome: "executed",
      authorization: "APPROVAL_CONSUMED",
      approval_id: "approval-1",
    });
    expect(replay).toEqual({
      outcome: "approval_not_authorized",
      approval_id: "approval-1",
      error: "APPROVAL_ALREADY_CONSUMED",
    });
    expect(executions).toBe(1);
    expect(gate.evaluateCalls).toBe(0);
    expect(gate.consumeCalls).toBe(2);
  });

  test.each([
    "APPROVAL_REJECTED",
    "APPROVAL_EXPIRED",
    "APPROVAL_REQUEST_MISMATCH",
  ] as const)("%s never invokes the executor", async (error) => {
    const gate = new FakeGate(evaluation("REQUIRE_APPROVAL"));
    gate.consumeFailure = error;
    const runner = createGuardedToolRunner(gate);
    let executions = 0;

    const result = await runner.consumeAndExecute({
      approval_id: "approval-1",
      request: approvalRequest,
      toolExecutor: () => {
        executions += 1;
        return null;
      },
    });

    expect(result).toEqual({
      outcome: "approval_not_authorized",
      approval_id: "approval-1",
      error,
    });
    expect(executions).toBe(0);
    expect(gate.evaluateCalls).toBe(0);
  });

  test("a mismatched successful-consume response fails closed", async () => {
    const gate = new FakeGate(evaluation("REQUIRE_APPROVAL"));
    gate.consumedApprovalId = "different-approval";
    const runner = createGuardedToolRunner(gate);
    let executions = 0;

    const result = await runner.consumeAndExecute({
      approval_id: "approval-1",
      request: approvalRequest,
      toolExecutor: () => {
        executions += 1;
        return null;
      },
    });

    expect(result).toEqual({
      outcome: "gate_error",
      approval_id: "approval-1",
      error: "INVALID_GATE_RESPONSE",
    });
    expect(executions).toBe(0);
  });

  test("an ALLOW response for a different tool fails closed", async () => {
    const response = evaluation("ALLOW");
    response.normalized_tool = "email.send";
    const gate = new FakeGate(response);
    const runner = createGuardedToolRunner(gate);
    let executions = 0;

    const result = await runner.execute({
      request,
      toolExecutor: () => {
        executions += 1;
        return null;
      },
    });

    expect(result).toEqual({
      outcome: "gate_error",
      approval_id: null,
      error: "INVALID_GATE_RESPONSE",
    });
    expect(executions).toBe(0);
  });

  test("an ALLOW response with different arguments fails closed", async () => {
    const response = evaluation("ALLOW");
    response.normalized_args = {
      contact_id: "c-999",
      target_tenant: "acme",
    };
    const gate = new FakeGate(response);
    const runner = createGuardedToolRunner(gate);
    let executions = 0;

    const result = await runner.execute({
      request,
      toolExecutor: () => {
        executions += 1;
        return null;
      },
    });

    expect(result.outcome).toBe("gate_error");
    expect(executions).toBe(0);
  });

  test("a malformed gate argument object cannot reach an ALLOW executor", async () => {
    const response = evaluation("ALLOW");
    response.normalized_args = [] as unknown as JsonObject;
    const gate = new FakeGate(response);
    const runner = createGuardedToolRunner(gate);
    let executions = 0;

    const result = await runner.execute({
      request,
      toolExecutor: () => {
        executions += 1;
        return null;
      },
    });

    expect(result.outcome).toBe("gate_error");
    expect(executions).toBe(0);
  });

  test("a pending approval for a different action fails closed", async () => {
    const gate = new FakeGate(evaluation("REQUIRE_APPROVAL"));
    const runner = createGuardedToolRunner(gate);
    let executions = 0;

    const result = await runner.execute({
      request,
      toolExecutor: () => {
        executions += 1;
        return null;
      },
    });

    expect(result.outcome).toBe("gate_error");
    expect(executions).toBe(0);
  });

  test("a consumed approval with a mismatched tool or arguments never executes", async () => {
    const gate = new FakeGate(evaluation("REQUIRE_APPROVAL"));
    gate.consumedToolName = "crm.read_contact";
    gate.consumedArgs = {
      contact_id: "c-123",
      target_tenant: "acme",
    };
    const runner = createGuardedToolRunner(gate);
    let executions = 0;

    const result = await runner.consumeAndExecute({
      approval_id: "approval-1",
      request: approvalRequest,
      toolExecutor: () => {
        executions += 1;
        return null;
      },
    });

    expect(result).toEqual({
      outcome: "gate_error",
      approval_id: "approval-1",
      error: "INVALID_GATE_RESPONSE",
    });
    expect(executions).toBe(0);
  });

  test("a malformed consumed response cannot be followed by an executable replay", async () => {
    let consumeCalls = 0;
    const gate: ActionGateClient = {
      evaluate: async () => evaluation("REQUIRE_APPROVAL"),
      consumeApproval: async () => {
        consumeCalls += 1;
        return consumeCalls === 1
          ? {
              authorized: true,
              approval_id: "approval-1",
              tool_name: "crm.read_contact",
              normalized_args: {
                contact_id: "c-123",
                target_tenant: "acme",
              },
            }
          : {
              authorized: true,
              approval_id: "approval-1",
              tool_name: "email.send",
              normalized_args: {
                to: "customer@example.com",
                target_tenant: "acme",
              },
            };
      },
    };
    const runner = createGuardedToolRunner(gate);
    let executions = 0;
    const toolExecutor = () => {
      executions += 1;
      return null;
    };

    const malformed = await runner.consumeAndExecute({
      approval_id: "approval-1",
      request: approvalRequest,
      toolExecutor,
    });
    const replay = await runner.consumeAndExecute({
      approval_id: "approval-1",
      request: approvalRequest,
      toolExecutor,
    });

    expect(malformed.outcome).toBe("gate_error");
    expect(replay).toEqual({
      outcome: "approval_not_authorized",
      approval_id: "approval-1",
      error: "APPROVAL_ALREADY_CONSUMED",
    });
    expect(executions).toBe(0);
    expect(consumeCalls).toBe(2);
  });

  test("a buggy adapter cannot replay a successful consumed approval", async () => {
    const gate = new FakeGate(evaluation("REQUIRE_APPROVAL"));
    gate.repeatSuccessfulConsumption = true;
    const runner = createGuardedToolRunner(gate);
    let executions = 0;
    const toolExecutor = () => {
      executions += 1;
      return { delivered: true };
    };

    const first = await runner.consumeAndExecute({
      approval_id: "approval-1",
      request: approvalRequest,
      toolExecutor,
    });
    const replay = await runner.consumeAndExecute({
      approval_id: "approval-1",
      request: approvalRequest,
      toolExecutor,
    });

    expect(first.outcome).toBe("executed");
    expect(replay).toEqual({
      outcome: "approval_not_authorized",
      approval_id: "approval-1",
      error: "APPROVAL_ALREADY_CONSUMED",
    });
    expect(executions).toBe(1);
    expect(gate.consumeCalls).toBe(2);
  });

  test("a gate failure propagates without invoking the executor", async () => {
    let executions = 0;
    const gate: ActionGateClient = {
      evaluate: async () => {
        throw new Error("simulated persistence failure");
      },
      consumeApproval: async () => ({
        authorized: false,
        error: "APPROVAL_CONSUME_UNAVAILABLE",
      }),
    };
    const runner = createGuardedToolRunner(gate);

    await expect(
      runner.execute({
        request,
        toolExecutor: () => {
          executions += 1;
          return null;
        },
      }),
    ).rejects.toThrow("simulated persistence failure");
    expect(executions).toBe(0);
  });
});
