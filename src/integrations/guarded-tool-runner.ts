import type {
  ActionRequest,
  EvaluationResult,
  JsonObject,
  JsonValue,
} from "../contracts";
import { normalizeToolCall } from "../normalize";
import { canonicalJson } from "../security/crypto";

/**
 * The HTTP gate may extend the core policy result with approval metadata.
 * Keeping that extension here avoids making the provider-neutral policy core
 * responsible for persistence concerns.
 */
export type GuardEvaluation = EvaluationResult;

export type ApprovalConsumeError =
  | "APPROVAL_ALREADY_CONSUMED"
  | "APPROVAL_REJECTED"
  | "APPROVAL_EXPIRED"
  | "APPROVAL_REQUEST_MISMATCH"
  | "APPROVAL_NOT_FOUND"
  | "APPROVAL_NOT_APPROVED"
  | "APPROVAL_CONSUME_UNAVAILABLE";

/**
 * This is the only approval-consumption shape that can reach a tool executor.
 * Implementations must return it only after an atomic APPROVED -> CONSUMED
 * transition and exact request-hash verification.
 */
export type ApprovalConsumptionResult =
  | {
      authorized: true;
      approval_id: string;
      tool_name: string;
      normalized_args: JsonObject;
    }
  | {
      authorized: false;
      error: ApprovalConsumeError;
    };

export interface ActionGateClient {
  evaluate(request: ActionRequest): Promise<GuardEvaluation>;
  consumeApproval(input: {
    approval_id: string;
    request: ActionRequest;
  }): Promise<ApprovalConsumptionResult>;
}

export interface AuthorizedToolCall {
  tool_name: string;
  normalized_args: JsonObject;
}

export type ToolExecutor<TResult> = (
  call: AuthorizedToolCall,
) => TResult | Promise<TResult>;

export type GuardedExecutionResult<TResult> =
  | {
      outcome: "executed";
      authorization: "POLICY_ALLOW" | "APPROVAL_CONSUMED";
      approval_id: string | null;
      tool_name: string;
      normalized_args: JsonObject;
      result: TResult;
    }
  | {
      outcome: "denied";
      evaluation: GuardEvaluation;
    }
  | {
      outcome: "approval_pending";
      evaluation: GuardEvaluation;
      approval_id: string;
      expires_at: string;
    }
  | {
      outcome: "approval_not_authorized";
      approval_id: string;
      error: ApprovalConsumeError;
    }
  | {
      outcome: "gate_error";
      approval_id: string | null;
      error: "INVALID_GATE_RESPONSE";
    };

export interface GuardedToolRunner {
  execute<TResult>(input: {
    request: ActionRequest;
    toolExecutor: ToolExecutor<TResult>;
  }): Promise<GuardedExecutionResult<TResult>>;

  consumeAndExecute<TResult>(input: {
    approval_id: string;
    request: ActionRequest;
    toolExecutor: ToolExecutor<TResult>;
  }): Promise<GuardedExecutionResult<TResult>>;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * Gate clients can be adapters around an HTTP boundary, so do not trust their
 * TypeScript type alone. In particular, objects with a surprising prototype,
 * non-finite numbers, and cycles must never reach a tool executor.
 */
function isJsonValue(
  value: unknown,
  ancestors: Set<object> = new Set(),
): value is JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return true;
  }

  if (typeof value === "number") {
    return Number.isFinite(value);
  }

  if (typeof value !== "object" || ancestors.has(value)) {
    return false;
  }

  ancestors.add(value);
  const valid = Array.isArray(value)
    ? value.every((entry) => isJsonValue(entry, ancestors))
    : (Object.getPrototypeOf(value) === Object.prototype ||
        Object.getPrototypeOf(value) === null) &&
      Object.values(value).every((entry) => isJsonValue(entry, ancestors));
  ancestors.delete(value);
  return valid;
}

function isJsonObject(value: unknown): value is JsonObject {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null) &&
    isJsonValue(value)
  );
}

function expectedAuthorizedCall(request: ActionRequest): AuthorizedToolCall | null {
  const normalization = normalizeToolCall(request);

  if (
    !normalization.parse_ok ||
    !isNonEmptyString(normalization.normalized.tool_name) ||
    !isJsonObject(normalization.normalized.args)
  ) {
    return null;
  }

  return {
    tool_name: normalization.normalized.tool_name,
    normalized_args: normalization.normalized.args,
  };
}

/**
 * A gate authorization is valid only when it describes the exact normalized
 * request presented to this runner. The executor receives a canonical clone of
 * that request rather than an object supplied by the gate adapter.
 */
function authorizedCallForRequest(
  request: ActionRequest,
  authorized: Pick<AuthorizedToolCall, "tool_name" | "normalized_args">,
): AuthorizedToolCall | null {
  try {
    const expected = expectedAuthorizedCall(request);

    if (
      expected === null ||
      !isNonEmptyString(authorized.tool_name) ||
      !isJsonObject(authorized.normalized_args)
    ) {
      return null;
    }

    if (
      authorized.tool_name !== expected.tool_name ||
      canonicalJson(authorized.normalized_args) !==
        canonicalJson(expected.normalized_args)
    ) {
      return null;
    }

    // canonicalJson is validated above and makes this a detached plain JSON
    // object. A mutating executor therefore cannot alter the gate response or
    // authorization details returned to the caller.
    return {
      tool_name: expected.tool_name,
      normalized_args: JSON.parse(
        canonicalJson(expected.normalized_args),
      ) as JsonObject,
    };
  } catch {
    return null;
  }
}

/**
 * Creates the sole execution boundary used by integrations. The executor is
 * invoked only in the two explicitly authorized branches below.
 */
export function createGuardedToolRunner(
  gate: ActionGateClient,
): GuardedToolRunner {
  /**
   * The authoritative one-time transition is in the approval repository. This
   * local record is defense in depth for a buggy adapter that reports the same
   * consumed approval twice while this runner instance remains alive.
   */
  const locallyConsumedApprovalIds = new Set<string>();

  return {
    async execute<TResult>({
      request,
      toolExecutor,
    }: {
      request: ActionRequest;
      toolExecutor: ToolExecutor<TResult>;
    }): Promise<GuardedExecutionResult<TResult>> {
      const evaluation = await gate.evaluate(request);

      if (
        evaluation.decision === "ALLOW" &&
        evaluation.requires_approval === false
      ) {
        const call = authorizedCallForRequest(request, {
          tool_name: evaluation.normalized_tool,
          normalized_args: evaluation.normalized_args,
        });

        if (call === null) {
          return {
            outcome: "gate_error",
            approval_id: null,
            error: "INVALID_GATE_RESPONSE",
          };
        }

        return {
          outcome: "executed",
          authorization: "POLICY_ALLOW",
          approval_id: null,
          ...call,
          result: await toolExecutor(call),
        };
      }

      if (evaluation.decision === "REQUIRE_APPROVAL") {
        if (
          evaluation.requires_approval !== true ||
          typeof evaluation.approval_id !== "string" ||
          evaluation.approval_id.length === 0 ||
          typeof evaluation.expires_at !== "string" ||
          evaluation.expires_at.length === 0
        ) {
          return {
            outcome: "gate_error",
            approval_id: null,
            error: "INVALID_GATE_RESPONSE",
          };
        }

        if (
          authorizedCallForRequest(request, {
            tool_name: evaluation.normalized_tool,
            normalized_args: evaluation.normalized_args,
          }) === null
        ) {
          return {
            outcome: "gate_error",
            approval_id: null,
            error: "INVALID_GATE_RESPONSE",
          };
        }

        return {
          outcome: "approval_pending",
          evaluation,
          approval_id: evaluation.approval_id,
          expires_at: evaluation.expires_at,
        };
      }

      if (evaluation.decision === "ALLOW") {
        return {
          outcome: "gate_error",
          approval_id: null,
          error: "INVALID_GATE_RESPONSE",
        };
      }

      return { outcome: "denied", evaluation };
    },

    async consumeAndExecute<TResult>({
      approval_id,
      request,
      toolExecutor,
    }: {
      approval_id: string;
      request: ActionRequest;
      toolExecutor: ToolExecutor<TResult>;
    }): Promise<GuardedExecutionResult<TResult>> {
      const consumption = await gate.consumeApproval({
        approval_id,
        request,
      });

      if (!consumption.authorized) {
        return {
          outcome: "approval_not_authorized",
          approval_id,
          error: consumption.error,
        };
      }

      if (
        !isNonEmptyString(approval_id) ||
        consumption.approval_id !== approval_id
      ) {
        return {
          outcome: "gate_error",
          approval_id,
          error: "INVALID_GATE_RESPONSE",
        };
      }

      if (locallyConsumedApprovalIds.has(approval_id)) {
        return {
          outcome: "approval_not_authorized",
          approval_id,
          error: "APPROVAL_ALREADY_CONSUMED",
        };
      }

      // The gate contract defines authorized: true as an already-completed
      // atomic transition. Record it before validating the returned call, so a
      // malformed adapter response cannot later be followed by a replay that
      // reaches the executor.
      locallyConsumedApprovalIds.add(approval_id);

      const call = authorizedCallForRequest(request, {
        tool_name: consumption.tool_name,
        normalized_args: consumption.normalized_args,
      });

      if (call === null) {
        return {
          outcome: "gate_error",
          approval_id,
          error: "INVALID_GATE_RESPONSE",
        };
      }

      return {
        outcome: "executed",
        authorization: "APPROVAL_CONSUMED",
        approval_id: consumption.approval_id,
        ...call,
        result: await toolExecutor(call),
      };
    },
  };
}

export async function guardedExecute<TResult>(input: {
  gate: ActionGateClient;
  request: ActionRequest;
  toolExecutor: ToolExecutor<TResult>;
}): Promise<GuardedExecutionResult<TResult>> {
  return createGuardedToolRunner(input.gate).execute(input);
}
