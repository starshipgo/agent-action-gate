import type { ActionRequest, JsonObject, JsonValue } from "../contracts";
import type {
  GuardedExecutionResult,
  GuardedToolRunner,
  ToolExecutor,
} from "./guarded-tool-runner";

const MCP_TO_GATE_TOOL = {
  crm_read_contact: "crm.read_contact",
  email_send: "email.send",
  refund_create: "refund.create",
} as const;

export type LocalMcpToolName = keyof typeof MCP_TO_GATE_TOOL;
type GateToolName = (typeof MCP_TO_GATE_TOOL)[LocalMcpToolName];

const LOCAL_MCP_TOOL_NAME_SET: ReadonlySet<string> = new Set(
  Object.keys(MCP_TO_GATE_TOOL),
);

export function isLocalMcpToolName(value: string): value is LocalMcpToolName {
  return LOCAL_MCP_TOOL_NAME_SET.has(value);
}

export interface LocalMcpCallContext {
  /** Supplied by the trusted MCP host, never accepted from model tool args. */
  agent_role: string;
  source_text: string;
  request_tenant: string;
}

export interface LocalMcpToolDefinition {
  name: LocalMcpToolName;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, { type: "string" | "integer" }>;
    required: string[];
    additionalProperties: boolean;
  };
}

export interface LocalMcpToolResult {
  content: Array<{ type: "text"; text: string }>;
  structuredContent: JsonObject;
  isError?: true;
}

export type DemoToolExecutors = {
  [TTool in GateToolName]: ToolExecutor<JsonValue>;
};

export interface LocalMcpGuardedTools {
  listTools(): { tools: readonly LocalMcpToolDefinition[] };
  callTool(input: {
    name: LocalMcpToolName;
    /** Runtime input from an MCP client; validate before it reaches the gate. */
    arguments: unknown;
  }): Promise<LocalMcpToolResult>;
}

const TOOL_DEFINITIONS: readonly LocalMcpToolDefinition[] = [
  {
    name: "crm_read_contact",
    description: "Read one CRM contact through Agent Action Gate.",
    inputSchema: {
      type: "object",
      properties: {
        contact_id: { type: "string" },
        target_tenant: { type: "string" },
      },
      required: ["contact_id", "target_tenant"],
      additionalProperties: false,
    },
  },
  {
    name: "email_send",
    description: "Request an outbound email through Agent Action Gate.",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "string" },
        subject: { type: "string" },
        body: { type: "string" },
        attachment: { type: "string" },
        target_tenant: { type: "string" },
      },
      required: ["to", "target_tenant"],
      additionalProperties: false,
    },
  },
  {
    name: "refund_create",
    description: "Request a refund through Agent Action Gate.",
    inputSchema: {
      type: "object",
      properties: {
        amount_minor: { type: "integer" },
        recipient: { type: "string" },
        target_tenant: { type: "string" },
      },
      required: ["amount_minor", "target_tenant"],
      additionalProperties: false,
    },
  },
];

const TOOL_DEFINITIONS_BY_NAME: ReadonlyMap<
  LocalMcpToolName,
  LocalMcpToolDefinition
> = new Map(TOOL_DEFINITIONS.map((definition) => [definition.name, definition]));

function isPlainObject(value: unknown): value is Record<string, unknown> {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return false;
    }

    const prototype = Object.getPrototypeOf(value) as unknown;
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

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

  try {
    ancestors.add(value);
    const valid = Array.isArray(value)
      ? value.every((entry) => isJsonValue(entry, ancestors))
      : isPlainObject(value) &&
        Object.values(value).every((entry) => isJsonValue(entry, ancestors));
    ancestors.delete(value);
    return valid;
  } catch {
    ancestors.delete(value);
    return false;
  }
}

function matchesDeclaredType(
  value: unknown,
  type: LocalMcpToolDefinition["inputSchema"]["properties"][string]["type"],
): boolean {
  if (type === "string") {
    return typeof value === "string";
  }

  // A JSON Schema integer that cannot be represented safely in JavaScript
  // cannot be bound exactly to the gate request, so reject it at the MCP
  // boundary rather than allowing an ambiguous authorization.
  return typeof value === "number" && Number.isSafeInteger(value);
}

/**
 * MCP JSON-RPC parsing establishes only that arguments are JSON. This runtime
 * check enforces the declared per-tool input schema before a call can reach
 * either the policy gate or an executor. It intentionally exposes no details
 * about malformed client values in its result.
 */
function conformsToToolInputSchema(
  name: string,
  argumentsValue: unknown,
): argumentsValue is JsonObject {
  if (!isLocalMcpToolName(name) || !isPlainObject(argumentsValue)) {
    return false;
  }

  const definition = TOOL_DEFINITIONS_BY_NAME.get(name);
  if (definition === undefined) {
    return false;
  }

  try {
    const { inputSchema } = definition;
    for (const requiredName of inputSchema.required) {
      if (!Object.prototype.hasOwnProperty.call(argumentsValue, requiredName)) {
        return false;
      }
    }

    for (const [argumentName, argumentValue] of Object.entries(
      argumentsValue,
    )) {
      const property = inputSchema.properties[argumentName];
      if (property === undefined) {
        if (!inputSchema.additionalProperties) {
          return false;
        }

        // No current local tool permits extra properties. If a future schema
        // does, it still accepts only ordinary JSON values.
        if (!isJsonValue(argumentValue)) {
          return false;
        }
      } else if (!matchesDeclaredType(argumentValue, property.type)) {
        return false;
      }
    }

    return true;
  } catch {
    // Proxies/getters and other surprising runtime values must never be able
    // to trigger a gate evaluation or tool execution.
    return false;
  }
}

function invalidArgumentsResult(): LocalMcpToolResult {
  return {
    content: [
      { type: "text", text: "Tool arguments did not match the declared schema." },
    ],
    structuredContent: {
      status: "invalid_arguments",
      error: "INVALID_TOOL_ARGUMENTS",
    },
    isError: true,
  };
}

function requestForTool(
  name: LocalMcpToolName,
  args: JsonObject,
  context: LocalMcpCallContext,
): ActionRequest {
  return {
    agent_role: context.agent_role,
    tool_name: MCP_TO_GATE_TOOL[name],
    arguments_json: JSON.stringify(args),
    source_text: context.source_text,
    request_tenant: context.request_tenant,
  };
}

function asStructuredResult(
  result: GuardedExecutionResult<JsonValue>,
): LocalMcpToolResult {
  if (result.outcome === "executed") {
    return {
      content: [{ type: "text", text: "Tool execution completed." }],
      structuredContent: {
        status: "executed",
        authorization: result.authorization,
        tool_name: result.tool_name,
        result: result.result,
      },
    };
  }

  if (result.outcome === "approval_pending") {
    return {
      content: [
        {
          type: "text",
          text: "Human approval is required before this tool can execute.",
        },
      ],
      structuredContent: {
        status: "approval_pending",
        decision: "REQUIRE_APPROVAL",
        approval_id: result.approval_id,
        expires_at: result.expires_at,
      },
    };
  }

  if (result.outcome === "denied") {
    return {
      content: [{ type: "text", text: "Agent Action Gate denied the call." }],
      structuredContent: {
        status: "denied",
        decision: "DENY",
        risk_level: result.evaluation.risk_level,
        policy_codes: result.evaluation.policy_codes,
      },
      isError: true,
    };
  }

  if (result.outcome === "gate_error") {
    return {
      content: [
        { type: "text", text: "Agent Action Gate returned an invalid response." },
      ],
      structuredContent: {
        status: "gate_error",
        error: result.error,
      },
      isError: true,
    };
  }

  return {
    content: [{ type: "text", text: "Approval did not authorize execution." }],
    structuredContent: {
      status: "approval_not_authorized",
      approval_id: result.approval_id,
      error: result.error,
    },
    isError: true,
  };
}

/**
 * A small MCP-shaped local adapter. It deliberately exposes only tool listing
 * and invocation; operator approval and rejection remain a separate channel.
 * The underlying executors are closed over and reachable only through the
 * guarded runner.
 */
export function createLocalMcpGuardedTools(input: {
  runner: GuardedToolRunner;
  executors: DemoToolExecutors;
  /** Host-injected identity context; it is not part of MCP tool arguments. */
  getTrustedContext: () =>
    | LocalMcpCallContext
    | PromiseLike<LocalMcpCallContext>;
}): LocalMcpGuardedTools {
  return {
    listTools: () => ({ tools: TOOL_DEFINITIONS }),
    async callTool({ name, arguments: args }) {
      if (!conformsToToolInputSchema(name, args)) {
        return invalidArgumentsResult();
      }

      const gateToolName = MCP_TO_GATE_TOOL[name];
      const trustedContext = await input.getTrustedContext();
      const result = await input.runner.execute({
        request: requestForTool(name, args, trustedContext),
        toolExecutor: input.executors[gateToolName],
      });

      return asStructuredResult(result);
    },
  };
}
