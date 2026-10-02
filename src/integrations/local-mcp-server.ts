import type { JsonObject, JsonValue } from "../contracts";
import type { GuardedToolRunner } from "./guarded-tool-runner";
import {
  createLocalMcpGuardedTools,
  isLocalMcpToolName,
  type DemoToolExecutors,
  type LocalMcpCallContext,
} from "./local-mcp-tools";

export type JsonRpcId = string | number | null;

export type McpJsonRpcResponse =
  | {
      jsonrpc: "2.0";
      id: JsonRpcId;
      result: unknown;
    }
  | {
      jsonrpc: "2.0";
      id: JsonRpcId;
      error: { code: number; message: string };
    };

export interface LocalMcpJsonRpcHandler {
  handle(request: unknown): Promise<McpJsonRpcResponse | null>;
}

const DEFAULT_PROTOCOL_VERSION = "2025-06-18";

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
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

  ancestors.add(value);
  const valid = Array.isArray(value)
    ? value.every((item) => isJsonValue(item, ancestors))
    : isRecord(value) &&
      Object.values(value).every((item) => isJsonValue(item, ancestors));
  ancestors.delete(value);
  return valid;
}

function isJsonObject(value: unknown): value is JsonObject {
  return isRecord(value) && isJsonValue(value);
}

function isJsonRpcId(value: unknown): value is JsonRpcId {
  return (
    value === null ||
    typeof value === "string" ||
    (typeof value === "number" && Number.isFinite(value))
  );
}

function success(id: JsonRpcId, result: unknown): McpJsonRpcResponse {
  return { jsonrpc: "2.0", id, result };
}

function failure(
  id: JsonRpcId,
  code: number,
  message: string,
): McpJsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

/**
 * Dependency-free, hostable MCP JSON-RPC handler. A transport can pass parsed
 * request objects to `handle`; no network or stdio process is started here.
 * Only initialize, tools/list, and tools/call are exposed. In particular,
 * operator approval and rejection are deliberately absent.
 */
export function createLocalMcpJsonRpcHandler(input: {
  runner: GuardedToolRunner;
  executors: DemoToolExecutors;
  getTrustedContext: () =>
    | LocalMcpCallContext
    | PromiseLike<LocalMcpCallContext>;
  protocolVersion?: string;
}): LocalMcpJsonRpcHandler {
  const tools = createLocalMcpGuardedTools({
    runner: input.runner,
    executors: input.executors,
    getTrustedContext: input.getTrustedContext,
  });

  return {
    async handle(request: unknown): Promise<McpJsonRpcResponse | null> {
      if (!isRecord(request) || request.jsonrpc !== "2.0") {
        return failure(null, -32600, "Invalid Request");
      }

      if (!("id" in request)) {
        return null;
      }

      const id = request.id;
      if (!isJsonRpcId(id) || typeof request.method !== "string") {
        return failure(null, -32600, "Invalid Request");
      }

      if (request.method === "initialize") {
        return success(id, {
          protocolVersion: input.protocolVersion ?? DEFAULT_PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: {
            name: "agent-action-gate-local",
            version: "0.1.0",
          },
        });
      }

      if (request.method === "tools/list") {
        return success(id, tools.listTools());
      }

      if (request.method !== "tools/call") {
        return failure(id, -32601, "Method not found");
      }

      const params = request.params;
      if (
        !isRecord(params) ||
        typeof params.name !== "string" ||
        !isLocalMcpToolName(params.name)
      ) {
        return failure(id, -32602, "Invalid params");
      }

      const args = params.arguments ?? {};
      if (!isJsonObject(args)) {
        return failure(id, -32602, "Invalid params");
      }

      try {
        return success(
          id,
          await tools.callTool({ name: params.name, arguments: args }),
        );
      } catch {
        return failure(id, -32603, "Internal error");
      }
    },
  };
}
