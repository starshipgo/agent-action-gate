import { WorkersAiSemanticClassifier } from "./classifiers/workers-ai";
import type { SemanticClassifier } from "./classifiers/types";
import { evaluateAction } from "./evaluate";
import { validateEvaluationRequest } from "./http/validate-request";

export interface WorkerDependencies {
  createClassifier?: (env: Env) => SemanticClassifier;
}

export const MAX_REQUEST_BODY_BYTES = 64 * 1024;

type JsonBodyResult =
  | { ok: true; value: unknown }
  | { ok: false; error: "INVALID_JSON" | "REQUEST_BODY_TOO_LARGE" };

function jsonResponse(value: unknown, status: number): Response {
  return Response.json(value, {
    status,
    headers: {
      "cache-control": "no-store",
    },
  });
}

async function sha256(value: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return new Uint8Array(digest);
}

async function secretsEqual(left: string, right: string): Promise<boolean> {
  const [leftDigest, rightDigest] = await Promise.all([
    sha256(left),
    sha256(right),
  ]);

  let difference = 0;
  for (let index = 0; index < leftDigest.length; index += 1) {
    difference |= leftDigest[index]! ^ rightDigest[index]!;
  }

  return difference === 0;
}

async function isAuthorized(request: Request, env: Env): Promise<boolean> {
  const expectedKey = env.GATE_API_KEY;
  const authorization = request.headers.get("authorization");

  if (typeof expectedKey !== "string" || expectedKey === "" || !authorization) {
    return false;
  }

  const parts = authorization.split(" ");
  if (
    parts.length !== 2 ||
    parts[0]?.toLowerCase() !== "bearer" ||
    !parts[1]
  ) {
    return false;
  }

  return secretsEqual(parts[1], expectedKey);
}

async function readJsonBody(request: Request): Promise<JsonBodyResult> {
  const declaredLength = request.headers.get("content-length");
  if (
    declaredLength !== null &&
    /^\d+$/.test(declaredLength) &&
    Number(declaredLength) > MAX_REQUEST_BODY_BYTES
  ) {
    return { ok: false, error: "REQUEST_BODY_TOO_LARGE" };
  }

  if (request.body === null) {
    return { ok: false, error: "INVALID_JSON" };
  }

  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let byteLength = 0;
  let text = "";

  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }

      byteLength += chunk.value.byteLength;
      if (byteLength > MAX_REQUEST_BODY_BYTES) {
        await reader.cancel();
        return { ok: false, error: "REQUEST_BODY_TOO_LARGE" };
      }

      text += decoder.decode(chunk.value, { stream: true });
    }

    text += decoder.decode();
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false, error: "INVALID_JSON" };
  }
}

export function createWorker(dependencies: WorkerDependencies = {}) {
  const createClassifier =
    dependencies.createClassifier ??
    ((env: Env) => new WorkersAiSemanticClassifier(env.AI));

  return {
    async fetch(request: Request, env: Env): Promise<Response> {
      const url = new URL(request.url);

      if (url.pathname === "/health" && request.method === "GET") {
        return jsonResponse(
          { status: "ok", service: "agent-action-gate" },
          200,
        );
      }

      if (url.pathname !== "/v1/evaluate") {
        return jsonResponse({ error: "NOT_FOUND" }, 404);
      }

      if (!(await isAuthorized(request, env))) {
        return jsonResponse({ error: "UNAUTHORIZED" }, 401);
      }

      if (request.method !== "POST") {
        return new Response(JSON.stringify({ error: "METHOD_NOT_ALLOWED" }), {
          status: 405,
          headers: {
            allow: "POST",
            "cache-control": "no-store",
            "content-type": "application/json; charset=utf-8",
          },
        });
      }

      const body = await readJsonBody(request);
      if (!body.ok) {
        return jsonResponse({ error: body.error }, 400);
      }

      const validation = validateEvaluationRequest(body.value);
      if (!validation.ok) {
        return jsonResponse(
          { error: "INVALID_REQUEST", details: validation.errors },
          400,
        );
      }

      const decision = await evaluateAction(validation.value, (context) =>
        createClassifier(env).classify(context),
      );

      return jsonResponse(decision, 200);
    },
  } satisfies ExportedHandler<Env>;
}

export default createWorker();
