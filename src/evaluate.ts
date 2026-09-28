import type {
  ActionRequest,
  EvaluationResult,
  SemanticRiskClassifier,
  SemanticRiskContext,
} from "./contracts";
import { normalizeToolCall } from "./normalize";
import { applyPolicy, rejectSemanticClassifierFailure } from "./policy";
import { normalizeSemanticRisk } from "./risk";

export const DEFAULT_CLASSIFIER_TIMEOUT_MS = 10_000;

export interface EvaluationOptions {
  classifier_timeout_ms?: number;
}

class SemanticClassifierTimeoutError extends Error {
  constructor() {
    super("semantic classifier timed out");
    this.name = "SemanticClassifierTimeoutError";
  }
}

function semanticContext(input: ActionRequest): SemanticRiskContext {
  return {
    source_text: String(input.source_text ?? ""),
    tool_name: String(input.tool_name ?? ""),
    agent_role: String(input.agent_role ?? ""),
    request_tenant: String(input.request_tenant ?? ""),
  };
}

async function classifyWithTimeout(
  classifySemanticRisk: SemanticRiskClassifier,
  context: SemanticRiskContext,
  timeoutMs: number,
) {
  let timeout: ReturnType<typeof setTimeout> | undefined;

  try {
    return await Promise.race([
      Promise.resolve().then(() => classifySemanticRisk(context)),
      new Promise<never>((_, reject) => {
        timeout = setTimeout(
          () => reject(new SemanticClassifierTimeoutError()),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}

/**
 * Normalizes first, skips the sensor for malformed arguments, and delegates all
 * decisions to the deterministic policy engine. The classifier stays injected
 * so this orchestration remains provider-neutral and tests need no live model.
 */
export async function evaluateAction(
  input: ActionRequest,
  classifySemanticRisk: SemanticRiskClassifier,
  options: EvaluationOptions = {},
): Promise<EvaluationResult> {
  const normalization = normalizeToolCall(input);

  if (!normalization.parse_ok) {
    return applyPolicy(normalization, null);
  }

  let semanticRisk;

  try {
    const rawRisk = await classifyWithTimeout(
      classifySemanticRisk,
      semanticContext(input),
      options.classifier_timeout_ms ?? DEFAULT_CLASSIFIER_TIMEOUT_MS,
    );
    semanticRisk = normalizeSemanticRisk(rawRisk);
  } catch {
    return rejectSemanticClassifierFailure(normalization);
  }

  return applyPolicy(normalization, semanticRisk);
}
