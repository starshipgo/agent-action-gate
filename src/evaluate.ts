import type {
  ActionRequest,
  EvaluationResult,
  SemanticRiskClassifier,
  SemanticRiskContext,
} from "./contracts";
import { normalizeToolCall } from "./normalize";
import {
  applyDeterministicPrechecks,
  applyPolicy,
  rejectSemanticClassifierFailure,
} from "./policy";
import type { NormalizationResult } from "./contracts";
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

export function semanticContext(input: ActionRequest): SemanticRiskContext {
  return {
    source_text: String(input.source_text ?? ""),
    tool_name: String(input.tool_name ?? ""),
    agent_role: String(input.agent_role ?? ""),
    request_tenant: String(input.request_tenant ?? ""),
  };
}

export type PreparedEvaluation =
  | { kind: "complete"; result: EvaluationResult }
  | {
      kind: "needs_semantic";
      input: ActionRequest;
      normalization: NormalizationResult;
    };

export function prepareEvaluation(input: ActionRequest): PreparedEvaluation {
  const normalization = normalizeToolCall(input);
  const precheck = applyDeterministicPrechecks(normalization);

  return precheck === null
    ? { kind: "needs_semantic", input, normalization }
    : { kind: "complete", result: precheck };
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
export async function evaluatePreparedAction(
  prepared: Extract<PreparedEvaluation, { kind: "needs_semantic" }>,
  classifySemanticRisk: SemanticRiskClassifier,
  options: EvaluationOptions = {},
): Promise<EvaluationResult> {
  let semanticRisk;

  try {
    const rawRisk = await classifyWithTimeout(
      classifySemanticRisk,
      semanticContext(prepared.input),
      options.classifier_timeout_ms ?? DEFAULT_CLASSIFIER_TIMEOUT_MS,
    );
    semanticRisk = normalizeSemanticRisk(rawRisk);
  } catch {
    return rejectSemanticClassifierFailure(prepared.normalization);
  }

  return applyPolicy(prepared.normalization, semanticRisk);
}

export async function evaluateAction(
  input: ActionRequest,
  classifySemanticRisk: SemanticRiskClassifier,
  options: EvaluationOptions = {},
): Promise<EvaluationResult> {
  const prepared = prepareEvaluation(input);

  if (prepared.kind === "complete") {
    return prepared.result;
  }

  return evaluatePreparedAction(prepared, classifySemanticRisk, options);
}
