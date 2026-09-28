import type { RawRiskSignals, SemanticRiskContext } from "../contracts";

/** Provider-neutral semantic sensor used by the evaluation orchestrator. */
export interface SemanticClassifier {
  classify(context: SemanticRiskContext): Promise<RawRiskSignals>;
}
