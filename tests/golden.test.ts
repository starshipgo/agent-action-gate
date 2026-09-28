import { describe, expect, test } from "bun:test";
import golden from "../golden/cases.json";
import type {
  ActionRequest,
  EvaluationResult,
  RawSemanticRisk,
} from "../src/contracts";
import { evaluateAction } from "../src/evaluate";

interface GoldenCase {
  name: string;
  input: ActionRequest;
  semantic_risk?: Partial<RawSemanticRisk>;
  classifier_must_not_run?: boolean;
  expected: EvaluationResult;
}

const corpus = golden as {
  default_semantic_risk: RawSemanticRisk;
  cases: GoldenCase[];
};

describe("Dify golden cases", () => {
  for (const fixture of corpus.cases) {
    test(fixture.name, async () => {
      let classifierCalls = 0;

      const output = await evaluateAction(fixture.input, () => {
        classifierCalls += 1;

        if (fixture.classifier_must_not_run) {
          throw new Error("semantic classifier ran for malformed JSON");
        }

        return {
          ...corpus.default_semantic_risk,
          ...fixture.semantic_risk,
        };
      });

      expect(output).toEqual(fixture.expected);
      expect(classifierCalls).toBe(fixture.classifier_must_not_run ? 0 : 1);
    });
  }
});
