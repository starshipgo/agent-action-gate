import { YAML } from "bun";

interface DifyVariable {
  variable?: string;
  label?: string;
  type?: string;
  required?: boolean;
  max_length?: number;
}

interface DifyOutput {
  variable?: string;
  value_type?: string;
}

interface DifyNode {
  id?: string;
  data?: {
    title?: string;
    type?: string;
    code?: string;
    variables?: DifyVariable[];
    outputs?: DifyOutput[];
    structured_output?: {
      schema?: unknown;
    };
  };
}

interface DifyExport {
  workflow?: {
    graph?: {
      nodes?: DifyNode[];
    };
  };
}

const requestedPath = process.argv[2];
const candidates = requestedPath
  ? [requestedPath]
  : ["dify/agent-action-gate.dify.yml"];

let workflowPath: string | undefined;

for (const candidate of candidates) {
  if (await Bun.file(candidate).exists()) {
    workflowPath = candidate;
    break;
  }
}

if (!workflowPath) {
  throw new Error(`Dify export not found. Checked: ${candidates.join(", ")}`);
}

const document = YAML.parse(await Bun.file(workflowPath).text()) as DifyExport;
const nodes = document.workflow?.graph?.nodes ?? [];

function node(title: string): DifyNode {
  const match = nodes.find((candidate) => candidate.data?.title === title);

  if (!match) {
    throw new Error(`Expected Dify node not found: ${title}`);
  }

  return match;
}

function source(title: string): string {
  return node(title).data?.code ?? "";
}

function outputs(title: string): DifyOutput[] {
  return node(title).data?.outputs ?? [];
}

const report = {
  file: workflowPath,
  user_inputs: node("User Input").data?.variables ?? [],
  normalization: {
    node: "Normalize Tool Call",
    source: source("Normalize Tool Call"),
  },
  malformed_json_branch: {
    node: "Reject Invalid Tool Call",
    source: source("Reject Invalid Tool Call"),
    final_outputs: outputs("Invalid Input Output"),
  },
  semantic_risk: {
    node: "Semantic Risk Classifier",
    schema: node("Semantic Risk Classifier").data?.structured_output?.schema,
  },
  deterministic_policy: {
    node: "Policy Engine",
    source: source("Policy Engine"),
  },
  final_output_contract: outputs("Output"),
};

console.log(JSON.stringify(report, null, 2));
