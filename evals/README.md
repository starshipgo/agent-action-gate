# Local adversarial evaluation corpus

Run `bun run eval` to evaluate `cases.json` with fixed semantic-risk fixtures and write `report.json`. This is deterministic, offline, and does not call a paid model. `mode: deterministic` cases test policy/precheck behavior; `mode: semantic_fixture` cases inject structured sensor outputs into the same authorization core. The nine categories cover prompt injection, data exfiltration, authority impersonation, approval bypass, cross-tenant attempts, malformed tool calls, refund manipulation, benign controls, and ambiguous cases.

The JSON report labels fixture results as `fixture_regression` and `measured_semantic_accuracy: "not_measured"`. Passing fixtures does **not** measure classifier detection accuracy.

An operator may explicitly opt into a compatible HTTPS provider endpoint later with `AAG_EVAL_LIVE=1`, `AAG_EVAL_PROVIDER_URL`, `AAG_EVAL_PROVIDER_TOKEN`, and `bun run evals/run.ts --live`. This makes network calls, may incur provider cost, and is **not** part of the default suite. Provider output is treated as structured signals only; deterministic policy still decides. Review the endpoint's contract and privacy obligations before enabling it. Do not commit provider credentials or a report containing sensitive prompts.
