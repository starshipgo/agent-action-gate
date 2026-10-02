# Contributing

This repository is being prepared for a small beta. Contributions should preserve the gate's central invariant: semantic classification is a sensor; deterministic policy alone returns `ALLOW`, `REQUIRE_APPROVAL`, or `DENY`.

For a local change: use Bun, keep tests offline, add regression cases for policy changes, run `bun test`, `bunx tsc --noEmit`, `bunx wrangler types --check`, `bun run build`, and `git diff --check`. Do not require a paid model for default tests. Use fictional data in examples and tests. Do not commit credentials, personal absolute paths, raw prompts from customers, or D1 state.

Policy changes should explain the threat and the intended authorization impact; do not merely alter golden expectations to pass. The public demo must not gain real tool imports or live credentials. Security reports belong in the private channel described in [SECURITY.md](SECURITY.md), not a public issue.
