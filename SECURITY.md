# Security policy

Agent Action Gate is a beta/portfolio project, not a promise of production-grade protection. Do not use real customer secrets or production external executors in the public demo.

## Responsible disclosure

Once the public GitHub repository is created, private security reports should use GitHub's **private vulnerability reporting** feature through the repository's Security tab. The maintainer must enable that feature at publication. Until it is enabled, do not publish exploit details, credentials, customer data, or private URLs in a public issue. No personal email address is required or published here.

Please provide a concise reproduction with fictional data, affected version/commit, impact, and suggested mitigations. Do not test against other tenants, real customers, or live external tools. We will acknowledge and triage reports as capacity permits; no response-time guarantee is offered.

## Secrets and data

Never commit API keys, operator credentials, Cloudflare tokens, `.env*`, `.dev.vars*`, D1 local files, or logs. The public demo must use isolated demo resources and fake executors only. Run `bun run check:public-release` before publishing, investigate all findings, and rotate any exposed credential. Scanner output gives locations, not secret values; it is a guardrail, not a guarantee.
