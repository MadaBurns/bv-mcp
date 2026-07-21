# CI/CD Cost Posture

bv-mcp's CI/CD runs at **$0**. This is a constraint we enforce, not a coincidence.

## Why it's free

- The repo is **public** → GitHub Actions has **free, unlimited** minutes.
- Every tool used is free for OSS: Node, Vitest, wrangler, wasm-pack, gitleaks, the built stdio CLI.
- The DNS-security dogfood scan uses **bv-mcp's own scanner** (no paid action).

## Enforced rules (`scripts/ci/check-workflow-cost.mjs`, audited by `test/audits/workflow-cost.audit.test.ts`)

- No `runs-on: self-hosted`.
- No paid marketplace action (denylist seeded with `MadaBurns/blackveil-dns-action`).
- Any new workflow must be free-tier; add paid actions to the denylist if they appear.

## Deploy (operator setup)

CD (`deploy-prod.yml`) is approval-gated. Before the first run, configure:

1. **GitHub → Settings → Environments → `production`** with yourself as a **Required reviewer**.
2. Environment secrets:
   - `CLOUDFLARE_API_TOKEN` — Workers Edit + Account Read.
   - `WRANGLER_DEPLOY_OVERLAY_B64` — `base64 -i .dev/wrangler.deploy.jsonc` (the gitignored private overlay).
   - `BV_INTERNAL_DEV_KEY` — owner-tier key for post-deploy verification.
3. Registry publish stays a **manual** post-deploy step (`mcp-publisher publish`) — see CLAUDE.md "Release".

`scripts/ci/verify-deploy.mjs` defaults to the `bv-dns-security-mcp.bv-edge.workers.dev` origin; self-hosters deploying under a different workers.dev subdomain can override it with the `VERIFY_URL` env var (set it in the workflow `env:` or as a `production` Environment variable).
