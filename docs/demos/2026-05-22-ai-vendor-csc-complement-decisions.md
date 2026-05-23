# AI-Vendor CSC-Complement Demo — Decisions Locked

Date locked: 2026-05-22
Operator: [operator]
Branch: `demos/ai-vendor-csc-complement` (local-only, no remote)

## Decisions

| ID  | Decision                 | Locked value                                                                                                                        |
| --- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| D1  | Anthropic in deliverable | Both vendors named. Internal-only deliverable.                                                                                      |
| D2  | Public-DNS framing       | "observable from public DNS"; dangling CNAME with NXDOMAIN target = "misconfiguration"; no "vulnerability" wording without proof.   |
| D3  | Discovery mode           | tiered (prod has operator bindings; tools/list returns 200 on prod).                                                                |
| D4  | Raw output retention     | `.dev/demos/<vendor>/` gitignored; `docs/demos/` committed locally.                                                                 |
| D5  | External review gate     | N/A — internal-only.                                                                                                                |
| D6  | Remote state             | No `git push`, no PR. Branch stays local.                                                                                           |
| D7  | Auth                     | `BV_INTERNAL_DEV_KEY` from `.dev.vars` (owner-tier, unlimited quota). `BV_API_KEY` rotated 2026-05-22 via `.dev/rotate-bv-keys.sh`. |

## Target seed inventory

| Vendor    | Apex          | Brand aliases                 | ccTLD set                       | Known corporate sibling apex |
| --------- | ------------- | ----------------------------- | ------------------------------- | ---------------------------- |
| OpenAI    | openai.com    | openai, chatgpt, dall-e, sora | .ai .co .io .net .org .app .dev | (none asserted)              |
| Anthropic | anthropic.com | anthropic, claude             | .ai .co .io .net .org .app .dev | (none asserted)              |

`known_corporate_sibling_apex` left empty by design — only vendor-published siblings should ever be asserted. Tiered discovery enumerates them organically via the Tier-1 infrastructure-graph and Tier-3 classic sweep.

## Pre-execution verifications (already completed this session)

- `BV_INTERNAL_DEV_KEY` from `.dev.vars` returns HTTP 200 against `https://dns-mcp.blackveilsecurity.com/mcp` `tools/list`.
- Old `BV_INTERNAL_DEV_KEY` returns HTTP 401 (rotation verified).
- pandoc v3.9.0.2, jq v1.7.1-apple, openssl all present locally.

## Manual follow-ups outside this branch

1. Update claude.ai connector (Blackveil DNS) with the new `BV_API_KEY` from `.dev/.new-bv-api-key.tmp` (mode-600 handoff). Re-auth via OAuth if applicable.
2. After step 1: `rm -P .dev/.new-bv-api-key.tmp` (or `shred -u`).
3. Re-test the mobile/desktop connectors with a small scan.

These steps are operator-only and not part of the demo branch's commit history.
