# Threat models

Output home for the `threat-model-analyst` skill (STRIDE-A threat modeling,
ported from github/awesome-copilot, lives in `bv-cc` → synced to `~/.claude/skills/`).

## How it's used

Ask for a threat model (e.g. "run a threat model of bv-mcp") or invoke
`/threat-model-analyst`. Each run writes a timestamped folder here:

```
docs/threat-model/
  threat-model-YYYYMMDD-HHMMSS/
    0-assessment.md          # executive summary
    0.1-architecture.md      # architecture overview + DFD
    1-threatmodel.md
    2-stride-analysis.md
    3-findings.md            # prioritized findings (CVSS 4.0 / CWE / OWASP)
    threat-inventory.json    # machine-readable inventory (incremental baseline)
```

**Incremental mode** diffs the current code against the most recent prior folder's
`threat-inventory.json`, tracking new / resolved / still-present threats. Keep old
folders committed so refreshes have a baseline to compare against.

## Before committing a generated model

This repo's `.githooks/pre-commit` blocks IP-address leakage and other ignored
local patterns. A threat model can surface internal endpoints, service bindings,
or IPs:

- Use placeholders for anything sensitive; raw IPs and per-IP detail belong in
  operator-only notes, not here (consistent with the analytics/investigation rules
  in `CLAUDE.md`).
- If the hook flags a reviewed false positive, override with `--no-verify` only
  after confirming nothing sensitive is staged.

## Related

- `devsecops-reviewer` skill — per-PR security review (OWASP Top 10, LLM Top 10,
  Agentic/ASI Top 10). Hand off to `threat-model-analyst` for a full architectural
  pass with DFDs and a tracked inventory.
