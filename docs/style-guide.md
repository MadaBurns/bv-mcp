# Documentation Style Guide

This guide defines the writing conventions for `README.md` and files under `docs/`.

## Goals

- Prioritize implementation accuracy over marketing language.
- Keep docs maintainable by using canonical sources.
- Use wording that matches code and protocol behavior.

## Voice and Tone

- Use technical, neutral, OSS-first language.
- Avoid promotional claims unless they are verifiable and linked.
- Prefer deterministic phrasing: "must", "does", "returns", "runs".
- Avoid second-person guidance unless in setup/runbook steps.

## Terminology

Use these canonical terms consistently:

- `MCP`
- `JSON-RPC 2.0`
- `Streamable HTTP`
- `Cloudflare Workers`
- `tools/call`
- `per-IP`
- `KV-backed`
- `in-memory fallback`

When naming limits and values, mirror implementation constants from code.

## Document Structure

Recommended section order for technical docs:

1. Purpose / scope
2. Interface or behavior definition
3. Constraints and edge cases
4. References to canonical source files

For runbooks (troubleshooting), use numbered step headings.

## Formatting Rules

- Use sentence case headings.
- Keep paragraphs short (1-3 sentences).
- Use bullet lists for behavior enumerations.
- Use fenced code blocks with language tags (`bash`, `json`, `yaml`).
- Use inline code for paths, symbols, methods, and config keys.

## Source of Truth and Cross-References

- Link to code paths for canonical behavior.
- Avoid duplicating large configuration blocks in multiple docs.
- Prefer one canonical doc per topic and link from others.

## Consistency Checks Before Merge

- Verify tool names match `tools/list` behavior.
- Verify limits/weights match source files (`rate-limiter.ts`, `scoring.ts`).
- Verify endpoint paths and methods are consistent.
- Verify links to local docs resolve.

## Non-Goals

- Marketing copywriting
- Product roadmap narratives
- Unverified benchmark claims without linked methodology
