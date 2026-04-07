---
description: Add a new MCP tool end to end in this repository, including schema registration, handler wiring, scan integration, tests, and docs updates.
name: Add MCP Tool
argument-hint: Tool name, purpose, inputs, and whether it should run inside scan_domain
agent: agent
---
Implement a new MCP tool in this repository using existing patterns and minimal unrelated changes.

Inputs to use:
- Tool name and check module name
- Purpose and expected outputs
- Required arguments and validation rules
- Include in scan_domain: yes or no

Execution requirements:
- Follow repository conventions in [CLAUDE.md](../../CLAUDE.md).
- Validate and normalize domain input with sanitize helpers.
- Build findings and check results via scoring helpers.
- Register tool schema and tool handler wiring.
- If scan integration is requested, add orchestration and cache handling.
- Add or update tests in test/ with dns-mock helpers and proper cleanup.
- Update relevant documentation links and tool lists.

Output format:
1. Summary of changes.
2. Files changed with one-line purpose each.
3. Test commands run and results.
4. Any follow-up actions needed.
