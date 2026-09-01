# Production capacity testing

This directory is the source of truth for controlled capacity testing of the production MCP service.

Capacity testing is an operator-controlled production change. It must not start from an ordinary development credential, an unapproved source address, or an uncoordinated workstation. Cloudflare DDoS protection and emergency controls remain enabled throughout every test.

## Documents

- [Measurement procedure](./global-ceiling-procedure.md) — ceilings, SLOs, stages, workload mix, and evidence requirements.
- [Operator runbook](./global-ceiling-runbook.md) — preparation, execution, stop conditions, recovery, and cleanup.
- [2026-09-01 report](./2026-09-01-global-ceiling-report.md) — observed results and their limits.
- [2026-09-01 incident note](./2026-09-01-cloudflare-ddos-activation.md) — DDoS activation, response, and corrective actions.

## Implemented harness

- `scripts/load/global-ceiling.k6.js` implements the edge, protocol, useful, heavy, and mixed lanes.
- `scripts/load/run-global-ceiling.mjs` executes a local staircase, records independent health probes, stops after two consecutive unstable stages, and writes sanitized JSON evidence to a temporary directory.
- `npm run load:global-ceiling` runs one configured k6 test.
- `npm run load:global-ceiling:run` runs the staircase orchestrator.

The harness does not grant approval to run a production test. Follow the runbook gates first.
