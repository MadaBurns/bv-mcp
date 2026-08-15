# Test environments and characterization contracts

`npm test` is the authoritative runtime suite. It uses
`@cloudflare/vitest-pool-workers`, therefore route, binding, Durable Object,
KV, queue, and service-binding contracts execute in a Workerd-compatible
Miniflare environment.

## Commands

```bash
npm test
npx vitest run --config vitest.node.config.mts
npm run typecheck && npm run lint && npm run build
npm run validate:internal-deps
npm run audit:repo-safety
```

The Node suite is deliberately limited to filesystem, process, PDF, and report
code that cannot run in Workerd. It is not evidence of Worker runtime
compatibility.

## Coverage decision

Do **not** run V8 coverage against the Worker pool. Workerd does not expose
`node:inspector`; Vitest's V8 provider consequently reports false zeroes.
Until a source-instrumentation tool is proven against Workerd, coverage is
measured by the executable contract suites and structural audits, not a line
percentage. Pure runtime-agnostic modules may gain Node coverage only when the
same behavior is already exercised by a Worker contract.

## Contract fixtures

Fixtures must be deterministic, redact credentials, and model normalized public
responses rather than provider payloads. Network, production probes, and paid
service integrations are optional operator smoke checks, never CI gates.

The calibration configuration currently matches no specs. The explicit decision
is **defer removal**: it documents the intended one-hour Node calibration lane,
but it must not be treated as a passing quality signal until named calibration
fixtures are restored in a separately reviewed change.
