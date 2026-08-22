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
npm run typecheck:tests
npm run validate:internal-deps
npm run audit:repo-safety
```

`npm run typecheck:tests` is the only gate that typechecks the test trees —
`tsconfig.json` excludes `test`, and Vitest's esbuild transform strips types
without checking them, so specs are otherwise unchecked. It is a **ratchet, not
a burndown**: it compares per-file error counts against
`test/typecheck-baseline.json` and fails only on an increase. A decrease passes
and is reported — bank it with `npm run typecheck:tests -- --update`.

Per-file matters. A file's baseline is its allowance, so a file carrying banked
errors can absorb a real new one silently. That is why `test/raw-modules.d.ts`
declares Vite's `?raw` import suffix rather than letting those TS2307s sit in
the baseline: audits read prose and config as strings via `?raw` (the Workers
pool has no filesystem), and banking them was inflating ~40 files' allowances.
Prefer fixing an error class over raising a baseline.

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

## Environment-dependent checks

The default suite must remain offline and deterministic. Its Miniflare bindings
are declared in `vitest.config.mts`; test-specific service bindings belong in
the individual contract test, never in shared developer environment files.

Production probes, paid upstream lookups, and credentials are operator smoke
checks rather than CI gates. Run them only from an authenticated local shell
using ignored environment files or a secret manager; never place credentials in
fixture data, command arguments, logs, or checked-in configuration. A probe
must state the target, required binding or secret, expected cost, and the
public response contract it is validating.

## Calibration decision

`vitest.calibration.config.mts` matches no current specs. It remains a dormant
Node-only configuration documenting the intended one-hour calibration lane, but
it is not a quality signal and is not run by CI. Removing it would be a separate
repository-cleanup decision because it is an operator-facing entry point;
restoring it requires named, deterministic calibration fixtures and an explicit
CI policy first.
