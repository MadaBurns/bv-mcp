# Repository Guidelines

## Project Structure & Module Organization

This repository is a TypeScript Cloudflare Workers MCP server for DNS and email-security checks. Core Worker code lives in `src/`: tool implementations are in `src/tools/`, request handlers in `src/handlers/`, shared scoring/auth/config logic in `src/lib/`, and tenant workflows in `src/tenants/`. Tests live in `test/`, with focused specs such as `test/check-*.spec.ts`, audit tests under `test/audits/`, and chaos coverage under `test/chaos/`. Operational scripts live in `scripts/`, documentation in `docs/`, static/report assets in `assets/` and `reports/`, and the Rust/WASM helper crate in `crates/bv-wasm-core/`.

## Build, Test, and Development Commands

- `npm test` runs the Vitest suite, mostly in the Cloudflare Workers pool.
- `npm test -- test/path.spec.ts` runs a focused test file.
- `npm run typecheck` runs `tsc --noEmit`.
- `npm run lint` runs ESLint.
- `npm run build` bundles the package with `tsup`.
- `npm run build:wasm` rebuilds the WASM crate.
- `npm run validate:internal-deps` checks internal dependency rules.
- `npm run deploy:prod` generates private Wrangler config and deploys production. Use only with approved credentials.

## Coding Style & Naming Conventions

Use TypeScript ESM. Formatting follows `.editorconfig` and Prettier: tabs, LF endings, UTF-8, single quotes, semicolons, and 140-character print width. YAML uses spaces. Keep tool names snake_case for MCP registration, file names kebab-case, and tests named `*.spec.ts`. Prefer existing helpers such as `buildCheckResult()` and `createFinding()` over hand-built result objects.

## Testing Guidelines

Use Vitest. Mock DNS through `test/helpers/dns-mock.ts` and reset mocks/cache in `afterEach`. Add focused tests next to the affected behavior, audit tests for configuration invariants, and chaos tests when dispatcher/tool coverage changes. For new DNS tools, follow `test/check-<name>.spec.ts` patterns and update all registry/orchestration tests.

## Commit & Pull Request Guidelines

History uses concise imperative subjects, often Conventional Commit style: `fix(...)`, `feat(...)`, `test(...)`, `chore(...)`, or release subjects like `Release v2.21.4`. Keep commits scoped. PRs should describe behavior changes, list verification commands, link issues when applicable, and include screenshots or generated-report notes only for user-visible report/PDF changes.

## Security & Configuration Tips

The license is BUSL-1.1; retain SPDX headers on source files. Do not commit `.dev.vars`, generated private Wrangler config secrets, API keys, customer data, or internal CSC artifacts under `.dev/`. Non-secret Worker vars belong in `wrangler.jsonc`; secrets belong in Wrangler secrets or approved local env files.

Use synthetic fixtures only. There must be no real customer data, real tenant domains, customer emails, public IP literals, internal hostnames, generated reports, PDFs, CSC outputs, or proprietary planning material in tracked files. Prefer `example.test`, `example.com`, `example.invalid`, and RFC 5737 IPs such as `192.0.2.10`, `198.51.100.20`, and `203.0.113.30`.

Before changing fixtures, docs, scripts, workflows, hooks, publishing metadata, or safety policy, run `npm run audit:repo-safety` plus the focused audit tests that cover the changed surface.
