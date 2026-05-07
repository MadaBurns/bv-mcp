// Audit test: no committed (or about-to-be-committed) source file may contain a
// literal Blackveil API key (`bv_` prefix + 30+ url-safe characters), an AWS
// access key, or a private-key PEM header.
//
// Background: in 2026, `.mcp.json` was tracked at repo root with a real owner
// API key embedded in the URL. The key was caught by the gitleaks
// `generic-api-key` rule, but only because the surrounding context happened to
// match a generic pattern. A first-class audit makes the BV-key shape itself a
// hard fail regardless of surrounding heuristics.
//
// Implementation: tests run in the `@cloudflare/vitest-pool-workers` runtime,
// which has no `node:fs` / `node:child_process`. We use Vite's bulk `?raw`
// import via `import.meta.glob` — the file list is resolved at transform time
// (host Node) and the contents are bundled into the test module.
//
// This is not a strict equivalent of `git ls-files`: glob respects the
// filesystem, not git. We mitigate by (a) scoping to source-bearing extensions
// inside known-tracked top-level directories, and (b) excluding paths that
// would be `.gitignore`'d locally (`.dev/`, `.wrangler/`, `node_modules/`,
// `dist/`, `coverage/`, `.worktrees/`, `.claude/`). In CI (`actions/checkout`)
// only tracked files are present, so the result equals `git ls-files`.
//
// Per testing-methodology.md principle 4 — audit tests replace review checklists.

import { describe, it, expect } from 'vitest';

// 30+ chars after `bv_` rules out doc placeholders like `bv_Kx8eZ2rdtUPfdzR8e_...`
// (truncated with `...`) while still matching the real owner-key shape (40+ url-safe chars).
const BV_KEY_PATTERN = /bv_[A-Za-z0-9_]{30,}/;

// Sourced from .gitleaks.toml builtin AWS rule and the standard PEM private-key headers.
// We keep these intentionally narrow — broad pattern audits live in gitleaks proper;
// here we want zero false positives so the test stays cheap to keep green.
const AWS_ACCESS_KEY_PATTERN = /\bAKIA[0-9A-Z]{16}\b/;
const PRIVATE_KEY_HEADER_PATTERN = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY-----/;

interface SecretRule {
	readonly id: string;
	readonly pattern: RegExp;
}

const RULES: readonly SecretRule[] = [
	{ id: 'bv-api-key', pattern: BV_KEY_PATTERN },
	{ id: 'aws-access-key', pattern: AWS_ACCESS_KEY_PATTERN },
	{ id: 'private-key-pem', pattern: PRIVATE_KEY_HEADER_PATTERN },
];

// Files (relative to repo root) that are allowed to contain pattern matches.
// Audit tests + fixture files are excluded because they contain the regex
// literal itself, not a real secret. Spec files are excluded for the same reason.
const ALLOWLISTED_PATHS: readonly RegExp[] = [
	// This audit test itself contains the regex literals.
	/^test\/audits\/no-tracked-secrets\.audit\.test\.ts$/,
	// Test fixtures legitimately contain placeholder-shaped tokens.
	/^test\//,
	/^packages\/[^/]+\/test\//,
	// Any spec/test file outside the test/ tree.
	/\.(spec|test)\.ts$/,
	// .gitleaks.toml + githooks contain the patterns by definition.
	/^\.gitleaks\.toml$/,
	/^\.githooks\//,
	// Documented script defaults like `process.env.BV_API_KEY` and
	// `os.getenv("BV_API_KEY", "mock-key-for-local-testing")` reference the
	// env-var name, not a literal key. These don't match our 30-char pattern
	// but listing them for clarity if patterns ever loosen.
];

function isAllowlisted(rel: string): boolean {
	return ALLOWLISTED_PATHS.some((re) => re.test(rel));
}

// Bulk-load source-bearing files from known-tracked top-level directories.
// Worker bundles have a memory ceiling, so we scope by extension + directory.
// `eager: true` resolves at transform time on the host (Node) — works inside
// the Workers test pool because the strings are baked into the bundle.
//
// Globs are split per-directory both for clarity and to keep each glob's
// expansion bounded (avoids the unhandled-error worker crash we saw with a
// single broad `/**/*` pattern).
const FILE_GROUPS: ReadonlyArray<Record<string, unknown>> = [
	import.meta.glob(['/.mcp.json', '/.gitignore', '/.npmrc', '/server.json', '/smithery.yaml'], { query: '?raw', eager: true }),
	import.meta.glob('/*.{json,jsonc,yml,yaml,toml,md,mjs,cjs,js,ts}', { query: '?raw', eager: true }),
	import.meta.glob('/src/**/*.{ts,mjs,js,json,jsonc}', { query: '?raw', eager: true }),
	import.meta.glob('/packages/**/*.{ts,mjs,js,json,jsonc,md}', { query: '?raw', eager: true }),
	import.meta.glob('/scripts/**/*.{mjs,js,ts,py,sh}', { query: '?raw', eager: true }),
	import.meta.glob('/docs/**/*.{md,mdx}', { query: '?raw', eager: true }),
	import.meta.glob('/.github/**/*.{yml,yaml,md}', { query: '?raw', eager: true }),
];

function collectFiles(): Map<string, string> {
	const all = new Map<string, string>();
	for (const group of FILE_GROUPS) {
		for (const [absKey, mod] of Object.entries(group)) {
			// Glob keys start with `/`, e.g. `/src/index.ts`. Convert to repo-relative.
			const rel = absKey.startsWith('/') ? absKey.slice(1) : absKey;
			if (isAllowlisted(rel)) continue;
			// `?raw` modules expose the file body as `default`.
			const body = (mod as { default?: unknown })?.default;
			if (typeof body === 'string') {
				all.set(rel, body);
			}
		}
	}
	return all;
}

describe('no tracked secrets — BV API key + AWS + PEM', () => {
	// Build the regex literal at runtime so this test file itself doesn't
	// contain a key-shaped string that would self-trip the bv-api-key rule.
	const SAMPLE_REAL = 'bv_' + 'Kx8eZ2rdtUPfdzR8e_JfSCIVZ_UsdLQn3NOqwICW0HA';
	const SAMPLE_PLACEHOLDER = 'bv_' + 'Kx8eZ2rdtUPfdzR8e_...';

	it('regex matches a realistic BV API key shape (sanity check)', () => {
		expect(BV_KEY_PATTERN.test(SAMPLE_REAL)).toBe(true);
		// Doc placeholders (truncated) must NOT match.
		expect(BV_KEY_PATTERN.test(SAMPLE_PLACEHOLDER)).toBe(false);
		// Bare references must NOT match.
		expect(BV_KEY_PATTERN.test('hello bv_world')).toBe(false);
		expect(BV_KEY_PATTERN.test('process.env.BV_API_KEY')).toBe(false);
	});

	it('AWS access-key + PEM header sanity', () => {
		expect(AWS_ACCESS_KEY_PATTERN.test('AKIA' + 'IOSFODNN7EXAMPLE')).toBe(true);
		expect(AWS_ACCESS_KEY_PATTERN.test('not an akia value')).toBe(false);
		expect(PRIVATE_KEY_HEADER_PATTERN.test('-----BEGIN PRIVATE KEY-----')).toBe(true);
		expect(PRIVATE_KEY_HEADER_PATTERN.test('-----BEGIN OPENSSH PRIVATE KEY-----')).toBe(true);
		expect(PRIVATE_KEY_HEADER_PATTERN.test('-----BEGIN CERTIFICATE-----')).toBe(false);
	});

	it('audit covers source-bearing files (sanity floor)', () => {
		const files = collectFiles();
		// If this drops to zero, the glob is mis-scoped and the audit becomes a no-op.
		expect(files.size).toBeGreaterThan(50);
		// Repo-root config files we care about must be reachable.
		expect(files.has('.mcp.json')).toBe(true);
	});

	it('no scanned file contains a BV API key, AWS access key, or private-key PEM', () => {
		const files = collectFiles();
		const offenders: { file: string; line: number; rule: string; preview: string }[] = [];

		for (const [rel, body] of files) {
			const lines = body.split('\n');
			lines.forEach((text, idx) => {
				for (const rule of RULES) {
					const m = rule.pattern.exec(text);
					if (m) {
						offenders.push({
							file: rel,
							line: idx + 1,
							rule: rule.id,
							preview: m[0].slice(0, 8) + '…(redacted)',
						});
					}
				}
			});
		}

		expect(
			offenders,
			`Tracked files contain a literal secret. Rotate the credential and remove it from history:\n${offenders
				.map((o) => `  [${o.rule}] ${o.file}:${o.line}  ${o.preview}`)
				.join('\n')}`,
		).toEqual([]);
	});
});
