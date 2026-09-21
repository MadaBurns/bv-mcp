// SPDX-License-Identifier: BUSL-1.1

/**
 * RAIL 1 of the TypeSafe (System One / Jev) integration: **never the score.**
 *
 * `src/lib/typesafe.ts` wraps a THIRD-PARTY INFERENCE API. Nothing reachable from
 * `computeScanScore` or from the `scan_domain` orchestration path may import it,
 * for three reasons:
 *
 *  1. The scan score is deterministic by design. A weight or grade change
 *     re-grades every customer and is an operator decision; a probabilistic
 *     judgment in that path would make the score silently non-reproducible.
 *  2. `check_lookalikes` is the only consumer contemplated, and it is
 *     `scanIncluded: false`. Scored checks abstain via `checkStatus`; an
 *     inference timeout must never be able to zero a category.
 *  3. README.md markets the checks as "Read-only … Most are passive lookups over
 *     public Cloudflare DNS-over-HTTPS" and names the only direct-query tools.
 *     Third-party inference on a scan path is NEW EGRESS and would contradict
 *     that claim.
 *
 * ⚠️ This is enforced MECHANICALLY rather than by convention because the wiring
 * is latent, not hypothetical: `lookalikes` carries `importance: 2` in
 * `packages/dns-checks/src/scoring/profiles.ts` while being absent from
 * SCAN_CATEGORIES. A future edit completing that wiring would otherwise silently
 * pull an inference dependency into the score.
 *
 * Implementation note: `node:fs` is not reliable in the Cloudflare Workers test
 * pool. `import.meta.glob` with `query: '?raw'` is resolved by Vite at transform
 * time against the real filesystem and works inside the Workers runtime without
 * executing the imported modules — the same mechanism as
 * `deprecated-shim-absence.audit.test.ts`.
 */

import { describe, it, expect } from 'vitest';

const FORBIDDEN_MODULE = '@typesafe-ai/sdk';
/** Path suffix of the wrapper, matched however the import is spelled. */
const FORBIDDEN_LOCAL = 'lib/typesafe';

const workerSources = import.meta.glob('../../src/**/*.ts', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const dnsChecksSources = import.meta.glob('../../packages/dns-checks/src/**/*.ts', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const allSources: Record<string, string> = { ...workerSources, ...dnsChecksSources };

/** Normalise a glob key to a repo-relative path (`src/...`, `packages/...`). */
function repoPath(globKey: string): string {
	return globKey.replace(/^(\.\.\/)+/, '');
}

const byRepoPath = new Map<string, string>();
for (const [key, source] of Object.entries(allSources)) {
	byRepoPath.set(repoPath(key), source);
}

/** Every module specifier in `source`, from static imports, re-exports and dynamic import(). */
function importSpecifiers(source: string): string[] {
	const specs: string[] = [];
	// `import ... from '<spec>'` and `export ... from '<spec>'`
	for (const m of source.matchAll(/\b(?:import|export)\b[^'";]*?\bfrom\s*['"]([^'"]+)['"]/g)) specs.push(m[1]);
	// bare side-effect `import '<spec>'`
	for (const m of source.matchAll(/\bimport\s*['"]([^'"]+)['"]/g)) specs.push(m[1]);
	// `import('<spec>')`
	for (const m of source.matchAll(/\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) specs.push(m[1]);
	return specs;
}

/** Resolve a RELATIVE specifier against the importing file, to a key in `byRepoPath`. */
function resolveRelative(fromRepoPath: string, spec: string): string | null {
	if (!spec.startsWith('.')) return null;
	const fromDir = fromRepoPath.split('/').slice(0, -1);
	const parts = spec.split('/');
	const stack = [...fromDir];
	for (const part of parts) {
		if (part === '.' || part === '') continue;
		else if (part === '..') stack.pop();
		else stack.push(part);
	}
	const base = stack.join('/').replace(/\.(ts|js)$/, '');
	for (const candidate of [`${base}.ts`, `${base}/index.ts`]) {
		if (byRepoPath.has(candidate)) return candidate;
	}
	return null;
}

/**
 * Breadth-first transitive walk from `entrypoints`. Returns every reached file
 * plus the first import CHAIN that reaches a forbidden specifier, so a failure
 * names the path rather than just the endpoint.
 */
function walk(entrypoints: string[]): { reached: Set<string>; violation: string[] | null } {
	const reached = new Set<string>();
	const queue: Array<{ path: string; chain: string[] }> = [];
	for (const e of entrypoints) {
		if (byRepoPath.has(e)) queue.push({ path: e, chain: [e] });
	}
	while (queue.length > 0) {
		const { path, chain } = queue.shift()!;
		if (reached.has(path)) continue;
		reached.add(path);
		const source = byRepoPath.get(path);
		if (source === undefined) continue;
		for (const spec of importSpecifiers(source)) {
			if (spec === FORBIDDEN_MODULE || spec.includes(FORBIDDEN_LOCAL)) {
				return { reached, violation: [...chain, spec] };
			}
			const next = resolveRelative(path, spec);
			if (next && !reached.has(next)) queue.push({ path: next, chain: [...chain, next] });
		}
	}
	return { reached, violation: null };
}

const SCAN_ENTRYPOINTS = [
	'src/tools/scan-domain.ts',
	// `byRepoPath` is a Map — enumerate its keys, never Object.keys(), which
	// returns [] and would silently reduce this audit to a single entrypoint.
	...[...byRepoPath.keys()].filter((p) => p.startsWith('packages/dns-checks/src/scoring/')),
];

describe('TypeSafe is unreachable from the scan-scoring path (RAIL 1)', () => {
	it('resolves the scan entrypoints and a non-trivial import graph', () => {
		// Positive control. Without this, every assertion below could pass simply
		// because the glob resolved nothing and the walk visited zero files.
		expect(byRepoPath.has('src/tools/scan-domain.ts'), 'src/tools/scan-domain.ts must be globbed').toBe(true);
		expect(byRepoPath.has('src/lib/typesafe.ts'), 'the wrapper under test must exist').toBe(true);
		expect(SCAN_ENTRYPOINTS.length, 'scoring entrypoints must be discovered').toBeGreaterThan(1);

		const { reached } = walk(SCAN_ENTRYPOINTS);
		// scan_domain fans out to 19 categories; a walk that reaches only a handful
		// of files means the resolver silently failed and the audit is vacuous.
		expect(reached.size, 'transitive walk must reach a realistic module count').toBeGreaterThan(50);
	});

	it('reaches no TypeSafe import from scan_domain or the scoring engine', () => {
		const { violation } = walk(SCAN_ENTRYPOINTS);
		expect(
			violation,
			violation
				? `TypeSafe became reachable from the scan path. RAIL 1 forbids this — the scan score is deterministic and must not depend on third-party inference. Chain:\n  ${violation.join('\n  → ')}`
				: '',
		).toBeNull();
	});

	it('keeps TypeSafe out of packages/dns-checks entirely', () => {
		// dns-checks is runtime-agnostic and published separately; it must not gain
		// a Cloudflare- or network-bound dependency by any route, reachable or not.
		const offenders = Object.entries(dnsChecksSources)
			.filter(([, source]) => importSpecifiers(source).some((s) => s === FORBIDDEN_MODULE || s.includes(FORBIDDEN_LOCAL)))
			.map(([key]) => repoPath(key));
		expect(offenders, 'packages/dns-checks must not import TypeSafe').toEqual([]);
	});

	it('has a walker that actually detects a forbidden import (negative control)', () => {
		// Guards the audit against rotting into a vacuous pass: if the specifier
		// regex or the resolver breaks, THIS fails first and names the cause.
		const probe = "import { askTypesafe } from '../lib/typesafe';\nimport x from '@typesafe-ai/sdk';\n";
		const specs = importSpecifiers(probe);
		expect(specs).toContain('../lib/typesafe');
		expect(specs).toContain(FORBIDDEN_MODULE);
		expect(specs.some((s) => s.includes(FORBIDDEN_LOCAL))).toBe(true);

		// And the resolver must genuinely traverse a known real edge.
		const scanSource = byRepoPath.get('src/tools/scan-domain.ts')!;
		const resolvedEdges = importSpecifiers(scanSource)
			.map((s) => resolveRelative('src/tools/scan-domain.ts', s))
			.filter((p): p is string => p !== null);
		expect(resolvedEdges.length, 'resolver must resolve real relative imports from scan-domain.ts').toBeGreaterThan(3);
	});
});
