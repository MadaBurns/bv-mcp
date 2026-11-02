import { describe, expect, it } from 'vitest';
import { PER_CHECK_TIMEOUT_MS, SCAN_TIMEOUT_MS } from '../../src/lib/config';
import { resolveScanTimeoutBudget } from '../../src/tools/scan/timeouts';

// SQ-537: scan-domain.ts was split. A timeout constant can be redeclared in ANY module the
// orchestrator now spans, so the redeclaration scan covers the barrel plus the five split modules.
// Matched by glob (not by importing each file) so the census below can prove each module is
// actually present: a `not.toMatch` over a file that no longer exists passes vacuously.
const SPLIT_MODULES = ['check-dispatch.ts', 'scan-types.ts', 'early-results.ts', 'check-retry.ts', 'adaptive-weights.ts'] as const;

const scanSources = import.meta.glob(['../../src/tools/scan-domain.ts', '../../src/tools/scan/*.ts'], {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const SCAN_DOMAIN_KEY = '../../src/tools/scan-domain.ts';
const scanDomainSource = scanSources[SCAN_DOMAIN_KEY];
const COVERED_SOURCES: ReadonlyArray<readonly [string, string]> = [
	[SCAN_DOMAIN_KEY, scanDomainSource],
	...SPLIT_MODULES.map((name) => {
		const key = `../../src/tools/scan/${name}`;
		return [key, scanSources[key]] as const;
	}),
];

describe('scan timeout SSOT audit', () => {
	it('census: scan-domain.ts and all five split modules are present in the scanned glob', () => {
		expect(scanDomainSource, 'scan-domain.ts missing from the glob').toBeTypeOf('string');
		for (const name of SPLIT_MODULES) {
			const key = `../../src/tools/scan/${name}`;
			expect(Object.keys(scanSources), `${key} missing from the glob: a not.toMatch over it would pass vacuously`).toContain(key);
			expect(scanSources[key].length, `${key} is empty`).toBeGreaterThan(0);
		}
		expect(COVERED_SOURCES).toHaveLength(SPLIT_MODULES.length + 1);
	});

	it('keeps scan-domain and its split modules from redeclaring timeout constants', () => {
		for (const [path, source] of COVERED_SOURCES) {
			expect(source, `${path} redeclares SCAN_TIMEOUT_MS`).not.toMatch(/const\s+SCAN_TIMEOUT_MS\s*=/);
			expect(source, `${path} redeclares PER_CHECK_TIMEOUT_MS`).not.toMatch(/const\s+PER_CHECK_TIMEOUT_MS\s*=/);
		}
		// scanDomain itself still resolves its budget from the timeouts module.
		expect(scanDomainSource).toContain("from './scan/timeouts'");
	});

	it('keeps runtime timeout defaults tied to config constants', () => {
		const budget = resolveScanTimeoutBudget();

		expect(budget.scanTimeoutMs).toBe(SCAN_TIMEOUT_MS);
		expect(budget.perCheckTimeoutMs).toBe(PER_CHECK_TIMEOUT_MS);
	});
});
