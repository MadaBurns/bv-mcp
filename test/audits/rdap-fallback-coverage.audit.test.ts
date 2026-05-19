// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 6 of registrar-coverage-tdd-plan.md — audit pinning RDAP fallback coverage.
 *
 * The hardcoded FALLBACK_RDAP_SERVERS map in `src/tools/check-rdap-lookup.ts`
 * is the cold-start safety net when the IANA bootstrap fetch fails. This audit
 * enforces that the map covers every TLD in
 * `test/audits/data/rdap-fallback-required-tlds.txt`, so drift in either file
 * fails CI and forces both to be updated together.
 *
 * Per testing methodology principle 4: audit tests replace review checklists.
 */

import { describe, it, expect } from 'vitest';
import { FALLBACK_RDAP_SERVERS } from '../../src/tools/check-rdap-lookup';

const tldList = import.meta.glob('./data/rdap-fallback-required-tlds.txt', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

function parseRequiredTlds(raw: string): string[] {
	return raw
		.split('\n')
		.map((line) => line.replace(/#.*$/, '').trim())
		.filter((line) => line.length > 0)
		.map((tld) => tld.toLowerCase());
}

describe('rdap-fallback-coverage (audit)', () => {
	it('every TLD in the required-tlds snapshot has a FALLBACK_RDAP_SERVERS entry', () => {
		const [, raw] = Object.entries(tldList)[0];
		const required = parseRequiredTlds(raw);
		expect(required.length, 'required-tlds snapshot must not be empty').toBeGreaterThan(0);

		const missing: string[] = [];
		for (const tld of required) {
			const url = FALLBACK_RDAP_SERVERS[tld];
			if (typeof url !== 'string' || !/^https:\/\//.test(url)) {
				missing.push(tld);
			}
		}
		expect(
			missing,
			`FALLBACK_RDAP_SERVERS missing required TLDs: ${missing.join(', ')}. ` +
				`Add the entry to src/tools/check-rdap-lookup.ts (with the canonical IANA RDAP URL) ` +
				`or, if intentionally dropping coverage, remove the TLD from test/audits/data/rdap-fallback-required-tlds.txt.`,
		).toEqual([]);
	});

	it('every FALLBACK_RDAP_SERVERS entry has a URL with https:// scheme', () => {
		const violations: Array<{ tld: string; url: string }> = [];
		for (const [tld, url] of Object.entries(FALLBACK_RDAP_SERVERS)) {
			if (!/^https:\/\//.test(url)) violations.push({ tld, url });
		}
		expect(violations, 'all fallback URLs must be https://').toEqual([]);
	});
});
