// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it } from 'vitest';
import type { LookalikeResult } from '../src/tools/lookalike-dns';
import type { LookalikeCorroborators } from '../src/tools/lookalike-enrichment';

function candidate(domain: string): LookalikeResult {
	return { domain, hasA: true, hasMX: true, mxExchanges: ['mx.example.test'], probeDegraded: false };
}

function corroborators(webPresence: LookalikeCorroborators['webPresence']): LookalikeCorroborators {
	return {
		registrationDays: 1000,
		ageUnknown: false,
		registrationLookup: 'ok',
		mxOnDisposable: false,
		hasWebContent: true,
		webPresence,
		parkingSignals: webPresence === 'parked' ? ['parking_ns'] : [],
		wildcardProbe: 'not_probed',
		registrantOrg: null,
		registrarIanaId: null,
		registrarName: null,
	};
}

describe('#1206 attribution consumes the measured web reading', () => {
	it('prioritises a parked mail-capable candidate when the RDAP correlation cap binds', async () => {
		const { computeSameEntityCandidates } = await import('../src/tools/lookalike-attribution');
		const content = Array.from({ length: 10 }, (_, i) => candidate(`content${i}.example.test`));
		const parked = candidate('parked.example.test');
		const results = [...content, parked];
		const enrichment = new Map(results.map((r) => [r.domain, corroborators(r === parked ? 'parked' : 'content')]));
		const ranked = computeSameEntityCandidates(results, new Map(), enrichment);
		expect(ranked).toHaveLength(10);
		expect(ranked[0]).toBe(parked.domain);
		expect(ranked).not.toContain(content[9].domain);
		// The same boolean without parking evidence must retain the stable content order.
		enrichment.set(parked.domain, corroborators('unmeasured'));
		expect(computeSameEntityCandidates(results, new Map(), enrichment)).toEqual(content.map((r) => r.domain));
	});

	it('a refused HEAD does not assert web presence; an answered content probe still does', async () => {
		const { buildOwnedBySeedFinding } = await import('../src/tools/lookalike-findings');
		const ownership = { verdict: 'owned_by_seed' as const, strength: 'strong' as const, signals: [], rationale: 'Matched seed NS set' };
		const build = (webPresence: LookalikeCorroborators['webPresence']) =>
			buildOwnedBySeedFinding(candidate('candidate.example.test'), 'seed.example.test', ownership, { webPresence });
		expect(build('none').detail).toContain('probe refused');
		expect(build('none').detail).not.toMatch(/has web presence/i);
		expect(build('unmeasured').detail).toContain('Web presence unmeasured');
		expect(build('content').detail).toContain('Has web presence.');
	});
});
