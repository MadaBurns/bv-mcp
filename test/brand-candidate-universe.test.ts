// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { buildBrandCandidateUniverse } from '../src/lib/brand-candidate-universe';

describe('buildBrandCandidateUniverse', () => {
	it('emits deterministic brand and alias TLD sweeps with provenance', () => {
		const universe = buildBrandCandidateUniverse({
			seedDomain: 'example.com',
			brandAliases: ['examplecorp'],
			candidateDomains: ['portal.example.net'],
			depth: 'standard',
		});

		expect(universe.candidates.map((c) => c.domain)).toContain('example.net');
		expect(universe.candidates.map((c) => c.domain)).toContain('example.org');
		expect(universe.candidates.map((c) => c.domain)).toContain('examplecorp.com');
		expect(universe.candidates.map((c) => c.domain)).toContain('portal.example.net');

		const alias = universe.candidates.find((c) => c.domain === 'examplecorp.com');
		expect(alias?.sources).toContain('alias_tld_sweep');

		const explicit = universe.candidates.find((c) => c.domain === 'portal.example.net');
		expect(explicit?.sources).toContain('caller_candidate');
		expect(universe.stats.seeded).toBe(universe.candidates.length);
		expect(universe.stats.sources.alias_tld_sweep).toBeGreaterThan(0);
	});

	it('deep mode produces more candidates than standard mode without changing the seed itself', () => {
		const standard = buildBrandCandidateUniverse({ seedDomain: 'example.com', depth: 'standard' });
		const deep = buildBrandCandidateUniverse({ seedDomain: 'example.com', depth: 'deep' });

		expect(deep.candidates.length).toBeGreaterThan(standard.candidates.length);
		expect(deep.candidates.some((c) => c.domain === 'example.com')).toBe(false);
	});
});
