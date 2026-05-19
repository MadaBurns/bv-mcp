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

		expect(standard.candidates.length).toBeLessThanOrEqual(46);
		expect(deep.candidates.length).toBeGreaterThan(90);
		expect(deep.candidates.some((c) => c.domain === 'example.com')).toBe(false);
	});

	it('deep mode adds conservative enterprise affix seeds with source counts and cap drops', () => {
		const noisyMarkovList = Array.from({ length: 320 }, (_, i) => `candidate-${i}.example.net`);
		const universe = buildBrandCandidateUniverse({
			seedDomain: 'example.com',
			markovCandidates: noisyMarkovList,
			depth: 'deep',
		});

		expect(universe.candidates.length).toBeLessThanOrEqual(250);
		expect(universe.candidates.map((c) => c.domain)).toEqual(expect.arrayContaining([
			'examplecloud.com',
			'exampleid.com',
			'examplepay.com',
			'examplesecure.com',
			'examplesecurity.com',
			'exampleshop.com',
			'examplesupport.com',
		]));
		expect(universe.stats.sources.enterprise_affix).toBeGreaterThan(0);
		expect(universe.stats.dropped.cap).toBeGreaterThan(0);
	});

	it('caps after ranking so active lookalikes cannot crowd out exact brand TLDs', () => {
		const activeLookalikes = Array.from({ length: 220 }, (_, i) => `examp1e-${i}.test`);
		const universe = buildBrandCandidateUniverse({
			seedDomain: 'example.com',
			activeLookalikes,
			depth: 'deep',
		});
		const domains = universe.candidates.map((c) => c.domain);

		expect(domains).toEqual(expect.arrayContaining(['example.net', 'example.org', 'example.ca', 'example.co.uk']));
		expect(domains).not.toContain('examp1e-219.test');
		expect(universe.stats.dropped.cap).toBeGreaterThan(0);
	});

	it('orders retained candidates by probe value, not alphabetically', () => {
		const universe = buildBrandCandidateUniverse({
			seedDomain: 'example.com',
			candidateDomains: ['customer-supplied.example.net'],
			activeLookalikes: ['aaa-lookalike.test'],
			markovCandidates: ['aaa-generated.test'],
			depth: 'standard',
		});

		expect(universe.candidates.slice(0, 5).map((c) => c.domain)).toEqual([
			'customer-supplied.example.net',
			'example.net',
			'example.org',
			'example.co',
			'example.io',
		]);
		const activeIndex = universe.candidates.findIndex((c) => c.domain === 'aaa-lookalike.test');
		const generatedIndex = universe.candidates.findIndex((c) => c.domain === 'aaa-generated.test');
		expect(activeIndex).toBeGreaterThan(0);
		expect(generatedIndex).toBeGreaterThan(activeIndex);
	});
});
