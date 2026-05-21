// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { aggregateRegistrarPortfolio } from '../src/lib/registrar-portfolio';
import type { DiscoveryReportCandidate } from './helpers/discovery-report-model';

function candidate(domain: string, registrar: string, registrarSource = 'rdap'): DiscoveryReportCandidate {
	return {
		domain,
		bucket: 'consolidated',
		relationshipType: 'consolidated',
		evidence: 'test',
		registrar,
		registrarSource,
		signals: [],
		combinedConfidence: 0.9,
		reasons: [],
	};
}

describe('aggregateRegistrarPortfolio', () => {
	it('groups candidates by classified family', () => {
		const candidates = [
			candidate('brand-beta.com.au', 'CSC Corporate Domains, Inc.'),
			candidate('ford.de', 'CSC Global'),
			candidate('fordcorp.com', 'GoDaddy.com, LLC'),
		];
		const result = aggregateRegistrarPortfolio(candidates, {
			apex: 'brand-beta.com',
			registrar: 'CSC Corporate Domains, Inc.',
			registrarSource: 'rdap',
		});

		expect(result.totalApexes).toBe(4); // anchor + 3 candidates
		const csc = result.byFamily.find((f) => f.family === 'csc corporate domains');
		expect(csc?.count).toBe(3); // anchor + brand-beta.com.au + ford.de
		expect(csc?.exampleApexes).toContain('brand-beta.com');

		const godaddy = result.byFamily.find((f) => f.family === 'godaddy');
		expect(godaddy?.count).toBe(1);
		expect(result.offPortfolioCount).toBe(1);
		expect(result.offPortfolioApexes).toEqual(['fordcorp.com']);
	});

	it('buckets unclassified candidates as unknown', () => {
		const candidates = [candidate('mystery.com', 'Some Tiny Registrar')];
		const result = aggregateRegistrarPortfolio(candidates, {
			apex: 'anchor.com',
			registrar: 'MarkMonitor Inc.',
			registrarSource: 'rdap',
		});
		const unknown = result.byFamily.find((f) => f.family === 'unknown');
		expect(unknown?.count).toBe(1);
	});

	it('treats lookup_failed and "unknown" registrarSource as unknown family', () => {
		const candidates = [
			candidate('a.com', 'GoDaddy.com, LLC', 'lookup_failed'),
			candidate('b.com', 'GoDaddy.com, LLC', 'unknown'),
		];
		const result = aggregateRegistrarPortfolio(candidates, {
			apex: 'anchor.com',
			registrar: 'MarkMonitor Inc.',
			registrarSource: 'rdap',
		});
		const unknown = result.byFamily.find((f) => f.family === 'unknown');
		expect(unknown?.count).toBe(2); // both shoved into unknown because source unreliable
	});

	it('sorts byFamily descending by count', () => {
		const candidates = [
			candidate('a.com', 'GoDaddy.com, LLC'),
			candidate('b.com', 'GoDaddy.com, LLC'),
			candidate('c.com', 'CSC Corporate Domains'),
		];
		const result = aggregateRegistrarPortfolio(candidates, {
			apex: 'anchor.com',
			registrar: 'MarkMonitor Inc.',
			registrarSource: 'rdap',
		});
		expect(result.byFamily[0].family).toBe('godaddy');
		expect(result.byFamily[0].count).toBe(2);
	});

	it('caps exampleApexes at 5', () => {
		const candidates = Array.from({ length: 10 }, (_, i) => candidate(`a${i}.com`, 'GoDaddy.com, LLC'));
		const result = aggregateRegistrarPortfolio(candidates, {
			apex: 'anchor.com',
			registrar: 'MarkMonitor Inc.',
			registrarSource: 'rdap',
		});
		const godaddy = result.byFamily.find((f) => f.family === 'godaddy');
		expect(godaddy?.exampleApexes.length).toBeLessThanOrEqual(5);
	});

	it('handles empty candidate list', () => {
		const result = aggregateRegistrarPortfolio([], {
			apex: 'anchor.com',
			registrar: 'MarkMonitor Inc.',
			registrarSource: 'rdap',
		});
		expect(result.totalApexes).toBe(1);
		expect(result.offPortfolioCount).toBe(0);
		expect(result.byFamily.length).toBe(1); // anchor's family only
	});
});
