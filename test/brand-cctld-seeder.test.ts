// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for ccTLD candidate seeding.
 *
 * Defect: discovery returned 0 candidates for amazon.com / microsoft.com /
 * brand-zeta.example.com because the Markov generator only varies the BASE and keeps the
 * seed TLD, so the NS-correlator candidate list never includes ccTLD variants
 * the brand actually owns (amazon.de, amazon.co.uk, …). The seeder fills
 * that gap with a deterministic, brand-agnostic allowlist of common ccTLDs.
 *
 * Pure helper; no mocks.
 */

import { describe, it, expect } from 'vitest';
import { generateCctldVariants } from '../src/lib/brand-cctld-seeder';

describe('generateCctldVariants', () => {
	it('emits <base>.<ccTLD> for a representative ccTLD set', () => {
		const out = generateCctldVariants('amazon.com');
		expect(out).toContain('amazon.de');
		expect(out).toContain('amazon.fr');
		expect(out).toContain('amazon.co.uk');
		expect(out).toContain('amazon.co.jp');
		expect(out).toContain('amazon.com.au');
	});

	it('does NOT emit the seed itself', () => {
		expect(generateCctldVariants('amazon.com')).not.toContain('amazon.com');
		expect(generateCctldVariants('microsoft.com')).not.toContain('microsoft.com');
	});

	it('works for brands on any seed TLD (gTLD or ccTLD)', () => {
		// seed itself is a ccTLD — variants still emit
		const out = generateCctldVariants('example.co.uk');
		expect(out).toContain('example.com');
		expect(out).toContain('example.de');
		expect(out).not.toContain('example.co.uk');
	});

	it('returns at least 20 variants per seed (enough breadth for big-brand coverage)', () => {
		expect(generateCctldVariants('amazon.com').length).toBeGreaterThanOrEqual(20);
		expect(generateCctldVariants('microsoft.com').length).toBeGreaterThanOrEqual(20);
		expect(generateCctldVariants('brand-zeta.example.com').length).toBeGreaterThanOrEqual(20);
	});

	it('returns deduplicated, lowercase, dot-trimmed strings', () => {
		const out = generateCctldVariants('AMAZON.com.');
		const lower = out.every((d) => d === d.toLowerCase());
		const noTrailing = out.every((d) => !d.endsWith('.'));
		const dedup = new Set(out).size === out.length;
		expect(lower).toBe(true);
		expect(noTrailing).toBe(true);
		expect(dedup).toBe(true);
	});

	it('returns empty array for invalid / unparseable input', () => {
		expect(generateCctldVariants('')).toEqual([]);
		expect(generateCctldVariants('not-a-domain')).toEqual([]);
		expect(generateCctldVariants('.com')).toEqual([]);
	});

	it('deterministic: same input → identical output', () => {
		const a = generateCctldVariants('amazon.com');
		const b = generateCctldVariants('amazon.com');
		expect(a).toEqual(b);
	});
});
