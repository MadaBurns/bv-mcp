import { describe, expect, it } from 'vitest';

import {
	getNameserverDiversityFinding,
	getNsConfiguredFinding,
	getNsVisibilityFinding,
	getSingleNsFinding,
	getSoaValidationFindings,
	normalizeNsRecords,
	parseSoaValues,
} from '../src/tools/ns-analysis';

describe('ns-analysis', () => {
	it('normalizes nameserver records', () => {
		expect(normalizeNsRecords(['NS1.EXAMPLE.COM.', 'ns2.example.net.'])).toEqual(['ns1.example.com', 'ns2.example.net']);
	});

	it('builds visibility findings for missing NS records', () => {
		expect(getNsVisibilityFinding('example.com', true).severity).toBe('low');
		expect(getNsVisibilityFinding('example.com', false).severity).toBe('critical');
	});

	it('builds single nameserver and configured findings', () => {
		expect(getSingleNsFinding(['ns1.example.com'])?.severity).toBe('high');
		expect(getSingleNsFinding(['ns1.example.com', 'ns2.example.com'])).toBeNull();
		expect(getNsConfiguredFinding(['ns1.example.com', 'ns2.example.net']).detail).toContain('2 nameservers');
	});

	it('detects low nameserver diversity for same-provider hosts', () => {
		expect(getNameserverDiversityFinding(['ns1.cloudflare.com', 'ns2.cloudflare.com'])?.detail).toContain('cloudflare.com');
		expect(getNameserverDiversityFinding(['ns1.a.com', 'ns2.b.net'])).toBeNull();
	});

	it('parses SOA values and emits validation findings', () => {
		const soaValues = parseSoaValues('ns1.example.com. admin.example.com. 2024010101 100 200 300 90000');
		expect(soaValues).toEqual({ refresh: 100, retry: 200, expire: 300, minimum: 90000 });
		const findings = getSoaValidationFindings(soaValues!);
		expect(findings.map((finding) => finding.title)).toEqual([
			'SOA refresh interval too short',
			'SOA retry exceeds refresh interval',
			'SOA expire too short',
			'SOA negative cache TTL too long',
		]);
	});

	it('returns null for malformed SOA strings', () => {
		expect(parseSoaValues('bad data')).toBeNull();
	});
});