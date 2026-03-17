// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { parseSoaRecord, analyzeSoaConsistency, analyzeSensitiveSubdomains } from '../src/tools/zone-hygiene-analysis';
import type { NsSerialEntry, SubdomainProbeResult } from '../src/tools/zone-hygiene-analysis';

describe('parseSoaRecord', () => {
	it('should parse a valid SOA record', () => {
		const result = parseSoaRecord('ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 300');
		expect(result).not.toBeNull();
		expect(result!.primaryNs).toBe('ns1.example.com');
		expect(result!.adminEmail).toBe('admin.example.com');
		expect(result!.serial).toBe(2024010101);
		expect(result!.refresh).toBe(7200);
		expect(result!.retry).toBe(3600);
		expect(result!.expire).toBe(1209600);
		expect(result!.minimum).toBe(300);
	});

	it('should strip trailing dots from NS and admin email', () => {
		const result = parseSoaRecord('ns1.example.com. hostmaster.example.com. 100 3600 900 604800 86400');
		expect(result).not.toBeNull();
		expect(result!.primaryNs).toBe('ns1.example.com');
		expect(result!.adminEmail).toBe('hostmaster.example.com');
	});

	it('should return null for invalid SOA with too few fields', () => {
		expect(parseSoaRecord('ns1.example.com. admin.example.com.')).toBeNull();
	});

	it('should return null for empty string', () => {
		expect(parseSoaRecord('')).toBeNull();
	});

	it('should return null for null/undefined input', () => {
		expect(parseSoaRecord(null as unknown as string)).toBeNull();
		expect(parseSoaRecord(undefined as unknown as string)).toBeNull();
	});

	it('should return null when numeric fields are not valid numbers', () => {
		expect(parseSoaRecord('ns1.example.com. admin.example.com. abc 7200 3600 1209600 300')).toBeNull();
	});

	it('should return null when numeric fields are negative', () => {
		expect(parseSoaRecord('ns1.example.com. admin.example.com. -1 7200 3600 1209600 300')).toBeNull();
	});
});

describe('analyzeSoaConsistency', () => {
	it('should return info finding when all serials match', () => {
		const nsSerials: NsSerialEntry[] = [
			{ ns: 'ns1.example.com', serial: 2024010101 },
			{ ns: 'ns2.example.com', serial: 2024010101 },
		];

		const findings = analyzeSoaConsistency(nsSerials);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].title).toBe('SOA serial numbers consistent across all nameservers');
	});

	it('should return high finding when serials differ', () => {
		const nsSerials: NsSerialEntry[] = [
			{ ns: 'ns1.example.com', serial: 2024010101 },
			{ ns: 'ns2.example.com', serial: 2024010100 },
		];

		const findings = analyzeSoaConsistency(nsSerials);
		const mismatch = findings.find((f) => f.title === 'NS SOA serial mismatch (stale zone)');
		expect(mismatch).toBeDefined();
		expect(mismatch!.severity).toBe('high');
		expect(mismatch!.metadata?.serials).toBeDefined();
	});

	it('should return info finding when fewer than 2 NS responded', () => {
		const nsSerials: NsSerialEntry[] = [{ ns: 'ns1.example.com', serial: 2024010101 }];

		const findings = analyzeSoaConsistency(nsSerials);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].title).toBe('Insufficient NS responses for SOA comparison');
	});

	it('should return info finding when no NS responded', () => {
		const nsSerials: NsSerialEntry[] = [
			{ ns: 'ns1.example.com', serial: null },
			{ ns: 'ns2.example.com', serial: null },
		];

		const findings = analyzeSoaConsistency(nsSerials);
		expect(findings).toHaveLength(1);
		expect(findings[0].title).toBe('Insufficient NS responses for SOA comparison');
	});

	it('should return medium finding when some NS failed to respond', () => {
		const nsSerials: NsSerialEntry[] = [
			{ ns: 'ns1.example.com', serial: 2024010101 },
			{ ns: 'ns2.example.com', serial: 2024010101 },
			{ ns: 'ns3.example.com', serial: null },
		];

		const findings = analyzeSoaConsistency(nsSerials);
		const drift = findings.find((f) => f.title === 'NS configuration drift');
		expect(drift).toBeDefined();
		expect(drift!.severity).toBe('medium');
		expect(drift!.detail).toContain('ns3.example.com');
	});
});

describe('analyzeSensitiveSubdomains', () => {
	it('should return info finding when no subdomains resolve', () => {
		const results: SubdomainProbeResult[] = [
			{ subdomain: 'vpn.example.com', resolves: false, ips: [] },
			{ subdomain: 'admin.example.com', resolves: false, ips: [] },
		];

		const findings = analyzeSensitiveSubdomains(results);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].title).toBe('No sensitive subdomains resolve publicly');
	});

	it('should return medium finding when one subdomain resolves', () => {
		const results: SubdomainProbeResult[] = [
			{ subdomain: 'vpn.example.com', resolves: true, ips: ['203.0.113.10'] },
			{ subdomain: 'admin.example.com', resolves: false, ips: [] },
		];

		const findings = analyzeSensitiveSubdomains(results);
		const found = findings.find((f) => f.title.includes('vpn.example.com'));
		expect(found).toBeDefined();
		expect(found!.severity).toBe('medium');
		expect(found!.metadata?.subdomain).toBe('vpn.example.com');
		expect(found!.metadata?.ips).toEqual(['203.0.113.10']);
	});

	it('should return additional medium finding when 3+ subdomains resolve', () => {
		const results: SubdomainProbeResult[] = [
			{ subdomain: 'vpn.example.com', resolves: true, ips: ['203.0.113.10'] },
			{ subdomain: 'admin.example.com', resolves: true, ips: ['203.0.113.11'] },
			{ subdomain: 'staging.example.com', resolves: true, ips: ['203.0.113.12'] },
		];

		const findings = analyzeSensitiveSubdomains(results);
		const excessive = findings.find((f) => f.title.includes('Excessive internal subdomain exposure'));
		expect(excessive).toBeDefined();
		expect(excessive!.severity).toBe('medium');
		expect(excessive!.title).toContain('3 found');
	});

	it('should include IPs in metadata for resolving subdomains', () => {
		const results: SubdomainProbeResult[] = [
			{ subdomain: 'dev.example.com', resolves: true, ips: ['198.51.100.1', '198.51.100.2'] },
		];

		const findings = analyzeSensitiveSubdomains(results);
		const found = findings.find((f) => f.title.includes('dev.example.com'));
		expect(found).toBeDefined();
		expect(found!.metadata?.ips).toEqual(['198.51.100.1', '198.51.100.2']);
	});

	it('should not produce excessive exposure finding for exactly 2 resolving subdomains', () => {
		const results: SubdomainProbeResult[] = [
			{ subdomain: 'vpn.example.com', resolves: true, ips: ['203.0.113.10'] },
			{ subdomain: 'admin.example.com', resolves: true, ips: ['203.0.113.11'] },
		];

		const findings = analyzeSensitiveSubdomains(results);
		const excessive = findings.find((f) => f.title.includes('Excessive'));
		expect(excessive).toBeUndefined();
	});
});
