// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { analyzePtrRecords, analyzeDnsblResults, reverseIpForDnsbl, buildDnsblZones } from '../src/tools/mx-reputation-analysis';

describe('mx-reputation-analysis', () => {
	describe('analyzePtrRecords', () => {
		it('should return medium finding when no PTR records exist', () => {
			const findings = analyzePtrRecords('198.51.100.1', [], []);
			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('medium');
			expect(findings[0].title).toContain('No PTR record');
			expect(findings[0].title).toContain('198.51.100.1');
		});

		it('should return medium finding when PTR does not match forward DNS (FCrDNS failure)', () => {
			const findings = analyzePtrRecords('198.51.100.1', ['mail.example.com'], ['198.51.100.99']);
			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('medium');
			expect(findings[0].title).toContain('PTR does not match forward DNS');
		});

		it('should return low finding for generic PTR hostname', () => {
			const findings = analyzePtrRecords('198.51.100.1', ['dynamic-198-51-100-1.isp.net'], ['198.51.100.1']);
			const genericFinding = findings.find((f) => f.severity === 'low');
			expect(genericFinding).toBeDefined();
			expect(genericFinding!.title).toBe('MX uses generic PTR hostname');
		});

		it('should return info finding when PTR is valid and matches forward DNS', () => {
			const findings = analyzePtrRecords('198.51.100.1', ['mail.example.com'], ['198.51.100.1']);
			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('info');
			expect(findings[0].title).toContain('Reverse DNS valid');
		});

		it('should handle multiple PTR hostnames', () => {
			const findings = analyzePtrRecords('198.51.100.1', ['mail.example.com', 'mx.example.com'], ['198.51.100.1']);
			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('info');
		});

		it('should detect residential PTR patterns', () => {
			const patterns = ['cable-198-51-100-1.isp.net', 'dhcp-pool.example.net', 'broadband-user.example.net'];
			for (const hostname of patterns) {
				const findings = analyzePtrRecords('198.51.100.1', [hostname], ['198.51.100.1']);
				const generic = findings.find((f) => f.title === 'MX uses generic PTR hostname');
				expect(generic, `Expected generic finding for ${hostname}`).toBeDefined();
			}
		});

		it('should not flag professional PTR hostnames as generic', () => {
			const findings = analyzePtrRecords('198.51.100.1', ['mail.example.com'], ['198.51.100.1']);
			const generic = findings.find((f) => f.title === 'MX uses generic PTR hostname');
			expect(generic).toBeUndefined();
		});
	});

	describe('analyzeDnsblResults', () => {
		it('should return high finding when IP is listed on a DNSBL', () => {
			const findings = analyzeDnsblResults('198.51.100.1', [
				{ zone: 'zen.spamhaus.org', listed: true },
				{ zone: 'bl.spamcop.net', listed: false },
				{ zone: 'b.barracudacentral.org', listed: false },
			]);
			const highFinding = findings.find((f) => f.severity === 'high');
			expect(highFinding).toBeDefined();
			expect(highFinding!.title).toContain('listed on zen.spamhaus.org');
		});

		it('should return multiple high findings when listed on multiple DNSBLs', () => {
			const findings = analyzeDnsblResults('198.51.100.1', [
				{ zone: 'zen.spamhaus.org', listed: true },
				{ zone: 'bl.spamcop.net', listed: true },
				{ zone: 'b.barracudacentral.org', listed: false },
			]);
			const highFindings = findings.filter((f) => f.severity === 'high');
			expect(highFindings).toHaveLength(2);
		});

		it('should return info finding when IP is clean on all DNSBLs', () => {
			const findings = analyzeDnsblResults('198.51.100.1', [
				{ zone: 'zen.spamhaus.org', listed: false },
				{ zone: 'bl.spamcop.net', listed: false },
				{ zone: 'b.barracudacentral.org', listed: false },
			]);
			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('info');
			expect(findings[0].title).toContain('MX reputation clean');
		});
	});

	describe('reverseIpForDnsbl', () => {
		it('should correctly reverse IPv4 octets', () => {
			expect(reverseIpForDnsbl('1.2.3.4')).toBe('4.3.2.1');
		});

		it('should handle real-world IPs', () => {
			expect(reverseIpForDnsbl('198.51.100.25')).toBe('25.100.51.198');
		});

		it('should handle loopback', () => {
			expect(reverseIpForDnsbl('127.0.0.1')).toBe('1.0.0.127');
		});
	});

	describe('buildDnsblZones', () => {
		it('should return the expected DNSBL zones', () => {
			const zones = buildDnsblZones();
			expect(zones).toContain('zen.spamhaus.org');
			expect(zones).toContain('bl.spamcop.net');
			expect(zones).toContain('b.barracudacentral.org');
			expect(zones).toHaveLength(3);
		});
	});
});
