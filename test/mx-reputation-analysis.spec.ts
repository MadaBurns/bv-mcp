// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import {
	analyzePtrRecords,
	analyzeDnsblResults,
	classifyDnsblAnswers,
	reverseIpForDnsbl,
	buildDnsblZones,
	detectSharedMxProvider,
} from '../src/tools/mx-reputation-analysis';

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
				{ zone: 'zen.spamhaus.org', status: 'listed', returnCodes: ['127.0.0.2'] },
				{ zone: 'bl.spamcop.net', status: 'not_listed' },
				{ zone: 'b.barracudacentral.org', status: 'not_listed' },
			]);
			const highFinding = findings.find((f) => f.severity === 'high');
			expect(highFinding).toBeDefined();
			expect(highFinding!.title).toContain('listed on zen.spamhaus.org');
		});

		it('should return multiple high findings when listed on multiple DNSBLs', () => {
			const findings = analyzeDnsblResults('198.51.100.1', [
				{ zone: 'zen.spamhaus.org', status: 'listed', returnCodes: ['127.0.0.2'] },
				{ zone: 'bl.spamcop.net', status: 'listed', returnCodes: ['127.0.0.2'] },
				{ zone: 'b.barracudacentral.org', status: 'not_listed' },
			]);
			const highFindings = findings.filter((f) => f.severity === 'high');
			expect(highFindings).toHaveLength(2);
		});

		it('should return info finding when IP is clean on all DNSBLs', () => {
			const findings = analyzeDnsblResults('198.51.100.1', [
				{ zone: 'zen.spamhaus.org', status: 'not_listed' },
				{ zone: 'bl.spamcop.net', status: 'not_listed' },
				{ zone: 'b.barracudacentral.org', status: 'not_listed' },
			]);
			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('info');
			expect(findings[0].title).toContain('MX reputation clean');
		});

		// Regression suite: the 127.255.255.254 false-positive class. The scanner
		// runs through Workers DoH (a public resolver), so Spamhaus consistently
		// returns 127.255.255.254 ("query refused") for shared MX IPs. Pre-fix this
		// surfaced as a high-severity "listed on zen.spamhaus.org" finding. The
		// captured example is the SMX NZ shared IP 203.84.134.3 from the
		// bayleystaupo.co.nz / westerman.co.nz scans.
		describe('inconclusive results (public-resolver refusal codes)', () => {
			it('emits info-severity inconclusive finding instead of high listed finding for 127.255.255.254', () => {
				const findings = analyzeDnsblResults('203.84.134.3', [
					{ zone: 'zen.spamhaus.org', status: 'inconclusive', returnCodes: ['127.255.255.254'] },
					{ zone: 'bl.spamcop.net', status: 'not_listed' },
					{ zone: 'b.barracudacentral.org', status: 'not_listed' },
				]);
				// No high-severity finding — this is the closed false-positive
				expect(findings.find((f) => f.severity === 'high')).toBeUndefined();
				// Exactly one inconclusive finding for the zen.spamhaus.org refusal
				const inconclusive = findings.find((f) => f.title.includes('inconclusive'));
				expect(inconclusive).toBeDefined();
				expect(inconclusive!.severity).toBe('info');
				expect(inconclusive!.detail).toContain('127.255.255.254');
				expect(inconclusive!.detail).toContain('check.spamhaus.org');
				expect(inconclusive!.metadata?.inconclusive).toBe(true);
			});

			it('omits the "MX reputation clean" summary when any zone is inconclusive', () => {
				const findings = analyzeDnsblResults('203.84.134.3', [
					{ zone: 'zen.spamhaus.org', status: 'inconclusive', returnCodes: ['127.255.255.254'] },
					{ zone: 'bl.spamcop.net', status: 'not_listed' },
					{ zone: 'b.barracudacentral.org', status: 'not_listed' },
				]);
				expect(findings.find((f) => f.title.includes('MX reputation clean'))).toBeUndefined();
			});

			it('still surfaces real listings even when other zones are inconclusive (mixed-state)', () => {
				const findings = analyzeDnsblResults('198.51.100.1', [
					{ zone: 'zen.spamhaus.org', status: 'listed', returnCodes: ['127.0.0.2'] },
					{ zone: 'bl.spamcop.net', status: 'inconclusive', returnCodes: ['127.255.255.254'] },
					{ zone: 'b.barracudacentral.org', status: 'not_listed' },
				]);
				const high = findings.find((f) => f.severity === 'high');
				expect(high).toBeDefined();
				expect(high!.title).toContain('listed on zen.spamhaus.org');
				const inconclusive = findings.find((f) => f.title.includes('inconclusive'));
				expect(inconclusive).toBeDefined();
			});

			it('treats Spamhaus 127.255.255.252 (typo/zone error) as inconclusive too', () => {
				const findings = analyzeDnsblResults('198.51.100.1', [
					{ zone: 'zen.spamhaus.org', status: 'inconclusive', returnCodes: ['127.255.255.252'] },
				]);
				expect(findings.find((f) => f.severity === 'high')).toBeUndefined();
				expect(findings[0].detail).toContain('127.255.255.252');
			});

			it('treats Spamhaus 127.255.255.255 (rate-limit) as inconclusive too', () => {
				const findings = analyzeDnsblResults('198.51.100.1', [
					{ zone: 'zen.spamhaus.org', status: 'inconclusive', returnCodes: ['127.255.255.255'] },
				]);
				expect(findings.find((f) => f.severity === 'high')).toBeUndefined();
				expect(findings[0].detail).toContain('127.255.255.255');
			});
		});
	});

	describe('classifyDnsblAnswers', () => {
		it('returns not_listed for empty answers (NXDOMAIN-like)', () => {
			const { status, returnCodes } = classifyDnsblAnswers([]);
			expect(status).toBe('not_listed');
			expect(returnCodes).toEqual([]);
		});

		// Real Spamhaus listing codes per their published spec
		it.each([
			['127.0.0.2'], // SBL
			['127.0.0.3'], // CSS
			['127.0.0.4'], // XBL
			['127.0.0.5'], // XBL
			['127.0.0.6'], // XBL
			['127.0.0.7'], // XBL
			['127.0.0.9'], // SBL CSS
			['127.0.0.10'], // PBL ISP
			['127.0.0.11'], // PBL Spamhaus
		])('classifies %s as listed (real Spamhaus listing code)', (code) => {
			const { status, returnCodes } = classifyDnsblAnswers([code]);
			expect(status).toBe('listed');
			expect(returnCodes).toEqual([code]);
		});

		// The 127.255.255.X range — Spamhaus operational codes
		it('classifies 127.255.255.254 (public-resolver refusal) as inconclusive', () => {
			const { status, returnCodes } = classifyDnsblAnswers(['127.255.255.254']);
			expect(status).toBe('inconclusive');
			expect(returnCodes).toEqual(['127.255.255.254']);
		});

		it('classifies 127.255.255.252 (zone error) as inconclusive', () => {
			expect(classifyDnsblAnswers(['127.255.255.252']).status).toBe('inconclusive');
		});

		it('classifies 127.255.255.255 (rate-limit) as inconclusive', () => {
			expect(classifyDnsblAnswers(['127.255.255.255']).status).toBe('inconclusive');
		});

		it('classifies anomalous loopback codes (127.0.0.0, 127.0.0.1) as inconclusive', () => {
			expect(classifyDnsblAnswers(['127.0.0.0']).status).toBe('inconclusive');
			expect(classifyDnsblAnswers(['127.0.0.1']).status).toBe('inconclusive');
		});

		it('classifies non-127.x answers as inconclusive (spoofed/anomalous)', () => {
			expect(classifyDnsblAnswers(['8.8.8.8']).status).toBe('inconclusive');
			expect(classifyDnsblAnswers(['192.0.2.1']).status).toBe('inconclusive');
		});

		it('treats a real listing alongside a refusal code as listed (real signal wins)', () => {
			const { status, returnCodes } = classifyDnsblAnswers(['127.0.0.2', '127.255.255.254']);
			expect(status).toBe('listed');
			expect(returnCodes).toEqual(['127.0.0.2', '127.255.255.254']);
		});
	});

	describe('reverseIpForDnsbl', () => {
		it('should correctly reverse IPv4 octets', () => {
			expect(reverseIpForDnsbl('192.0.2.1')).toBe('1.2.0.192');
		});

		it('should handle real-world IPs', () => {
			expect(reverseIpForDnsbl('198.51.100.25')).toBe('25.100.51.198');
		});

		it('should handle loopback', () => {
			expect(reverseIpForDnsbl('127.0.0.1')).toBe('1.0.0.127');
		});
	});

	describe('buildDnsblZones', () => {
		it('NEVER includes Spamhaus ZEN — it is dropped unconditionally', () => {
			const zones = buildDnsblZones();
			expect(zones).not.toContain('zen.spamhaus.org');
			expect(zones).toContain('bl.spamcop.net');
			expect(zones).toContain('b.barracudacentral.org');
			expect(zones).toHaveLength(2);
		});
	});
});

/**
 * Shared-provider rDNS false positive (2026-09-07).
 *
 * `detectSharedMxProvider` was computed at the call site but never passed into
 * `analyzePtrRecords`, so the shared-infrastructure downgrade reached DNSBL findings
 * only. Cloudflare Email Security publishes NO PTR on its inbound MX IPs (measured:
 * 192.0.2.10 / 192.0.2.11 / 192.0.2.12 all NXDOMAIN on reverse lookup, while
 * Google, M365 and Rackspace all answer), so every customer domain on it took
 * 3 x medium = -45 on mx_reputation for infrastructure it does not operate.
 */
describe('analyzePtrRecords — shared-provider rDNS downgrade (FP fix 2026-09-07)', () => {
	it('downgrades missing PTR to info when the MX is shared provider infrastructure', () => {
		const findings = analyzePtrRecords('192.0.2.10', [], [], 'Cloudflare Email Security');
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].title).toContain('No PTR record');
		expect(findings[0].metadata?.sharedProvider).toBe('Cloudflare Email Security');
	});

	it('downgrades an FCrDNS mismatch to info on shared provider infrastructure', () => {
		const findings = analyzePtrRecords('198.51.100.1', ['mail.example.com'], ['198.51.100.99'], 'Microsoft 365');
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
	});

	it('KEEPS medium for dedicated infrastructure — the downgrade must not be blanket', () => {
		// The domain owner normally controls the reverse zone for their own mail server,
		// so this remains actionable and must keep scoring.
		const findings = analyzePtrRecords('198.51.100.1', [], [], null);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('medium');
		expect(findings[0].metadata?.sharedProvider).toBeUndefined();
	});

	it('explains WHY it is informational, so the report is not just silently softer', () => {
		const findings = analyzePtrRecords('192.0.2.10', [], [], 'Cloudflare Email Security');
		expect(findings[0].detail).toContain('Cloudflare Email Security');
		expect(findings[0].detail).toContain('SENDING');
	});
});

describe('detectSharedMxProvider — Cloudflare Email Security (FP fix 2026-09-07)', () => {
	it('recognises the cf-emailsecurity.net inbound MX suffix', () => {
		expect(detectSharedMxProvider('mxa.global.inbound.cf-emailsecurity.net')).toBe('Cloudflare Email Security');
		expect(detectSharedMxProvider('mxb-canary.global.inbound.cf-emailsecurity.net')).toBe('Cloudflare Email Security');
	});

	it('still returns null for genuinely dedicated infrastructure', () => {
		expect(detectSharedMxProvider('mail.example.com')).toBeNull();
	});
});
