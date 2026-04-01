// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { analyzeSrvResults, SRV_PREFIXES } from '../src/tools/srv-analysis';
import type { SrvProbeResult } from '../src/tools/srv-analysis';

describe('analyzeSrvResults', () => {
	it('should return info finding when no services found', () => {
		const results: SrvProbeResult[] = SRV_PREFIXES.map((prefix) => ({ prefix, records: [] }));
		const findings = analyzeSrvResults(results);

		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].title).toBe('No SRV service records found');
	});

	it('should return info finding for a single discovered service', () => {
		const results: SrvProbeResult[] = [
			{ prefix: '_imaps._tcp', records: [{ priority: 10, weight: 0, port: 993, target: 'mail.example.com' }] },
			{ prefix: '_imap._tcp', records: [] },
		];
		const findings = analyzeSrvResults(results);

		const discovered = findings.filter((f) => f.title.startsWith('SRV service discovered'));
		expect(discovered).toHaveLength(1);
		expect(discovered[0].metadata?.port).toBe(993);
		expect(discovered[0].metadata?.target).toBe('mail.example.com');
	});

	it('should flag plain-text IMAP without IMAPS as medium', () => {
		const results: SrvProbeResult[] = [
			{ prefix: '_imap._tcp', records: [{ priority: 10, weight: 0, port: 143, target: 'mail.example.com' }] },
		];
		const findings = analyzeSrvResults(results);

		const medium = findings.filter((f) => f.severity === 'medium');
		expect(medium).toHaveLength(1);
		expect(medium[0].title).toContain('Plain-text IMAP');
	});

	it('should flag plain-text POP3 without POP3S as medium', () => {
		const results: SrvProbeResult[] = [
			{ prefix: '_pop3._tcp', records: [{ priority: 10, weight: 0, port: 110, target: 'mail.example.com' }] },
		];
		const findings = analyzeSrvResults(results);

		const medium = findings.filter((f) => f.severity === 'medium');
		expect(medium).toHaveLength(1);
		expect(medium[0].title).toContain('Plain-text POP3');
	});

	it('should NOT flag IMAP when IMAPS is also present', () => {
		const results: SrvProbeResult[] = [
			{ prefix: '_imap._tcp', records: [{ priority: 10, weight: 0, port: 143, target: 'mail.example.com' }] },
			{ prefix: '_imaps._tcp', records: [{ priority: 10, weight: 0, port: 993, target: 'mail.example.com' }] },
		];
		const findings = analyzeSrvResults(results);

		const medium = findings.filter((f) => f.severity === 'medium');
		expect(medium).toHaveLength(0);
	});

	it('should NOT flag POP3 when POP3S is also present', () => {
		const results: SrvProbeResult[] = [
			{ prefix: '_pop3._tcp', records: [{ priority: 10, weight: 0, port: 110, target: 'mail.example.com' }] },
			{ prefix: '_pop3s._tcp', records: [{ priority: 10, weight: 0, port: 995, target: 'mail.example.com' }] },
		];
		const findings = analyzeSrvResults(results);

		const medium = findings.filter((f) => f.severity === 'medium');
		expect(medium).toHaveLength(0);
	});

	it('should flag autodiscover exposure as low', () => {
		const results: SrvProbeResult[] = [
			{ prefix: '_autodiscover._tcp', records: [{ priority: 10, weight: 0, port: 443, target: 'autodiscover.example.com' }] },
		];
		const findings = analyzeSrvResults(results);

		const low = findings.filter((f) => f.severity === 'low');
		expect(low).toHaveLength(1);
		expect(low[0].title).toContain('Autodiscover SRV record exposed');
	});

	it('should report SIP/XMPP services as info', () => {
		const results: SrvProbeResult[] = [
			{ prefix: '_sip._tcp', records: [{ priority: 10, weight: 0, port: 5060, target: 'sip.example.com' }] },
			{ prefix: '_xmpp-client._tcp', records: [{ priority: 10, weight: 0, port: 5222, target: 'xmpp.example.com' }] },
		];
		const findings = analyzeSrvResults(results);

		const comm = findings.find((f) => f.title === 'SIP/XMPP services publicly advertised');
		expect(comm).toBeDefined();
		expect(comm!.severity).toBe('info');
	});

	it('should include summary finding with correct service count', () => {
		const results: SrvProbeResult[] = [
			{ prefix: '_imaps._tcp', records: [{ priority: 10, weight: 0, port: 993, target: 'mail.example.com' }] },
			{ prefix: '_caldavs._tcp', records: [{ priority: 10, weight: 0, port: 443, target: 'cal.example.com' }] },
			{ prefix: '_https._tcp', records: [{ priority: 10, weight: 0, port: 443, target: 'www.example.com' }] },
		];
		const findings = analyzeSrvResults(results);

		const summary = findings.find((f) => f.title.includes('Service footprint'));
		expect(summary).toBeDefined();
		expect(summary!.title).toContain('3 services');
		expect(summary!.metadata?.serviceCount).toBe(3);
		expect(summary!.metadata?.prefixes).toEqual(['_imaps._tcp', '_caldavs._tcp', '_https._tcp']);
	});

	it('should include correct metadata on discovered service findings', () => {
		const results: SrvProbeResult[] = [
			{ prefix: '_submission._tcp', records: [{ priority: 5, weight: 10, port: 587, target: 'smtp.example.com' }] },
		];
		const findings = analyzeSrvResults(results);

		const discovered = findings.find((f) => f.title.startsWith('SRV service discovered'));
		expect(discovered).toBeDefined();
		expect(discovered!.metadata?.prefix).toBe('_submission._tcp');
		expect(discovered!.metadata?.port).toBe(587);
		expect(discovered!.metadata?.target).toBe('smtp.example.com');
	});

	it('should flag both IMAP and POP3 insecure when both present without encrypted variants', () => {
		const results: SrvProbeResult[] = [
			{ prefix: '_imap._tcp', records: [{ priority: 10, weight: 0, port: 143, target: 'mail.example.com' }] },
			{ prefix: '_pop3._tcp', records: [{ priority: 10, weight: 0, port: 110, target: 'mail.example.com' }] },
		];
		const findings = analyzeSrvResults(results);

		const medium = findings.filter((f) => f.severity === 'medium');
		expect(medium).toHaveLength(2);
		expect(medium.some((f) => f.title.includes('IMAP'))).toBe(true);
		expect(medium.some((f) => f.title.includes('POP3'))).toBe(true);
	});

	it('should handle mixed secure and insecure services correctly', () => {
		const results: SrvProbeResult[] = [
			{ prefix: '_imap._tcp', records: [{ priority: 10, weight: 0, port: 143, target: 'mail.example.com' }] },
			{ prefix: '_imaps._tcp', records: [{ priority: 10, weight: 0, port: 993, target: 'mail.example.com' }] },
			{ prefix: '_pop3._tcp', records: [{ priority: 10, weight: 0, port: 110, target: 'mail.example.com' }] },
			// No _pop3s._tcp — POP3 should be flagged but IMAP should not
		];
		const findings = analyzeSrvResults(results);

		const medium = findings.filter((f) => f.severity === 'medium');
		expect(medium).toHaveLength(1);
		expect(medium[0].title).toContain('POP3');
	});
});
