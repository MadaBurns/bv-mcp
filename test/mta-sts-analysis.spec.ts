import { describe, expect, it } from 'vitest';

import {
	finalizeMissingMtaStsRecordFinding,
	finalizeMissingTlsRptRecordFinding,
	extractPolicyMxPatterns,
	getMtaStsPolicyFindings,
	getMtaStsTxtFindings,
	getTlsRptRecordFindings,
	getUncoveredMxHostFindings,
	matchesMxPattern,
	shouldSummarizeMissingMailProtections,
} from '../src/tools/mta-sts-analysis';
import { createFinding } from '../src/lib/scoring';

describe('mta-sts-analysis', () => {
	it('parses TXT records and flags missing id tag', () => {
		const analysis = getMtaStsTxtFindings(['v=STSv1; bogus=value']);
		expect(analysis.hasTxtRecord).toBe(true);
		expect(analysis.findings.find((finding) => finding.title.includes('missing id'))?.severity).toBe('medium');
	});

	it('represents missing TXT records before domain-specific detail is applied', () => {
		const analysis = getMtaStsTxtFindings([]);
		const finalized = finalizeMissingMtaStsRecordFinding(analysis.findings, 'example.com');
		expect(analysis.hasTxtRecord).toBe(false);
		expect(finalized[0].detail).toContain('_mta-sts.example.com');
	});

	it('evaluates policy mode and mx directives', () => {
		const findings = getMtaStsPolicyFindings('version: STSv1\nmode: testing\nmax_age: 86400', 'https://mta-sts.example.com/.well-known/mta-sts.txt');
		expect(findings.find((finding) => finding.title.includes('testing mode'))?.severity).toBe('low');
		expect(findings.find((finding) => finding.title.includes('missing MX'))?.detail).toContain('https://mta-sts.example.com/.well-known/mta-sts.txt');
	});

	it('evaluates RFC-required MTA-STS policy directives', () => {
		const findings = getMtaStsPolicyFindings('mode: enforce\nmx: mail.example.com\nmax_age: 3600', 'https://mta-sts.example.com/.well-known/mta-sts.txt');
		expect(findings.find((finding) => finding.title.includes('missing or invalid version'))?.severity).toBe('high');
		expect(findings.find((finding) => finding.title.includes('max_age too short'))?.severity).toBe('low');
	});

	it('matches exact and wildcard mx patterns', () => {
		expect(extractPolicyMxPatterns('mx: *.example.com\nmx: mail.example.net')).toEqual(['*.example.com', 'mail.example.net']);
		expect(matchesMxPattern('mail1.example.com', '*.example.com')).toBe(true);
		expect(matchesMxPattern('example.com', '*.example.com')).toBe(true);
		expect(matchesMxPattern('mail.example.net', 'mail.example.net')).toBe(true);
		expect(matchesMxPattern('mail.other.com', '*.example.com')).toBe(false);
	});

	it('finds uncovered mx hosts', () => {
		const findings = getUncoveredMxHostFindings(['mail1.example.com', 'mail2.other.com'], ['mail1.example.com']);
		expect(findings).toHaveLength(1);
		expect(findings[0].title).toContain('mail2.other.com');
	});

	it('validates TLS-RPT records and missing rua details', () => {
		expect(finalizeMissingTlsRptRecordFinding(getTlsRptRecordFindings([]).findings, 'example.com')[0].detail).toContain('_smtp._tls.example.com');
		expect(getTlsRptRecordFindings(['v=TLSRPTv1;']).findings[0].title).toContain('missing rua');
		expect(getTlsRptRecordFindings(['v=TLSRPTv1; rua=ftp://bad.example.com']).findings[0].severity).toBe('medium');
		expect(getTlsRptRecordFindings(['v=TLSRPTv1; rua=mailto:tls@example.com']).findings).toHaveLength(0);
	});

	it('summarizes fully missing mail protections only without DNS errors', () => {
		expect(shouldSummarizeMissingMailProtections([], false, true, false)).toBe(true);
		expect(
			shouldSummarizeMissingMailProtections(
				[createFinding('mta_sts', 'MTA-STS DNS query failed', 'low', 'failed')],
				false,
				true,
				false,
			),
		).toBe(false);
	});
});