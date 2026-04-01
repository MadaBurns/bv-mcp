import { describe, expect, it } from 'vitest';

import { getHttpRedirectFindings, getHttpsErrorFinding, getHttpsFindings } from '../src/tools/ssl-analysis';

describe('ssl-analysis', () => {
	it('flags HTTPS downgrade and missing HSTS', () => {
		const findings = getHttpsFindings('example.com', 'http://example.com/', null);
		expect(findings.map((finding) => finding.title)).toEqual(['HTTPS redirects to HTTP', 'No HSTS header']);
	});

	it('flags short HSTS and missing includeSubDomains', () => {
		const findings = getHttpsFindings('example.com', 'https://example.com/', 'max-age=3600');
		expect(findings.find((finding) => finding.title === 'HSTS max-age too short')?.severity).toBe('low');
		expect(findings.find((finding) => finding.title === 'HSTS missing includeSubDomains')?.severity).toBe('low');
	});

	it('maps HTTPS errors to severity-specific findings', () => {
		expect(getHttpsErrorFinding('example.com', 'The operation was aborted due to timeout').title).toBe('HTTPS connection timeout');
		expect(getHttpsErrorFinding('example.com', 'ECONNREFUSED').severity).toBe('critical');
	});

	it('evaluates HTTP redirect responses', () => {
		expect(getHttpRedirectFindings('example.com', 301, 'https://example.com/')).toHaveLength(0);
		expect(getHttpRedirectFindings('example.com', 302, 'http://example.com/')[0].title).toBe('HTTP does not redirect to HTTPS');
		expect(getHttpRedirectFindings('example.com', 200, null)[0].title).toBe('No HTTP to HTTPS redirect');
	});
});