import { describe, it, expect } from 'vitest';
import { analyzeTrustSurface } from '../src/tools/spf-trust-surface';

describe('analyzeTrustSurface', () => {
	it('returns empty array for SPF with no shared platform includes', () => {
		const findings = analyzeTrustSurface('v=spf1 ip4:192.168.1.0/24 -all');
		expect(findings).toEqual([]);
	});

	it('returns one informational finding for SPF with one shared platform by default', () => {
		const findings = analyzeTrustSurface('v=spf1 include:_spf.google.com -all');
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].title).toContain('Google Workspace');
		expect(findings[0].metadata?.trustSurface).toBe(true);
		expect(findings[0].metadata?.platform).toBe('Google Workspace');
	});

	it('returns individual info findings plus info summary when DMARC is not weak', () => {
		const findings = analyzeTrustSurface('v=spf1 include:_spf.google.com include:sendgrid.net -all');
		// 2 individual + 1 summary = 3
		expect(findings).toHaveLength(3);
		const infos = findings.filter((f) => f.severity === 'info');
		expect(infos).toHaveLength(3);
		const summary = findings.find((f) => f.metadata?.platformCount === 2);
		expect(summary).toBeDefined();
		expect(summary!.title).toContain('2 shared platforms');
		expect(summary!.metadata?.platformCount).toBe(2);
	});

	it('elevates findings when weak DMARC corroborates the exposure', () => {
		const findings = analyzeTrustSurface('v=spf1 include:_spf.google.com include:sendgrid.net -all', {
			corroboratedByWeakDmarc: true,
			dmarcPolicy: 'none',
			dmarcAlignmentMode: 'relaxed',
		});

		expect(findings).toHaveLength(3);
		expect(findings.filter((f) => f.severity === 'medium')).toHaveLength(2);
		const summary = findings.find((f) => f.severity === 'high');
		expect(summary).toBeDefined();
		expect(summary!.metadata?.dmarcCorroborated).toBe(true);
	});

	it('detects platform via redirect= directive', () => {
		const findings = analyzeTrustSurface('v=spf1 redirect=_spf.google.com');
		expect(findings).toHaveLength(1);
		expect(findings[0].metadata?.platform).toBe('Google Workspace');
	});

	it('returns no findings for unknown include domain', () => {
		const findings = analyzeTrustSurface('v=spf1 include:mail.mycompany.com -all');
		expect(findings).toEqual([]);
	});

	it('matches subdomain of known platform (suffix match)', () => {
		const findings = analyzeTrustSurface('v=spf1 include:eu._spf.salesforce.com -all');
		expect(findings).toHaveLength(1);
		expect(findings[0].metadata?.platform).toBe('Salesforce');
		expect(findings[0].metadata?.includeDomain).toBe('eu._spf.salesforce.com');
	});
});
