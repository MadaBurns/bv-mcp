// SPDX-License-Identifier: BUSL-1.1

/**
 * CAA tag-completeness analysis.
 *
 * Ported from the Worker-side `test/caa-analysis.spec.ts`, which exercised a
 * duplicate copy at `src/tools/caa-analysis.ts` that nothing in the production
 * path imported — `src/tools/check-caa.ts` delegates to this package. The tests
 * passed while validating dead code, so the live implementation was untested.
 * The duplicate is removed; this file is the coverage, pointed at what runs.
 */

import { describe, expect, it } from 'vitest';

import {
	getCaaConfiguredFinding,
	getCaaParameterBindingFindings,
	getCaaValidationFindings,
	parseCaaParameters,
	summarizeCaaTags,
} from '../../checks/caa-analysis';

describe('caa-analysis', () => {
	it('summarizes presence of key CAA tags', () => {
		expect(
			summarizeCaaTags([
				{ flags: 0, tag: 'issue', value: 'letsencrypt.org' },
				{ flags: 0, tag: 'iodef', value: 'mailto:admin@example.com' },
			]),
		).toEqual({ hasIssue: true, hasIssuewild: false, hasIodef: true, hasIssuemail: false });
	});

	it('emits findings for missing tags', () => {
		const findings = getCaaValidationFindings({ hasIssue: false, hasIssuewild: false, hasIodef: true });
		expect(findings.map((finding) => finding.title)).toEqual(['No CAA issue tag', 'No CAA issuewild tag']);
	});

	it('produces the configured finding when all tags are present', () => {
		expect(getCaaValidationFindings({ hasIssue: true, hasIssuewild: true, hasIodef: true })).toHaveLength(0);
		expect(getCaaConfiguredFinding().severity).toBe('info');
	});

	it('summarizes the RFC 9495 issuemail tag', () => {
		expect(summarizeCaaTags([{ flags: 0, tag: 'issuemail', value: 'digicert.com' }])).toEqual({
			hasIssue: false,
			hasIssuewild: false,
			hasIodef: false,
			hasIssuemail: true,
		});
	});
});

describe('parseCaaParameters (RFC 8657)', () => {
	it('parses an accounturi parameter out of an issue value', () => {
		const params = parseCaaParameters('letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123');
		expect(params.accounturi).toBe('https://acme-v02.api.letsencrypt.org/acme/acct/123');
	});

	it('parses a single validationmethods value as a one-element list', () => {
		expect(parseCaaParameters('letsencrypt.org; validationmethods=dns-01').validationmethods).toEqual(['dns-01']);
	});

	it('parses comma-separated validationmethods into a list', () => {
		expect(parseCaaParameters('letsencrypt.org; validationmethods=dns-01,http-01').validationmethods).toEqual(['dns-01', 'http-01']);
	});

	it('matches parameter tags case-insensitively', () => {
		const params = parseCaaParameters('letsencrypt.org; AccountURI=https://acme.example/acct/9; ValidationMethods=DNS-01');
		expect(params.accounturi).toBe('https://acme.example/acct/9');
		expect(params.validationmethods).toEqual(['DNS-01']);
	});

	it('tolerates whitespace around the separator, tag and value', () => {
		const params = parseCaaParameters(
			'  letsencrypt.org ;  accounturi =  https://acme.example/acct/7  ;  validationmethods = dns-01 , http-01 ',
		);
		expect(params.issuerDomain).toBe('letsencrypt.org');
		expect(params.accounturi).toBe('https://acme.example/acct/7');
		expect(params.validationmethods).toEqual(['dns-01', 'http-01']);
	});

	it('strips surrounding quotes from a parameter value', () => {
		expect(parseCaaParameters('letsencrypt.org; accounturi="https://acme.example/acct/5"').accounturi).toBe('https://acme.example/acct/5');
	});

	it('parses parameters on an issuewild value exactly as on issue', () => {
		const params = parseCaaParameters('sectigo.com; accounturi=https://acme.example/acct/42; validationmethods=dns-01');
		expect(params.issuerDomain).toBe('sectigo.com');
		expect(params.accounturi).toBe('https://acme.example/acct/42');
		expect(params.validationmethods).toEqual(['dns-01']);
	});

	it('reads the explicit no-issuance form as forbidding issuance, not as a parameterless grant', () => {
		const params = parseCaaParameters(';');
		expect(params.noIssuance).toBe(true);
		expect(params.issuerDomain).toBe('');
		expect(params.accounturi).toBeUndefined();
	});

	it('does not treat an ordinary parameterless grant as no-issuance', () => {
		const params = parseCaaParameters('letsencrypt.org');
		expect(params.noIssuance).toBe(false);
		expect(params.issuerDomain).toBe('letsencrypt.org');
	});
});

describe('getCaaParameterBindingFindings', () => {
	it('emits an info finding when CAA carries an account binding', () => {
		const findings = getCaaParameterBindingFindings([
			{ flags: 0, tag: 'issue', value: 'letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123' },
		]);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].metadata?.caaAccountBound).toBe(true);
	});

	it('emits an info finding when CAA carries a validation-method binding', () => {
		const findings = getCaaParameterBindingFindings([{ flags: 0, tag: 'issuewild', value: 'letsencrypt.org; validationmethods=dns-01' }]);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].metadata?.caaValidationMethods).toEqual(['dns-01']);
	});

	// The load-bearing arm. RFC 8657 parameters are a BONUS signal: ~97-99% of
	// CAA-publishing domains carry none, so any finding here — even a `low` — would
	// fire as a penalty against essentially every domain that did the right thing by
	// publishing CAA at all. Absence is not a defect and must stay silent.
	it('emits NO finding when CAA has no RFC 8657 parameters', () => {
		expect(
			getCaaParameterBindingFindings([
				{ flags: 0, tag: 'issue', value: 'letsencrypt.org' },
				{ flags: 0, tag: 'issuewild', value: 'letsencrypt.org' },
				{ flags: 0, tag: 'iodef', value: 'mailto:admin@example.com' },
			]),
		).toEqual([]);
	});

	it('emits no finding for the explicit no-issuance form, which carries no parameters', () => {
		expect(getCaaParameterBindingFindings([{ flags: 0, tag: 'issue', value: ';' }])).toEqual([]);
	});
});
