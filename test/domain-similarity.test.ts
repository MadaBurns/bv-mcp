// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { combosquatMatch, domainLabelSimilarity } from '../src/lib/domain-similarity';

describe('domainLabelSimilarity', () => {
	it('scores close typo labels higher than unrelated labels', () => {
		expect(domainLabelSimilarity('example.com', 'examp1e.com')).toBeGreaterThanOrEqual(0.85);
		expect(domainLabelSimilarity('example.com', 'totallydifferent.net')).toBeLessThan(0.5);
	});

	it('scores every one-edit typosquat of a brand identically, regardless of which side of the brand length it lands (#1038)', () => {
		// Pre-fix, `1 - distance/maxLen` made the score depend on the BRAND
		// length: paypall (insertion, maxLen 7) scored 0.86 while paypa
		// (deletion) and paypai (substitution) scored 0.83 — same one-edit
		// closeness, opposite side of the 0.85 impersonation gate.
		expect(domainLabelSimilarity('paypal.com', 'paypa.com')).toBeGreaterThanOrEqual(0.85);
		expect(domainLabelSimilarity('paypal.com', 'paypai.com')).toBeGreaterThanOrEqual(0.85);
		expect(domainLabelSimilarity('paypal.com', 'paypall.com')).toBeGreaterThanOrEqual(0.85);
	});

	it('keeps the plain ratio for one-edit pairs of very short labels — coincidence, not typosquat (#1038 guard)', () => {
		expect(domainLabelSimilarity('hp.com', 'hq.com')).toBeLessThan(0.85);
	});

	it('keeps the plain ratio when the labels are more than one edit apart (#1038 floor is single-edit only)', () => {
		expect(domainLabelSimilarity('paypal.com', 'payp.com')).toBeLessThan(0.85);
	});

	it('cannot see a brand token inside a longer combosquat label (the gap combosquatMatch fills)', () => {
		// `paypal-login` vs `paypal` scores far below the 0.85 impersonation
		// threshold — this is exactly why combosquats need a separate detector.
		expect(domainLabelSimilarity('paypal', 'paypal-login')).toBeLessThan(0.85);
	});
});

describe('combosquatMatch', () => {
	it('flags delimited brand-token segments (brand-keyword, keyword-brand)', () => {
		expect(combosquatMatch('paypal', 'paypal-login')).toMatchObject({
			brandToken: 'paypal',
			extraTokens: ['login'],
			hasLureKeyword: true,
			matchKind: 'delimited',
		});
		expect(combosquatMatch('paypal', 'secure-paypal')).toMatchObject({ extraTokens: ['secure'], hasLureKeyword: true });
		expect(combosquatMatch('microsoft', 'login.microsoft.update')).toMatchObject({ matchKind: 'delimited' });
	});

	it('flags a non-lure extra token but marks hasLureKeyword false (severity hint, still a match)', () => {
		expect(combosquatMatch('paypal', 'paypal-shop')).toMatchObject({ extraTokens: ['shop'], hasLureKeyword: false });
	});

	it('flags undelimited concatenation only when the remainder is a known lure keyword', () => {
		expect(combosquatMatch('paypal', 'paypallogin')).toMatchObject({ matchKind: 'undelimited', extraTokens: ['login'] });
		expect(combosquatMatch('microsoft', 'verifymicrosoft')).toMatchObject({ matchKind: 'undelimited', extraTokens: ['verify'] });
		// remainder is not a lure keyword → not a combosquat
		expect(combosquatMatch('paypal', 'paypalways')).toBeNull();
	});

	it('does NOT match an exact label (owned portfolio domain, not a combosquat)', () => {
		expect(combosquatMatch('paypal', 'paypal')).toBeNull();
	});

	it('does NOT match a short brand token concatenated into an unrelated word (FP guard)', () => {
		expect(combosquatMatch('pay', 'fabricpay')).toBeNull(); // brand too short for either branch
		expect(combosquatMatch('hp', 'shop')).toBeNull();
	});

	it('does NOT match a long brand token that is merely a substring of one bigger word', () => {
		expect(combosquatMatch('apple', 'pineapple')).toBeNull(); // < undelimited min len AND no lure remainder
		expect(combosquatMatch('amazon', 'amazonianforest')).toBeNull(); // remainder `ianforest` is not a lure keyword
	});

	it('handles empty / whitespace input safely', () => {
		expect(combosquatMatch('', 'paypal-login')).toBeNull();
		expect(combosquatMatch('paypal', '   ')).toBeNull();
	});
});
