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
		// length: fabpayy (insertion, maxLen 7) scored 0.86 while fabpa
		// (deletion) and fabpai (substitution) scored 0.83 — same one-edit
		// closeness, opposite side of the 0.85 impersonation gate.
		expect(domainLabelSimilarity('fabpay.com', 'fabpa.com')).toBeGreaterThanOrEqual(0.85);
		expect(domainLabelSimilarity('fabpay.com', 'fabpai.com')).toBeGreaterThanOrEqual(0.85);
		expect(domainLabelSimilarity('fabpay.com', 'fabpayy.com')).toBeGreaterThanOrEqual(0.85);
	});

	it('keeps the plain ratio for one-edit pairs of very short labels — coincidence, not typosquat (#1038 guard)', () => {
		expect(domainLabelSimilarity('hp.com', 'hq.com')).toBeLessThan(0.85);
	});

	it('keeps the plain ratio when the labels are more than one edit apart (#1038 floor is single-edit only)', () => {
		expect(domainLabelSimilarity('fabpay.com', 'fabp.com')).toBeLessThan(0.85);
	});

	it('cannot see a brand token inside a longer combosquat label (the gap combosquatMatch fills)', () => {
		// `fabpay-login` vs `fabpay` scores far below the 0.85 impersonation
		// threshold — this is exactly why combosquats need a separate detector.
		expect(domainLabelSimilarity('fabpay', 'fabpay-login')).toBeLessThan(0.85);
	});
});

describe('combosquatMatch', () => {
	it('flags delimited brand-token segments (brand-keyword, keyword-brand)', () => {
		expect(combosquatMatch('fabpay', 'fabpay-login')).toMatchObject({
			brandToken: 'fabpay',
			extraTokens: ['login'],
			hasLureKeyword: true,
			matchKind: 'delimited',
		});
		expect(combosquatMatch('fabpay', 'secure-fabpay')).toMatchObject({ extraTokens: ['secure'], hasLureKeyword: true });
		expect(combosquatMatch('microsoft', 'login.microsoft.update')).toMatchObject({ matchKind: 'delimited' });
	});

	it('flags a non-lure extra token but marks hasLureKeyword false (severity hint, still a match)', () => {
		expect(combosquatMatch('fabpay', 'fabpay-shop')).toMatchObject({ extraTokens: ['shop'], hasLureKeyword: false });
	});

	it('flags undelimited concatenation only when the remainder is a known lure keyword', () => {
		expect(combosquatMatch('fabpay', 'fabpaylogin')).toMatchObject({ matchKind: 'undelimited', extraTokens: ['login'] });
		expect(combosquatMatch('microsoft', 'verifymicrosoft')).toMatchObject({ matchKind: 'undelimited', extraTokens: ['verify'] });
		// remainder is not a lure keyword → not a combosquat
		expect(combosquatMatch('fabpay', 'fabpayways')).toBeNull();
	});

	it('does NOT match an exact label (owned portfolio domain, not a combosquat)', () => {
		expect(combosquatMatch('fabpay', 'fabpay')).toBeNull();
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
		expect(combosquatMatch('', 'fabpay-login')).toBeNull();
		expect(combosquatMatch('fabpay', '   ')).toBeNull();
	});
});
