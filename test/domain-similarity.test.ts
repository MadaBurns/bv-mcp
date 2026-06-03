// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { combosquatMatch, domainLabelSimilarity } from '../src/lib/domain-similarity';

describe('domainLabelSimilarity', () => {
	it('scores close typo labels higher than unrelated labels', () => {
		expect(domainLabelSimilarity('example.com', 'examp1e.com')).toBeGreaterThanOrEqual(0.85);
		expect(domainLabelSimilarity('example.com', 'totallydifferent.net')).toBeLessThan(0.5);
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
