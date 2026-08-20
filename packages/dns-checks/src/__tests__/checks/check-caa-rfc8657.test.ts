// SPDX-License-Identifier: BUSL-1.1

/**
 * RFC 8657 CAA parameter binding, end-to-end through `checkCAA`.
 *
 * The unit-level parsing lives in `caa-analysis.test.ts`; this file covers the two
 * things only the assembled check can answer: that the parameters actually reach
 * the finding list, and that surfacing them does NOT move the `caa` category
 * score. The neutrality arm is asserted rather than assumed — an `info` finding
 * carries penalty 0 today, but nothing structural stops a later edit from
 * promoting this finding to a scored severity, which would silently penalize the
 * ~97-99% of CAA-publishing domains that carry no RFC 8657 parameters.
 */
import { describe, expect, it } from 'vitest';

import { checkCAA } from '../../index.js';
import type { DNSQueryFunction } from '../../types.js';

const D = 'x.test';

/** Resolver that answers only what a case explicitly publishes; apex resolves so nothing abstains. */
function resolver(map: Record<string, string[]> = {}): DNSQueryFunction {
	return async (name: string, type: string) =>
		map[`${type}:${name}`] ?? (type === 'NS' && name === D ? ['ns1.x', 'ns2.x'] : type === 'A' && name === D ? ['192.0.2.1'] : []);
}

const opts = { timeout: 3000 };

/** A complete, well-formed CAA RRset — issue + issuewild + iodef — with no RFC 8657 parameters. */
const WITHOUT_PARAMETERS = ['0 issue "letsencrypt.org"', '0 issuewild "letsencrypt.org"', '0 iodef "mailto:security@x.test"'];

/** The SAME RRset, differing ONLY by the RFC 8657 parameters on the issue/issuewild values. */
const WITH_PARAMETERS = [
	'0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123; validationmethods=dns-01"',
	'0 issuewild "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123; validationmethods=dns-01"',
	'0 iodef "mailto:security@x.test"',
];

describe('checkCAA — RFC 8657 parameter binding', () => {
	it('surfaces an info finding when the CAA policy carries account and method binding', async () => {
		const result = await checkCAA(D, resolver({ [`CAA:${D}`]: WITH_PARAMETERS }), opts);
		const finding = result.findings.find((f) => f.title === 'CAA restricts issuance beyond the CA (RFC 8657)');
		expect(finding).toBeDefined();
		expect(finding?.severity).toBe('info');
		expect(finding?.metadata?.caaAccountBound).toBe(true);
		expect(finding?.metadata?.caaValidationMethods).toEqual(['dns-01']);
	});

	it('emits no such finding when the CAA policy carries no parameters', async () => {
		const result = await checkCAA(D, resolver({ [`CAA:${D}`]: WITHOUT_PARAMETERS }), opts);
		expect(result.findings.map((f) => f.title)).not.toContain('CAA restricts issuance beyond the CA (RFC 8657)');
	});

	// A5 — score neutrality, measured through the real scorer rather than reasoned
	// about from the severity constant.
	it('scores the caa category identically with and without the parameters', async () => {
		const without = await checkCAA(D, resolver({ [`CAA:${D}`]: WITHOUT_PARAMETERS }), opts);
		const with_ = await checkCAA(D, resolver({ [`CAA:${D}`]: WITH_PARAMETERS }), opts);

		expect(with_.score).toBe(without.score);
		expect(with_.passed).toBe(without.passed);
		// Guard the premise of the neutrality claim: the two runs must genuinely differ
		// in findings, or an identical score would prove nothing.
		expect(with_.findings.length).toBe(without.findings.length + 1);
	});
});
