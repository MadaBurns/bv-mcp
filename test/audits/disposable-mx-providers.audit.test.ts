// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: the lookalike "disposable MX" list never names a provider the product
 * itself recommends (#1198).
 *
 * `DISPOSABLE_MX_PROVIDERS` (`src/tools/lookalike-severity.ts`) is a HIGH
 * corroborator in the #264 matrix: a mail-capable lookalike whose MX sits on
 * one of those suffixes is elevated to HIGH with the prose "disposable MX
 * provider". `mailgun.org` used to be the first entry while
 * `generate-records.ts` emitted `include:mailgun.org` for a customer asking
 * who may send their mail, and `check-dkim.ts` listed Mailgun as a
 * high-confidence DKIM signer. Measured 2026-10-04 on `blackrockk.com`
 * (registered 1,669 days earlier, no A record): the Mailgun MX was the SOLE
 * cause of a `deterministic` HIGH.
 *
 * This audit is the drift guard the issue asked for. It sweeps every provider
 * the product recommends — the SPF include map, plus the provider domains
 * implied by `HIGH_CONFIDENCE_DKIM_PROVIDERS` (not exported from
 * `check-dkim.ts`, so listed inline) — and requires that none of them is a
 * disposable MX host, matches a disposable suffix, or shares a registrable
 * apex with a disposable entry. The positive controls at the end prove each
 * predicate can fire, so a green run cannot mean "compared nothing".
 */

import { describe, it, expect } from 'vitest';
import { KNOWN_SPF_INCLUDES } from '../../src/tools/generate-records';
import { DISPOSABLE_MX_PROVIDERS, isDisposableMxHost } from '../../src/tools/lookalike-severity';
import { getRegistrableDomain } from '../../src/lib/public-suffix';

/**
 * Provider domains implied by `HIGH_CONFIDENCE_DKIM_PROVIDERS` in
 * `src/tools/check-dkim.ts` (amazon ses, sendgrid, mailgun, postmark, google
 * workspace, microsoft 365). Keep in step with that set.
 */
const HIGH_CONFIDENCE_DKIM_PROVIDER_DOMAINS: readonly string[] = [
	'mailgun.org',
	'sendgrid.net',
	'amazonses.com',
	'mtasv.net',
	'google.com',
	'outlook.com',
];

const SPF_INCLUDE_VALUES: readonly string[] = [...new Set(Object.values(KNOWN_SPF_INCLUDES))];

/** The suffix rule `isDisposableMxHost` documents, restated so the list is checked independently of the function. */
function matchesDisposableSuffix(host: string): string | undefined {
	return DISPOSABLE_MX_PROVIDERS.find((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

/** Registrable apex, falling back to the host itself when the PSL yields none. */
function apexOf(host: string): string {
	return getRegistrableDomain(host) ?? host;
}

const DISPOSABLE_APEXES = new Set(DISPOSABLE_MX_PROVIDERS.map(apexOf));

function assertNotDisposable(host: string): void {
	expect(isDisposableMxHost(host), `${host} is classified disposable`).toBe(false);
	expect(matchesDisposableSuffix(host), `${host} matches a disposable suffix`).toBeUndefined();
	expect(DISPOSABLE_APEXES.has(apexOf(host)), `${host} shares registrable apex ${apexOf(host)} with a disposable entry`).toBe(false);
}

describe('DISPOSABLE_MX_PROVIDERS is disjoint from the SPF providers generate-records recommends (#1198)', () => {
	it('sweeps a non-empty recommended set that still includes mailgun.org (vacuous-green guard)', () => {
		expect(SPF_INCLUDE_VALUES.length).toBeGreaterThan(5);
		expect(SPF_INCLUDE_VALUES).toContain('mailgun.org');
	});

	for (const value of SPF_INCLUDE_VALUES) {
		it(`${value} is not a disposable MX host, suffix, or apex`, () => {
			assertNotDisposable(value);
		});
	}
});

describe('DISPOSABLE_MX_PROVIDERS is disjoint from the high-confidence DKIM providers (#1198)', () => {
	for (const value of HIGH_CONFIDENCE_DKIM_PROVIDER_DOMAINS) {
		it(`${value} is not a disposable MX host, suffix, or apex`, () => {
			assertNotDisposable(value);
		});
	}
});

describe('positive controls — each predicate above can fire', () => {
	it('the list still carries genuine throwaway providers, and a host under one is classified disposable', () => {
		expect(DISPOSABLE_MX_PROVIDERS.length).toBeGreaterThan(0);
		expect(isDisposableMxHost('mx.mailinator.com')).toBe(true);
		expect(matchesDisposableSuffix('mx.mailinator.com')).toBe('mailinator.com');
	});

	it('the apex comparison resolves a recommended include to its registrable apex', () => {
		expect(apexOf('_spf.google.com')).toBe('google.com');
		expect(apexOf('spf.protection.outlook.com')).toBe('outlook.com');
		expect(DISPOSABLE_APEXES.has(apexOf('mx.mailinator.com'))).toBe(true);
	});
});
