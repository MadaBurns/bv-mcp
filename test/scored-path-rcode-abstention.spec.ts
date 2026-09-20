// SPDX-License-Identifier: BUSL-1.1

/**
 * THE SCORED PATH, not the plumbing.
 *
 * `test/check-dmarc-rcode.spec.ts` covers the rcode helpers directly; this file covers
 * the six TXT-published controls through the entry points `scan_domain` actually calls,
 * with a DoH mock answering HTTP 200 + empty answer set — byte-identical between the two
 * cases except for the `Status` field, which is the whole difference:
 *
 *   - NOERROR (0)  → a MEASUREMENT. The absence verdict stands and the category scores.
 *   - SERVFAIL (2) → NO measurement. The check must abstain (`checkStatus` non-measured,
 *     no `missingControl`) so the scoring engine excludes the category instead of zeroing
 *     a control nobody looked at.
 *
 * A check wired to the rcode-discarding `string[]` projection passes the NOERROR case and
 * FAILS the SERVFAIL one, which is exactly the regression this file exists to catch.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { findingsIndicateMissingControl, isCheckMeasured } from '@blackveil/dns-checks/scoring';
import type { CheckResult } from '../src/lib/scoring';
import { createDohResponse, setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

const TXT = 16;

/** Every lookup answers HTTP 200 carrying `status` with an empty answer set. */
function mockEmptyDoh(status: number): void {
	globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: 'example.com', type: TXT }], [], { status }));
}

// Single attempt, no secondary-resolver confirmation: the rcode under test must reach the
// check rather than being retried or overwritten by a fallback resolver's answer.
const noSecondary = { retries: 0, confirmWithSecondaryOnEmpty: false } as const;

const SERVFAIL = 2;
const NOERROR = 0;

/** The six TXT-published controls, each through its shipped Worker entry point. */
const SCORED_TXT_CHECKS: Array<{ category: string; run: () => Promise<CheckResult> }> = [
	{
		category: 'dmarc',
		run: async () => (await import('../src/tools/check-dmarc')).checkDmarc('example.com', noSecondary),
	},
	{
		category: 'spf',
		run: async () => (await import('../src/tools/check-spf')).checkSpf('example.com', noSecondary),
	},
	{
		category: 'dkim',
		run: async () => (await import('../src/tools/check-dkim')).checkDkim('example.com', 'default', noSecondary),
	},
	{
		category: 'mta_sts',
		run: async () => (await import('../src/tools/check-mta-sts')).checkMtaSts('example.com', noSecondary),
	},
	{
		category: 'bimi',
		run: async () => (await import('../src/tools/check-bimi')).checkBimi('example.com', noSecondary),
	},
	{
		category: 'tlsrpt',
		run: async () => (await import('../src/tools/check-tlsrpt')).checkTlsrpt('example.com', noSecondary),
	},
];

describe('SERVFAIL on the control record abstains instead of scoring an absence', () => {
	it.each(SCORED_TXT_CHECKS)('$category', async ({ run }) => {
		mockEmptyDoh(SERVFAIL);

		const result = await run();

		// Non-measured is what makes the scoring engine EXCLUDE the category (isCheckMeasured,
		// scoring/evidence.ts) rather than grade it at 0.
		expect(isCheckMeasured(result.checkStatus)).toBe(false);
		expect(result.partial).toBe(true);

		// The #638 law: nothing may be claimed absent by a probe that never concluded.
		expect(findingsIndicateMissingControl(result.findings)).toBe(false);
		expect(result.findings.every((f) => f.metadata?.missingControl === undefined)).toBe(true);
		expect(result.controlPresent).toBeUndefined();

		// And it is an abstention, not a silent pass.
		expect(result.findings.some((f) => f.metadata?.inconclusive === true && f.metadata?.errorKind === 'dns_error')).toBe(true);
	});
});

describe('NOERROR with no answers is still a measured absence', () => {
	it.each(SCORED_TXT_CHECKS)('$category', async ({ run }) => {
		mockEmptyDoh(NOERROR);

		const result = await run();

		// The pre-existing behaviour the abstention must not swallow: an empty answer under
		// NOERROR IS evidence, and the category still scores. (`checkStatus` is left
		// undefined on a completed result — `isCheckMeasured` is the gate, not the field.)
		expect(result.checkStatus ?? 'completed').toBe('completed');
		expect(isCheckMeasured(result.checkStatus)).toBe(true);

		// A verdict was reached, and none of it is an abstention.
		expect(result.findings.length).toBeGreaterThan(0);
		expect(result.findings.some((f) => f.metadata?.inconclusive === true)).toBe(false);
	});
});
