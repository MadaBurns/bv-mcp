// SPDX-License-Identifier: BUSL-1.1

/**
 * DMARC is the worked example of the RCODE conflation: `_dmarc.<domain>` is a TXT lookup,
 * a SERVFAIL on it arrives as HTTP 200 with an empty answer set, and the `string[]`
 * projection hands the classifier the same thing a domain with no DMARC record produces.
 * The classifier then records a MEASURED absence, which zeroes a Core category.
 *
 * These cases pin both halves of the contract the seam has to keep straight:
 *   - NOERROR-with-no-answers still produces a measured absence (`missingControl`), and
 *   - an inconclusive rcode maps onto the EXISTING abstention shape — `checkStatus:
 *     'error'` + `errorKind` — and never onto `missingControl`.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildRcodeAbstentionResult, isInconclusiveRcode } from '@blackveil/dns-checks';
import { findingsIndicateMissingControl, isCheckMeasured } from '@blackveil/dns-checks/scoring';
import { createDohResponse, setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
});

const TXT = 16;

/** Mock DoH: every lookup answers HTTP 200 carrying `status` with an empty answer set. */
function mockEmptyDoh(status: number): void {
	globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: '_dmarc.example.com', type: TXT }], [], { status }));
}

const noSecondary = { retries: 0, confirmWithSecondaryOnEmpty: false } as const;

describe('_dmarc NOERROR-empty is still a measured absence', () => {
	it('checkDmarc records missingControl and reports the check as measured', async () => {
		mockEmptyDoh(0);
		const { checkDmarc } = await import('../src/tools/check-dmarc');

		const result = await checkDmarc('example.com', noSecondary);

		// The control was measured, and it is absent — the pre-existing behaviour this
		// change must not disturb.
		expect(isCheckMeasured(result.checkStatus)).toBe(true);
		expect(findingsIndicateMissingControl(result.findings)).toBe(true);
	});

	it('the seam reports the same lookup as conclusive', async () => {
		mockEmptyDoh(0);
		const { queryTxtRecordsWithRcode } = await import('../src/lib/dns-records');

		const outcome = await queryTxtRecordsWithRcode('_dmarc.example.com', noSecondary);

		expect(outcome.records).toEqual([]);
		expect(outcome.inconclusive).toBe(false);
	});
});

describe('the SCORED path abstains: checkDmarc itself under an inconclusive rcode', () => {
	// The seam cases below prove the plumbing. These prove the SHIPPED check consumes it:
	// they call the same entry point `scan_domain` calls, so a `checkDMARC` that reads the
	// rcode-discarding projection again fails here rather than passing on a helper nobody
	// is wired to (the SQ-62 wave-1 blind spot).
	it.each([
		[2, 'SERVFAIL'],
		[5, 'REFUSED'],
	])('rcode %i (%s) returns the abstention shape, not a zeroed Core category', async (status) => {
		mockEmptyDoh(status);
		const { checkDmarc } = await import('../src/tools/check-dmarc');

		const result = await checkDmarc('example.com', noSecondary);

		expect(result.checkStatus).toBe('error');
		expect(isCheckMeasured(result.checkStatus)).toBe(false);
		expect(result.partial).toBe(true);

		// The #638 law on the scored path: a probe that never concluded may not claim absence.
		expect(findingsIndicateMissingControl(result.findings)).toBe(false);
		expect(result.findings.every((f) => f.metadata?.missingControl === undefined)).toBe(true);
		expect(result.controlPresent).toBeUndefined();
		expect(result.findings[0].detail).toContain(status === 2 ? 'SERVFAIL' : 'REFUSED');
	});
});

describe('_dmarc SERVFAIL/REFUSED is an abstention, never a missing control', () => {
	it.each([
		[2, 'SERVFAIL'],
		[5, 'REFUSED'],
	])('rcode %i (%s) reaches the caller as an inconclusive signal, not an empty record set', async (status) => {
		mockEmptyDoh(status);
		const { queryTxtRecordsWithRcode } = await import('../src/lib/dns-records');

		const outcome = await queryTxtRecordsWithRcode('_dmarc.example.com', noSecondary);

		// Byte-identical to the NOERROR case in `records` — the rcode is the only difference,
		// and it is the whole difference.
		expect(outcome.records).toEqual([]);
		expect(outcome.rcode).toBe(status);
		expect(outcome.inconclusive).toBe(true);
		expect(isInconclusiveRcode(outcome.rcode)).toBe(true);
	});

	it('maps onto the existing abstention shape: checkStatus error + errorKind, no missingControl', async () => {
		mockEmptyDoh(2);
		const { queryTxtRecordsWithRcode } = await import('../src/lib/dns-records');

		const outcome = await queryTxtRecordsWithRcode('_dmarc.example.com', noSecondary);
		expect(outcome.inconclusive).toBe(true);

		const result = buildRcodeAbstentionResult('dmarc', 'DMARC', '_dmarc.example.com', 'TXT', outcome.rcode);

		// Abstention, as `isCheckMeasured` / the scoring engine's transient-failure exclusion
		// understands it — NOT a zeroed category.
		expect(result.checkStatus).toBe('error');
		expect(isCheckMeasured(result.checkStatus)).toBe(false);
		expect(result.partial).toBe(true);
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);

		// The #638 law: a probe that never concluded may not claim the control is absent.
		expect(findingsIndicateMissingControl(result.findings)).toBe(false);
		expect(result.findings.every((f) => f.metadata?.missingControl === undefined)).toBe(true);
		expect(result.controlPresent).toBeUndefined();

		// The markers `isDnsErrorFinding` and control-presence already filter on.
		const { isDnsErrorFinding } = await import('../src/lib/dns-error-result');
		expect(result.findings.some(isDnsErrorFinding)).toBe(true);
		expect(result.findings[0].metadata?.inconclusive).toBe(true);
		expect(result.findings[0].detail).toContain('SERVFAIL');
	});
});
