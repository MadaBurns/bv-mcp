// SPDX-License-Identifier: BUSL-1.1

/**
 * Regression guards for two customer-visible prose defects in `scan_domain`'s
 * post-processing, both of which had the scan contradict its OWN findings:
 *
 *  1. A domain publishing an RFC 7505 null MX was told "Since this domain has MX
 *     records and accepts email…" on the MTA-STS finding, in the same response
 *     that reported "Null MX record (RFC 7505) — Domain explicitly declares it
 *     does not accept email". The standalone `check_mta_sts` tool got it right;
 *     only the scan path overwrote the correct copy.
 *
 *  2. A domain that cannot send email (null MX / no-send SPF `-all`) was told it
 *     "is eligible for BIMI" and should publish a BIMI record.
 *
 * Both fixes are TEXT/branch-selection only — every assertion below also pins the
 * severity, because severity calibration in this repo is operator-gated and these
 * fixes must not move a score.
 */

import { describe, expect, it } from 'vitest';
import { type CheckResult, buildCheckResult, createFinding } from '../src/lib/scoring';

/** The exact copy `check-mta-sts` emits for a domain with no inbound mail. */
const MTA_STS_NON_MAIL_DETAIL =
	'Neither MTA-STS nor TLS-RPT records are present for example.com. This is normal for domains that do not accept inbound email, but consider adding these records if you operate a mail server.';

const MTA_STS_FALSEHOOD = 'has MX records and accepts email';

const BIMI_ELIGIBLE_DETAIL =
	'No BIMI record found at default._bimi.example.com. This domain has DMARC enforcement and is eligible for BIMI. Publishing a BIMI record allows email clients like Gmail and Apple Mail to display your brand logo next to your emails.';

function mtaStsMissing(): CheckResult {
	return buildCheckResult(
		'mta_sts',
		[createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'low', MTA_STS_NON_MAIL_DETAIL)],
		false,
	);
}

function bimiEligible(): CheckResult {
	return buildCheckResult('bimi', [createFinding('bimi', 'No BIMI record found', 'low', BIMI_ELIGIBLE_DETAIL)], false);
}

/** `check-mx` null-MX terminal path: the RFC 7505 finding + `controlPresent: false`. */
function nullMxResult(): CheckResult {
	return buildCheckResult(
		'mx',
		[createFinding('mx', 'Null MX record (RFC 7505)', 'info', 'Domain explicitly declares it does not accept email via null MX record.')],
		false,
	);
}

/** `check-mx` no-MX + `v=spf1 -all` terminal path. */
function noMxHardFailResult(): CheckResult {
	return buildCheckResult(
		'mx',
		[createFinding('mx', 'Correctly-configured non-mail domain', 'info', 'No MX records, and SPF publishes "-all" (hard fail).')],
		false,
	);
}

/** `check-mx` mail-routing terminal path. */
function realMxResult(): CheckResult {
	return buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 mail exchange record(s) present.')], true);
}

describe('scan post-processing — MTA-STS wording must not contradict a null MX', () => {
	it("leaves the check's correct non-mail copy alone for an RFC 7505 null-MX domain", async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const updated = await applyScanPostProcessing('example.com', [nullMxResult(), mtaStsMissing()]);
		const finding = updated.find((r) => r.category === 'mta_sts')?.findings[0];

		expect(finding?.detail).not.toContain(MTA_STS_FALSEHOOD);
		expect(finding?.detail).toContain('do not accept inbound email');
		// Text-only fix: severity is untouched.
		expect(finding?.severity).toBe('low');
	});

	it('leaves the correct non-mail copy alone for a no-MX + "-all" domain', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const updated = await applyScanPostProcessing('example.com', [noMxHardFailResult(), mtaStsMissing()]);
		const finding = updated.find((r) => r.category === 'mta_sts')?.findings[0];

		expect(finding?.detail).not.toContain(MTA_STS_FALSEHOOD);
		expect(finding?.severity).toBe('low');
	});

	it('still clarifies the MTA-STS copy for a domain that really does accept mail', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const updated = await applyScanPostProcessing('example.com', [
			realMxResult(),
			buildCheckResult('mta_sts', [createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'medium', MTA_STS_NON_MAIL_DETAIL)]),
		]);
		const finding = updated.find((r) => r.category === 'mta_sts')?.findings[0];

		expect(finding?.detail).toContain(MTA_STS_FALSEHOOD);
		expect(finding?.severity).toBe('medium');
	});

	it('still clarifies when the mx lookup was INCONCLUSIVE — a failed probe is not a "no mail" claim', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const inconclusiveMx: CheckResult = {
			...buildCheckResult('mx', [
				createFinding('mx', 'MX records not assessed', 'info', 'Could not query MX records due to a transient DNS failure.'),
			]),
			checkStatus: 'error',
		};

		const updated = await applyScanPostProcessing('example.com', [
			inconclusiveMx,
			buildCheckResult('mta_sts', [createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'medium', MTA_STS_NON_MAIL_DETAIL)]),
		]);
		const finding = updated.find((r) => r.category === 'mta_sts')?.findings[0];

		expect(finding?.detail).toContain(MTA_STS_FALSEHOOD);
	});
});

describe('scan post-processing — BIMI must not be recommended to a domain that cannot send', () => {
	it('rewrites the "eligible for BIMI" copy for an RFC 7505 null-MX domain', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const updated = await applyScanPostProcessing('example.com', [nullMxResult(), bimiEligible()]);
		const finding = updated.find((r) => r.category === 'bimi')?.findings[0];

		expect(finding?.detail).not.toContain('eligible for BIMI');
		expect(finding?.detail).toContain('does not appear to send email');
		// No stray double dot from the bimi-domain capture.
		expect(finding?.detail).toContain('at default._bimi.example.com.');
		expect(finding?.detail).not.toContain('example.com..');
		expect(finding?.severity).toBe('low');
	});

	it('rewrites the "eligible for BIMI" copy for a no-send SPF policy even when MX records exist', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const updated = await applyScanPostProcessing('example.com', [
			realMxResult(),
			buildCheckResult('spf', [
				createFinding('spf', 'SPF hard fail configured', 'info', 'SPF publishes "-all" with no authorizing mechanisms.', {
					noSendPolicy: true,
				}),
			]),
			bimiEligible(),
		]);
		const finding = updated.find((r) => r.category === 'bimi')?.findings[0];

		expect(finding?.detail).not.toContain('eligible for BIMI');
		expect(finding?.detail).toContain('does not appear to send email');
		expect(finding?.severity).toBe('low');
	});

	it('preserves the "eligible for BIMI" copy for a real mail-sending domain', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const updated = await applyScanPostProcessing('example.com', [realMxResult(), bimiEligible()]);
		const finding = updated.find((r) => r.category === 'bimi')?.findings[0];

		expect(finding?.detail).toContain('eligible for BIMI');
		expect(finding?.severity).toBe('low');
	});
});
