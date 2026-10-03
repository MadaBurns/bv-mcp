// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-287 item 1 — a non-mail downgrade must also retract `metadata.missingControl`.
 *
 * `adjustForNonApexNonMailHost`, `adjustForNonMailDomain` and `adjustForNoSendDomain`
 * rewrite a critical/high "No X record" finding to `info` / "not applicable" and then
 * re-derive the result with `buildCheckResult`. But `findingsIndicateMissingControl`
 * honours a DECLARED `metadata.missingControl: true` with no severity gate, so the
 * downgraded finding still zeroed the category and flipped `passed` to false — the
 * "not applicable" prose and the score contradicted each other.
 *
 * The earlier fixtures (see scan-post-processing.spec.ts) build the SPF/DMARC finding
 * WITHOUT `missingControl: true`, which is not how `check-spf` / the DMARC classifier
 * emit it, so they fell through to the severity-gated prose regex and never saw this.
 * Every finding below carries the declaration exactly as production does.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { findingsIndicateMissingControl } from '@blackveil/dns-checks/scoring';
import { type CheckResult, buildCheckResult, createFinding } from '../src/lib/scoring';

/** `check-spf`'s zero-record terminal finding, byte-for-byte shape (declares missingControl). */
function spfMissing(): CheckResult {
	return buildCheckResult(
		'spf',
		[
			createFinding(
				'spf',
				'No SPF record found',
				'critical',
				'No SPF (v=spf1) TXT record found for www.example.com. Without SPF, any server can send email claiming to be from your domain.',
				{ missingControl: true },
			),
		],
		false,
		false,
	);
}

/** The DMARC classifier's no-record finding (declares missingControl). */
function dmarcMissing(): CheckResult {
	return buildCheckResult(
		'dmarc',
		[
			createFinding(
				'dmarc',
				'No DMARC record found',
				'high',
				'No DMARC record found at _dmarc.www.example.com. Without DMARC, receivers cannot verify email authentication.',
				{ missingControl: true },
			),
		],
		false,
		false,
	);
}

function noMx(): CheckResult {
	return buildCheckResult(
		'mx',
		[createFinding('mx', 'Correctly-configured non-mail domain', 'info', 'No MX records, SPF publishes -all.')],
		false,
	);
}

function expectNotApplicable(result: CheckResult | undefined): void {
	expect(result).toBeDefined();
	const finding = result!.findings[0];
	expect(finding.severity).toBe('info');
	// The scored half: a not-applicable finding must not zero the category or fail it.
	expect(result!.score).toBe(100);
	expect(result!.passed).toBe(true);
	// The structural half: no finding may still DECLARE the control missing.
	expect(findingsIndicateMissingControl(result!.findings)).toBe(false);
	expect(finding.metadata?.missingControl).toBe(false);
}

describe('SQ-287 scan post-processing — non-mail downgrade clears missingControl', () => {
	beforeEach(() => {
		vi.resetModules();
	});
	afterEach(() => {
		vi.doUnmock('../src/lib/dns');
	});

	it('control: a mail domain with a declared-missing SPF keeps its zero (the declaration is real)', () => {
		const spf = spfMissing();
		expect(spf.score).toBe(0);
		expect(spf.passed).toBe(false);
	});

	it('adjustForNonApexNonMailHost: a www host with no MX is not scored as missing SPF/DMARC', async () => {
		vi.doMock('../src/lib/dns', () => ({ queryTxtRecords: vi.fn().mockResolvedValue([]) }));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const updated = await applyScanPostProcessing('www.example.com', [spfMissing(), dmarcMissing(), noMx()], { nonApexHost: true });

		expectNotApplicable(updated.find((r) => r.category === 'spf'));
		expectNotApplicable(updated.find((r) => r.category === 'dmarc'));
	});

	it('adjustForNonMailDomain: a no-MX subdomain covered by enforcing parent DMARC is not scored as missing SPF/DMARC', async () => {
		vi.doMock('../src/lib/dns', () => ({ queryTxtRecords: vi.fn().mockResolvedValue(['v=DMARC1; p=reject']) }));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const updated = await applyScanPostProcessing('sub.example.com', [spfMissing(), dmarcMissing(), noMx()]);

		expectNotApplicable(updated.find((r) => r.category === 'spf'));
		expectNotApplicable(updated.find((r) => r.category === 'dmarc'));
	});

	it('adjustForNoSendDomain: no-send SPF domain with MX does not zero dkim/mta_sts/bimi missing-record findings', async () => {
		vi.doMock('../src/lib/dns', () => ({ queryTxtRecords: vi.fn().mockResolvedValue([]) }));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const noSendSpf = buildCheckResult(
			'spf',
			[createFinding('spf', 'SPF hard fail with no senders', 'info', 'v=spf1 -all', { noSendPolicy: true })],
			true,
			true,
		);
		const realMx = buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '1 MX')], true);
		const dkim = buildCheckResult(
			'dkim',
			[
				createFinding('dkim', 'No DKIM records found among tested selectors', 'high', 'No DKIM records were found.', {
					missingControl: true,
				}),
			],
			false,
		);

		const updated = await applyScanPostProcessing('example.com', [noSendSpf, realMx, dkim]);

		expectNotApplicable(updated.find((r) => r.category === 'dkim'));
	});

	it('leaves a finding that is NOT downgraded (mail domain) declared-missing and zeroed', async () => {
		vi.doMock('../src/lib/dns', () => ({ queryTxtRecords: vi.fn().mockResolvedValue([]) }));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');
		const realMx = buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '1 MX')], true);

		const updated = await applyScanPostProcessing('example.com', [spfMissing(), realMx]);
		const spf = updated.find((r) => r.category === 'spf')!;

		expect(spf.findings[0].severity).toBe('critical');
		expect(spf.findings[0].metadata?.missingControl).toBe(true);
		expect(spf.score).toBe(0);
	});
});
