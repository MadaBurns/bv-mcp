// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-287 item 2 — the maturity ladder must read the DMARC policy from the structured
 * `dmarcPolicy` metadata the check emits, not infer `p=reject` from "the finding title
 * does not say none/quarantine".
 *
 * The old inference staged every DMARC result that merely LACKED those two titles as
 * `reject`: multiple records ("no valid policy"), a record with no `p=` tag, and an
 * invalid `p=` value all reached Stage 4 "Hardened" (a zero-score category was only
 * ever capped down to "Enforcing (score-capped)" afterwards). These cases run the REAL
 * `checkDMARC` over each record shape so the metadata is exactly what production emits.
 */

import { describe, expect, it, vi } from 'vitest';
import { checkDMARC } from '@blackveil/dns-checks';
import { computeMaturityStage } from '../src/tools/scan/maturity-staging';
import { buildCheckResult, createFinding } from '../src/lib/scoring';
import type { CheckResult } from '../src/lib/scoring';

/** TXT stub: answers only for the names given, NODATA elsewhere (NXDOMAIN would halt the tree walk). */
async function dmarcFor(records: string[], domain = 'example.com'): Promise<CheckResult> {
	const stub = vi.fn(async (name: string) => (name === `_dmarc.${domain}` ? records : []));
	return checkDMARC(domain, stub);
}

/** A mail domain that would reach Stage 4 on every OTHER signal, so DMARC policy alone decides 3/4 vs below. */
function hardenedRest(): CheckResult[] {
	return [
		buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')], true, true),
		buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'Found selectors')], true, true),
		buildCheckResult('mta_sts', [createFinding('mta_sts', 'MTA-STS configured', 'info', 'ok')], true, true),
		buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC enabled', 'info', 'ok')], true, true),
		buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '1 MX')], true, true),
	];
}

describe('SQ-287 maturity ladder — DMARC policy comes from structured metadata', () => {
	it('control: a real p=reject record still stages Stage 4 Hardened', async () => {
		const dmarc = await dmarcFor(['v=DMARC1; p=reject; rua=mailto:r@example.com']);
		const stage = computeMaturityStage([...hardenedRest(), dmarc]);
		expect(stage.stage).toBe(4);
	});

	it('control: a real p=quarantine record stages Enforcing or better', async () => {
		const dmarc = await dmarcFor(['v=DMARC1; p=quarantine; rua=mailto:r@example.com']);
		expect(computeMaturityStage([...hardenedRest(), dmarc]).stage).toBeGreaterThanOrEqual(3);
	});

	it('control: a real p=none record stages Monitoring/Basic, never enforcing', async () => {
		const dmarc = await dmarcFor(['v=DMARC1; p=none; rua=mailto:r@example.com']);
		expect(computeMaturityStage([...hardenedRest(), dmarc]).stage).toBeLessThan(3);
	});

	it('multiple DMARC records (no valid policy) do NOT stage as enforcing', async () => {
		const dmarc = await dmarcFor(['v=DMARC1; p=reject', 'v=DMARC1; p=reject; rua=mailto:r@example.com']);
		expect(computeMaturityStage([...hardenedRest(), dmarc]).stage).toBeLessThan(3);
	});

	it('a DMARC record with no p= tag does NOT stage as enforcing', async () => {
		const dmarc = await dmarcFor(['v=DMARC1; rua=mailto:r@example.com']);
		expect(computeMaturityStage([...hardenedRest(), dmarc]).stage).toBeLessThan(3);
	});

	it('a DMARC record with an invalid p= value does NOT stage as enforcing', async () => {
		const dmarc = await dmarcFor(['v=DMARC1; p=banana; rua=mailto:r@example.com']);
		expect(computeMaturityStage([...hardenedRest(), dmarc]).stage).toBeLessThan(3);
	});

	describe('web_only ladder', () => {
		const webOnlyRest = (): CheckResult[] => [
			buildCheckResult('ssl', [createFinding('ssl', 'HTTPS reachable', 'info', 'ok')], true, true),
			buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC enabled', 'info', 'ok')], true, true),
			buildCheckResult('mx', [createFinding('mx', 'No MX', 'info', 'no mail')], false, false),
			// SPF absent: the anti-spoof signal must come from DMARC alone in these cases.
			buildCheckResult('spf', [createFinding('spf', 'No SPF record found', 'critical', 'none', { missingControl: true })], false, false),
		];

		it('control: a real p=reject record is anti-spoof evidence (Stage 3 with SSL + DNSSEC)', async () => {
			const dmarc = await dmarcFor(['v=DMARC1; p=reject']);
			expect(computeMaturityStage([...webOnlyRest(), dmarc], 'web_only').stage).toBe(3);
		});

		it.each([
			['multiple records', ['v=DMARC1; p=reject', 'v=DMARC1; p=reject']],
			['no p= tag', ['v=DMARC1; rua=mailto:r@example.com']],
			['invalid p= value', ['v=DMARC1; p=banana']],
		])('%s is NOT read as DMARC reject anti-spoof evidence', async (_name, records) => {
			const dmarc = await dmarcFor(records);
			// Without anti-spoof the domain tops out at Stage 2 (SSL + DNSSEC, no anti-spoof).
			expect(computeMaturityStage([...webOnlyRest(), dmarc], 'web_only').stage).toBeLessThan(3);
		});
	});
});
