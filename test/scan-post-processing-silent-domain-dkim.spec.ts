// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-535 — a domain that neither receives mail (null MX) nor sends it (SPF `-all`
 * with no senders) and revokes every DKIM key (`v=DKIM1; p=`, often a wildcard
 * `*._domainkey`) has the recommended silent-domain posture. An empty `p=` cannot
 * verify any signature, so it protects the name rather than exposing it.
 *
 * `scan_domain` already reported the dkim category N/A for such a domain (non_mail
 * profile), yet still listed "[HIGH] DKIM keys revoked": the no-send downgrade was
 * gated off for null-MX domains, and its missing-record matcher never matched the
 * revoked/keyless titles anyway.
 *
 * The DKIM result here comes from the REAL `checkDKIM`, so a change to the titles it
 * emits fails this spec instead of silently re-arming the HIGH.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { checkDKIM } from '@blackveil/dns-checks';
import {
	type CheckResult,
	buildCheckResult,
	createFinding,
	computeProfileAwareScanScore,
	computeScanScore,
	detectDomainContext,
} from '../src/lib/scoring';

/** Every selector resolves to a revoked key, as a wildcard `*._domainkey` does. */
async function revokedEverywhereDkim(): Promise<CheckResult> {
	const queryDNS = async (name: string, type: string) => (type === 'TXT' && name.includes('._domainkey.') ? ['v=DKIM1; p='] : []);
	return checkDKIM('example.com', queryDNS);
}

const nullMx = (): CheckResult =>
	buildCheckResult('mx', [createFinding('mx', 'Null MX record (RFC 7505)', 'info', 'Domain declares it does not accept email.')], false);
const realMx = (): CheckResult => buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '1 MX')], true);
const noSendSpf = (): CheckResult =>
	buildCheckResult(
		'spf',
		[createFinding('spf', 'SPF hard fail with no senders', 'info', 'v=spf1 -all', { noSendPolicy: true })],
		true,
		true,
	);
const ordinarySpf = (): CheckResult =>
	buildCheckResult('spf', [createFinding('spf', 'SPF record found', 'info', 'v=spf1 include:_spf.example.net -all')], true, true);

const elevated = (result: CheckResult | undefined) =>
	(result?.findings ?? []).filter((f) => f.severity === 'high' || f.severity === 'critical').map((f) => f.title);

describe('SQ-535 silent domain — revoked DKIM keys are not a HIGH', () => {
	beforeEach(() => {
		vi.resetModules();
		vi.doMock('../src/lib/dns', () => ({ queryTxtRecords: vi.fn().mockResolvedValue([]) }));
	});
	afterEach(() => {
		vi.doUnmock('../src/lib/dns');
	});

	it('control: the real check emits the HIGH aggregate for an all-revoked selector set', async () => {
		const dkim = await revokedEverywhereDkim();
		expect(elevated(dkim)).toEqual(['DKIM keys revoked']);
	});

	it('null MX + SPF -all: the revoked-key aggregate is downgraded to info, not applicable', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');
		const updated = await applyScanPostProcessing('example.com', [noSendSpf(), nullMx(), await revokedEverywhereDkim()]);
		const dkim = updated.find((r) => r.category === 'dkim');

		expect(elevated(dkim)).toEqual([]);
		const revoked = dkim!.findings.find((f) => f.title === 'DKIM keys revoked')!;
		expect(revoked.severity).toBe('info');
		expect(revoked.detail).toContain('neither sends nor receives mail');
	});

	it('preserves evidence for the score-bearing Worker policy: real post-processing can change a non_mail grade despite report-level N/A', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');
		const original = [noSendSpf(), nullMx(), await revokedEverywhereDkim()];
		const beforeContext = detectDomainContext(original);
		const before = computeScanScore(original, beforeContext);
		const adjusted = await applyScanPostProcessing('example.com', original);
		const afterContext = detectDomainContext(adjusted);
		const after = computeScanScore(adjusted, afterContext);

		// This is scan_domain's post-processing -> context detection -> canonical score sequence, with real metadata.
		expect(beforeContext.profile).toBe('non_mail');
		expect(afterContext.profile).toBe('non_mail');
		expect(original.find((result) => result.category === 'dkim')!.score).toBe(75);
		expect(adjusted.find((result) => result.category === 'dkim')!.score).toBe(100);
		expect({ overall: before.overall, grade: before.grade }).toEqual({ overall: 81, grade: 'B' });
		expect({ overall: after.overall, grade: after.grade }).toEqual({ overall: 90, grade: 'A' });

		// Zero-weight web_only remains the score-neutral control; severity still changes through the same helper.
		const webBefore = computeProfileAwareScanScore(original, { profile: 'web_only' });
		const webAfter = computeProfileAwareScanScore(adjusted, { profile: 'web_only' });
		expect(webAfter.score.overall).toBe(webBefore.score.overall);
		expect(webAfter.score.grade).toBe(webBefore.score.grade);
	});

	it('a single revoked selector on a silent domain is downgraded too', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');
		const queryDNS = async (name: string, type: string) =>
			type === 'TXT' && name === 'default._domainkey.example.com' ? ['v=DKIM1; p='] : [];
		const single = await checkDKIM('example.com', queryDNS);
		expect(elevated(single).length).toBeGreaterThan(0);

		const updated = await applyScanPostProcessing('example.com', [noSendSpf(), nullMx(), single]);
		expect(elevated(updated.find((r) => r.category === 'dkim'))).toEqual([]);
	});

	it('null MX WITHOUT a no-send SPF keeps the HIGH (the domain may still send)', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');
		const updated = await applyScanPostProcessing('example.com', [ordinarySpf(), nullMx(), await revokedEverywhereDkim()]);
		expect(elevated(updated.find((r) => r.category === 'dkim'))).toEqual(['DKIM keys revoked']);
	});

	it('a receiving domain (real MX) + SPF -all is unchanged — that case is scored and out of scope', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');
		const updated = await applyScanPostProcessing('example.com', [noSendSpf(), realMx(), await revokedEverywhereDkim()]);
		expect(elevated(updated.find((r) => r.category === 'dkim'))).toEqual(['DKIM keys revoked']);
	});
});
