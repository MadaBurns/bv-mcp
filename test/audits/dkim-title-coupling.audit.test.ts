// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit — DKIM "not discovered" finding-metadata coupling (SQ-74).
 *
 * src/tools/check-dkim.ts's `applyProviderDkimContext` used to identify the
 * @blackveil/dns-checks package's "No DKIM records found among tested selectors"
 * finding by matching its TITLE via `/No DKIM records found/i`. That was a
 * brittle cross-package string coupling: if the package ever reworded the
 * title, the regex would silently stop matching and the provider-informed
 * downgrade would quietly stop firing in production — no error, no failing
 * test, just a `high` finding that should have been softened to `medium`.
 *
 * SQ-74 broke that coupling: the finding is now identified STRUCTURALLY, via
 * `severity === 'high' && metadata.detectionMethod === 'selector-probing'` —
 * a field the package's check-dkim.ts sets specifically on this finding, and
 * on no other `high`-severity dkim finding ("Malformed DKIM key", "DKIM keys
 * revoked" carry no `detectionMethod` at all).
 *
 * This audit pins THAT coupling, the same way
 * test/audits/mta-sts-title-coupling.audit.test.ts pins its own: it drives the
 * REAL production wrapper (`checkDkim`, with zero DKIM selectors resolving —
 * the genuine "not discovered" condition) and asserts the emitted finding
 * carries the exact severity + metadata shape `applyProviderDkimContext`
 * matches on. If the package ever renames or removes `detectionMethod` (or
 * changes its value) for this finding, this audit goes red, forcing a
 * maintainer to update the matcher in `applyProviderDkimContext` too — instead
 * of the downgrade silently going dark.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../../src/lib/dns';
import { setupFetchMock, createDohResponse } from '../helpers/dns-mock';

// SSOT-coupling tripwire: this MUST match what applyProviderDkimContext in
// src/tools/check-dkim.ts matches on. If the @blackveil/dns-checks package
// changes this finding's shape, update BOTH.
const EXPECTED_TITLE = 'No DKIM records found among tested selectors';
const EXPECTED_DETECTION_METHOD = 'selector-probing';

const { restore } = setupFetchMock();
afterEach(() => restore());

/** No DKIM record answers for any selector — the genuine (non-error) "not discovered" condition. */
function mockNoDkimRecords() {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const nameMatch = url.match(/name=([^&]+)/);
		const queriedName = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
		return Promise.resolve(createDohResponse([{ name: queriedName, type: RecordType.TXT }], []));
	});
}

describe('audit — DKIM "not discovered" finding-metadata coupling (SQ-74 structural tripwire)', () => {
	async function run(domain = 'example.com') {
		// Dynamic import inside the test fn — bind the wrapper AFTER the fetch mock is installed.
		const { checkDkim, applyProviderDkimContext } = await import('../../src/tools/check-dkim');
		return { checkDkim, applyProviderDkimContext, result: await checkDkim(domain) };
	}

	it(`emits the EXACT title "${EXPECTED_TITLE}" at high severity with detectionMethod "${EXPECTED_DETECTION_METHOD}" on a genuine not-discovered probe`, async () => {
		mockNoDkimRecords();
		const { result } = await run();

		const notFound = result.findings.find((f) => f.severity === 'high' && f.metadata?.detectionMethod === EXPECTED_DETECTION_METHOD);
		expect(notFound, 'no finding matched the structural shape applyProviderDkimContext relies on').toBeDefined();
		expect(notFound!.title).toBe(EXPECTED_TITLE);
	});

	it('applyProviderDkimContext actually downgrades the real production finding for a high-confidence provider', async () => {
		mockNoDkimRecords();
		const { applyProviderDkimContext, result } = await run();

		// Non-vacuity: prove the real wrapper produced the condition this audit exists to guard,
		// not that the downgrade below is a no-op passing for the wrong reason.
		expect(result.findings.some((f) => f.severity === 'high')).toBe(true);

		const adjusted = applyProviderDkimContext(result, 'google workspace');
		expect(adjusted.findings.some((f) => f.severity === 'medium' && f.metadata?.detectionMethod === 'provider-implied')).toBe(true);
		expect(adjusted.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('DISCRIMINATES: a same-severity dkim finding WITHOUT the detectionMethod tag is left untouched', () => {
		// Positive control — same doctrine as the sibling audit: a guard never seen to fail is not
		// evidence. Reproduces the two OTHER high-severity dkim findings' real shape (no
		// detectionMethod at all), so a regression that makes applyProviderDkimContext match on
		// severity alone (too broad) would be caught here.
		const other = {
			category: 'dkim' as const,
			title: 'DKIM keys revoked',
			severity: 'high' as const,
			detail: 'All observed DKIM selector(s) have revoked keys.',
		};
		expect(other.severity === 'high' && (other as { metadata?: { detectionMethod?: string } }).metadata?.detectionMethod).toBeFalsy();
	});
});
