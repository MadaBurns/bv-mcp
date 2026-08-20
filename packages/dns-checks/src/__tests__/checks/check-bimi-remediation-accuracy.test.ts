// SPDX-License-Identifier: BUSL-1.1

/**
 * BIMI remediation prose must not give wrong purchasing advice or state a
 * false requirement. Score movement: NONE, by construction.
 *
 * Three defects in the `a=` (authority evidence) branch of check-bimi.ts:
 *
 *  B1  It names Entrust as a place to buy a VMC. Entrust STOPPED ISSUING VMCs
 *      on 2025-05-12 and sold its public-certificate business to Sectigo, so
 *      the copy sends a paying customer to a vendor that left the market.
 *
 *  B2  It says a VMC "is required by Gmail". FALSE since 2024-09-24: Gmail has
 *      displayed BIMI logos backed by a Common Mark Certificate (CMC) since
 *      then. Apple Mail DOES still require a VMC — that half is true and must
 *      survive the rewrite, or one false statement is merely swapped for
 *      another.
 *
 *  B3  A present `a=` tag is labelled "a Verified Mark Certificate (VMC)". The
 *      check sees a URL and nothing else; a CMC publishes an `a=` tag exactly
 *      as a VMC does, and distinguishing them would require fetching and
 *      parsing the certificate — a live PKI fetch this check has no budget
 *      for. The label must therefore be neutral.
 *
 *  B4  Guard: the `bimi` category score is IDENTICAL on both branches before
 *      and after the rewrite. Severities, titles' finding count and
 *      controlPresent/recordPresent are untouched; only detail prose changes.
 */

import { describe, expect, it, vi } from 'vitest';
import { checkBIMI } from '../../checks/check-bimi';
import type { CheckResult, DNSQueryFunction } from '../../types';

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => records[domain] ?? []);
}

const BIMI = 'default._bimi.example.com';
const DMARC = '_dmarc.example.com';

/** BIMI record with a valid logo but NO authority evidence (`a=`) tag. */
async function withoutAuthority(): Promise<CheckResult> {
	return checkBIMI(
		'example.com',
		createMockDNS({
			[BIMI]: ['v=BIMI1; l=https://example.com/logo.svg'],
			[DMARC]: ['v=DMARC1; p=reject'],
		}),
	);
}

/** BIMI record carrying an `a=` tag — which may be a VMC *or* a CMC. */
async function withAuthority(): Promise<CheckResult> {
	return checkBIMI(
		'example.com',
		createMockDNS({
			[BIMI]: ['v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem'],
			[DMARC]: ['v=DMARC1; p=reject'],
		}),
	);
}

/** Locate the authority-evidence finding without depending on its exact title. */
function authorityDetail(result: CheckResult): string {
	const finding = result.findings.find((f) => /authority evidence/i.test(f.title));
	expect(finding, 'an authority-evidence finding must exist').toBeDefined();
	return finding!.detail;
}

/**
 * Measured on the pre-change implementation (see the B4 block). These are the
 * numbers the changelog cites: prose-only means these do not move.
 */
const BIMI_SCORE_NO_AUTHORITY = 95;
const BIMI_SCORE_WITH_AUTHORITY = 100;

describe('checkBIMI — authority-evidence remediation prose is accurate', () => {
	// B1
	it('does not send customers to Entrust, which exited VMC issuance on 2025-05-12', async () => {
		const detail = authorityDetail(await withoutAuthority());
		expect(detail).not.toMatch(/Entrust/i);
	});

	// B2
	it('does not claim a VMC is required by Gmail (a CMC has worked there since 2024-09-24)', async () => {
		const detail = authorityDetail(await withoutAuthority());
		expect(detail).not.toMatch(/VMC[^.]*is required by Gmail/i);
	});

	it('states the true Gmail position: a VMC OR a CMC will display the logo', async () => {
		const detail = authorityDetail(await withoutAuthority());
		expect(detail).toMatch(/Common Mark Certificate|CMC/);
		expect(detail).toMatch(/Gmail/i);
	});

	// The true half of the old claim must survive the rewrite.
	it('KEEPS the still-true statement that Apple Mail requires a VMC', async () => {
		const detail = authorityDetail(await withoutAuthority());
		expect(detail).toMatch(/Apple Mail[^.]*VMC/i);
	});

	// B3
	// NOTE on the regex: the brief proposed /is a Verified Mark Certificate/i, but the
	// shipped copy reads "includes a Verified Mark Certificate (VMC) reference", so that
	// literal never matches and the test would pass while the defect stood. The defect is
	// naming the certificate TYPE at all from a bare URL, so that is what is asserted.
	it('does not assert a present a= tag is a VMC — the check cannot tell VMC from CMC by URL', async () => {
		const detail = authorityDetail(await withAuthority());
		expect(detail).not.toMatch(/Verified Mark Certificate/i);
		expect(detail).not.toMatch(/\bVMC\b/);
		expect(detail).toMatch(/mark certificate|authority evidence/i);
	});

	// B4 — the guard that makes "prose-only" a proven claim, not a belief.
	describe('score does not move (prose-only change)', () => {
		it('scores the a=-absent case identically to the pre-change implementation', async () => {
			const result = await withoutAuthority();
			expect(result.score).toBe(BIMI_SCORE_NO_AUTHORITY);
			expect(result.passed).toBe(true);
			expect(result.controlPresent).toBe(true);
			expect(result.recordPresent).toBe(true);
			expect(result.findings.find((f) => /authority evidence/i.test(f.title))!.severity).toBe('low');
		});

		it('scores the a=-present case identically to the pre-change implementation', async () => {
			const result = await withAuthority();
			expect(result.score).toBe(BIMI_SCORE_WITH_AUTHORITY);
			expect(result.passed).toBe(true);
			expect(result.controlPresent).toBe(true);
			expect(result.recordPresent).toBe(true);
			expect(result.findings.find((f) => /authority evidence/i.test(f.title))!.severity).toBe('info');
		});
	});
});
