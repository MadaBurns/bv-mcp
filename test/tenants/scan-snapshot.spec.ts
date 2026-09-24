// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit coverage for `toTenantScanSnapshot`'s `maturityStage` projection.
 *
 * SQ-170 found that on tenant-db-tenant-pilot-1 the ungraded-by-design rows
 * (NXDOMAIN / SERVFAIL / no-records domains) were persisted with
 * `maturity_stage: 0` — the same value the ladder uses for a genuinely
 * "Unprotected" domain — because `buildNonResolvingResult` /
 * `buildDnsBrokenResult` (src/tools/scan-domain.ts:353-386, :408) set
 * `maturity: { stage: 0, ... }` as a placeholder (no `indeterminate` flag,
 * since a dead domain never reaches the email-auth ladder), and the old
 * snapshot logic only nulled the stage when `indeterminate === true`. A
 * domain with no measured score has no measured posture, so the stage must
 * be `null` whenever `score.overall` is `null` — never `0`.
 */

import { describe, expect, it } from 'vitest';
import { toTenantScanSnapshot } from '../../src/tenants/scan-snapshot';
import type { ScanDomainResult } from '../../src/tools/scan-domain';

describe('toTenantScanSnapshot maturityStage', () => {
	it('nulls maturity_stage for an NXDOMAIN-shaped (ungraded) scan, even though the raw stage is 0', () => {
		// Mirrors buildNonResolvingResult's shape (src/tools/scan-domain.ts:353-386):
		// score.overall/grade are null, and maturity carries a placeholder stage 0
		// with no `indeterminate` flag.
		const result = {
			domain: 'does-not-resolve.example.com',
			score: {
				overall: null,
				grade: null,
				categoryScores: {},
				findings: [],
				summary: 'does-not-resolve.example.com does not resolve (NXDOMAIN)',
				evidence: { attempted: 0, completed: 0, ratio: 0 },
			},
			checks: [],
			maturity: {
				stage: 0,
				label: 'Does not resolve',
				description: 'does-not-resolve.example.com does not resolve (NXDOMAIN)',
				nextStep: 'Confirm the domain is registered and has authoritative nameservers.',
			},
			resolves: false,
		} as unknown as ScanDomainResult;

		expect(toTenantScanSnapshot(result)).toEqual({
			score: null,
			grade: null,
			maturityStage: null,
			findings: [],
		});
	});

	it('still persists maturity_stage 0 for a genuinely Unprotected scan (score present)', () => {
		// Mirrors the real "Stage 0 — Unprotected" branch (src/tools/scan/maturity-staging.ts:543-549):
		// SPF/DMARC were measured and are simply absent, and the scan produced a real score.
		const result = {
			domain: 'unprotected.example.com',
			score: {
				overall: 42,
				grade: 'D',
				categoryScores: {},
				findings: [],
				summary: 'scored',
				evidence: { attempted: 19, completed: 19, ratio: 1 },
			},
			checks: [],
			maturity: {
				stage: 0,
				label: 'Unprotected',
				description: 'No email authentication — any server can send email as this domain.',
				nextStep: 'Publish SPF and DMARC records to begin protecting your domain.',
			},
		} as unknown as ScanDomainResult;

		expect(toTenantScanSnapshot(result)).toEqual({
			score: 42,
			grade: 'D',
			maturityStage: 0,
			findings: [],
		});
	});
});
