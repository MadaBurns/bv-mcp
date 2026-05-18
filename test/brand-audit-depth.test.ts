// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { buildBrandAuditDepthSummary } from '../src/lib/brand-audit-depth';

describe('buildBrandAuditDepthSummary', () => {
	it('summarizes candidate, signal, and registrar coverage without brand-specific fixtures', () => {
		const summary = buildBrandAuditDepthSummary({
			candidateUniverse: {
				seeded: 12,
				probed: 10,
				surfaced: 3,
				dropped: {
					belowConfidence: 4,
					corroborationGate: 2,
					invalidDomain: 1,
				},
				sources: {
					tld_sweep: 6,
					alias_tld_sweep: 2,
					markov: 2,
					active_lookalike: 2,
				},
			},
			signalStatus: {
				ns: { status: 'ok' },
				san: { status: 'timeout' },
				txt_verification: { status: 'ok' },
			},
			registrarSources: ['rdap', 'rdap', 'whois', 'unknown'],
		});

		expect(summary.candidateUniverse).toEqual({
			seeded: 12,
			probed: 10,
			surfaced: 3,
			dropped: {
				belowConfidence: 4,
				corroborationGate: 2,
				invalidDomain: 1,
			},
			sources: {
				tld_sweep: 6,
				alias_tld_sweep: 2,
				markov: 2,
				active_lookalike: 2,
			},
		});
		expect(summary.signalCoverage).toEqual({
			requested: 3,
			ok: 2,
			failed: 0,
			partial: 0,
			timeout: 1,
			skipped: 0,
		});
		expect(summary.registrarCoverage).toEqual({
			total: 4,
			rdap: 2,
			whois: 1,
			redacted: 0,
			notfound: 0,
			unknown: 1,
			knownRatio: 0.75,
		});
		expect(summary.warnings).toContain('SAN signal timed out; certificate-derived sibling coverage is incomplete.');
	});
});
