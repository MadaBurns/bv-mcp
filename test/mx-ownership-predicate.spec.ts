import { describe, expect, it } from 'vitest';
import { attachMxOwnershipPredicateReporting, describeMxOwnershipPredicate } from '../src/lib/mx-ownership-predicate';
import { buildCheckResult, createFinding } from '../src/lib/scoring';

describe('MX ownership prefilter reporting', () => {
	const describeMx = (
		candidateMx?: readonly string[],
		candidateProbeDegraded = false,
		seedMx: readonly string[] = ['gateway.example.net'],
	) => describeMxOwnershipPredicate({ seedDomain: 'example.com', seedMx, candidateMx, candidateProbeDegraded });

	it('does not infer candidate applicability from external seed MX', () => {
		expect(describeMx(['mail.example.com.'])).toEqual({ candidatePrefilter: 'satisfied', seedMxPlacement: 'outside_seed_bailiwick' });
		expect(describeMx(['gateway.example.net'])).toEqual({
			candidatePrefilter: 'not_satisfied_external_mx',
			seedMxPlacement: 'outside_seed_bailiwick',
		});
	});
	it('requires every candidate MX to be inside the seed registrable bailiwick', () => {
		expect(describeMx(['mail.example.com', 'gateway.example.net']).candidatePrefilter).toBe('not_satisfied_external_mx');
		expect(describeMx(['mailexample.com']).candidatePrefilter).toBe('not_satisfied_external_mx');
	});
	it('separates measured no-mail from missing, degraded and null-MX input', () => {
		expect(describeMx([]).candidatePrefilter).toBe('not_satisfied_no_real_mx');
		for (const input of [undefined, ['.'], ['not a host'], ['mail..example.com'], ['-mail.example.com']])
			expect(describeMx(input).candidatePrefilter).toBe('unknown');
		expect(describeMx([], true).candidatePrefilter).toBe('unknown');
		expect(describeMx(['mail.example.com'], true).candidatePrefilter).toBe('unknown');
	});
	it('reports seed placement without claiming measurement of an empty seed query', () => {
		expect(describeMx([], false, []).seedMxPlacement).toBe('unknown');
		expect(describeMx([], false, ['.']).seedMxPlacement).toBe('unknown');
		expect(describeMx([], false, ['mail.example.com']).seedMxPlacement).toBe('inside_seed_bailiwick');
		expect(describeMx([], false, ['mail.example.com', 'gateway.example.net']).seedMxPlacement).toBe('mixed');
	});
	it('serializes only observations while preserving findings, verdict, confidence and score', () => {
		const findings = [
			createFinding('lookalikes', 'Observed candidate', 'info', 'Observation', {
				lookalikeDomain: 'candidate.example.test',
				ownershipVerdict: 'third_party',
				attributionConfidence: 0.2,
			}),
			createFinding('lookalikes', 'Status', 'info', 'No measured candidate'),
		];
		const before = structuredClone(buildCheckResult('lookalikes', findings));
		attachMxOwnershipPredicateReporting(
			findings,
			[{ domain: 'candidate.example.test', mxExchanges: ['gateway.example.net'], probeDegraded: false }],
			'example.com',
			['gateway.example.net'],
		);
		const after = JSON.parse(JSON.stringify(buildCheckResult('lookalikes', findings)));
		expect(after.findings[0].metadata.mxOwnershipPredicate.candidatePrefilter).toBe('not_satisfied_external_mx');
		delete after.findings[0].metadata.mxOwnershipPredicate;
		expect(after).toEqual(before);
	});
});
