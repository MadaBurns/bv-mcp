// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: `/badge/:domain` and the `scan_domain` report show a customer the
 * SAME letter for the same domain.
 *
 * Two grade scales legitimately coexist (v3.26.0+, #461) — the canonical 9-band
 * `scoreToGrade` is internal/SSOT, the NIST 6-band `nistScoreToGrade` is what a
 * customer is shown. The defect class is not their coexistence; it is two
 * CUSTOMER-VISIBLE surfaces reading different scales and disagreeing on screen.
 *
 * That has now happened twice. #640: the maturity cap read the 9-band while the
 * report displayed the 6-band, so github.com at 67 printed grade D beside
 * "Stage 4 — Hardened". And the badge rendered `score.grade` — the 9-band letter
 * — so the same domain showed C on its badge and D in its report.
 *
 * Both surfaces now consume `displayGradeFor`. These cases pin the scores where
 * the two scales genuinely DISAGREE, because those are the only scores at which
 * a regression is observable — a test built on scores where the scales happen to
 * agree would pass against the very bug it exists to catch.
 */
import { describe, expect, it } from 'vitest';
import { gradeBadge } from '../src/lib/badge';
import { displayGradeFor } from '../src/lib/ungraded-display';
import { nistScoreToGrade, scoreToGrade } from '../src/lib/scoring';

/** Scores where the internal 9-band and the displayed 6-band letters differ. */
const DIVERGENT_SCORES = [
	{ score: 93, canonical: 'A+', display: 'A' },
	{ score: 88, canonical: 'A', display: 'B' },
	{ score: 78, canonical: 'B', display: 'C' },
	{ score: 67, canonical: 'C', display: 'D' }, // the #640 / github.com case
	{ score: 55, canonical: 'D', display: 'F' },
];

describe('badge ↔ report display-grade parity', () => {
	it('the chosen fixtures really are divergent (guards the guard)', () => {
		// If a future scale change made these agree, every assertion below would
		// still pass while testing nothing. Assert the premise explicitly.
		for (const { score, canonical, display } of DIVERGENT_SCORES) {
			expect(scoreToGrade(score)).toBe(canonical);
			expect(nistScoreToGrade(score)).toBe(display);
			expect(canonical).not.toBe(display);
		}
	});

	it('renders the DISPLAY letter, never the internal one', () => {
		for (const { score, canonical, display } of DIVERGENT_SCORES) {
			// `grade` carries the canonical letter exactly as the engine emits it — the
			// value the badge route used to render directly.
			const svg = gradeBadge(displayGradeFor({ overall: score, grade: canonical }));

			expect(svg).toContain(`>${display}<`);
			expect(svg).not.toContain(`>${canonical}<`);
		}
	});

	it('badge letter equals the report letter across the whole 0–100 range', () => {
		// The report computes its letter through the same `displayGradeFor`; comparing
		// against `nistScoreToGrade` directly pins the value both must agree on, so this
		// fails if EITHER surface starts re-deriving its own.
		for (let score = 0; score <= 100; score++) {
			expect(displayGradeFor({ overall: score, grade: scoreToGrade(score) })).toBe(nistScoreToGrade(score));
		}
	});

	it('abstains rather than fabricating a letter for an ungraded scan', () => {
		// Both halves of the guard are load-bearing: a null score and a null grade each
		// mean "never measured". Mapping either onto nistScoreToGrade(0) would publish a
		// fabricated F for a domain that does not resolve.
		expect(displayGradeFor({ overall: null, grade: null })).toBeNull();
		expect(displayGradeFor({ overall: null, grade: 'F' })).toBeNull();
		expect(displayGradeFor({ overall: 0, grade: null })).toBeNull();

		expect(gradeBadge(displayGradeFor({ overall: null, grade: null }))).toContain('unknown');
	});

	it('treats a measured zero as a real grade, not an abstention', () => {
		// score 0 with a real grade is a MEASUREMENT — only null means unmeasured.
		expect(displayGradeFor({ overall: 0, grade: 'F' })).toBe('F');
		expect(gradeBadge(displayGradeFor({ overall: 0, grade: 'F' }))).toContain('>F<');
	});
});
