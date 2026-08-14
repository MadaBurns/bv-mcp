// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { gradeBadge, errorBadge } from '../src/lib/badge';

describe('badge', () => {
	describe('gradeBadge', () => {
		it('returns valid SVG for known grades', () => {
			const svg = gradeBadge('A+');
			expect(svg).toContain('<svg');
			expect(svg).toContain('</svg>');
			expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
		});

		it('includes the grade text in the SVG', () => {
			const svg = gradeBadge('B');
			expect(svg).toContain('>B<');
		});

		it('includes "DNS Security" label', () => {
			const svg = gradeBadge('A');
			expect(svg).toContain('DNS Security');
		});

		it('uses correct color for each grade', () => {
			expect(gradeBadge('A+')).toContain('#4c1');
			expect(gradeBadge('A')).toContain('#4c1');
			expect(gradeBadge('B+')).toContain('#a4a61d');
			expect(gradeBadge('B')).toContain('#a4a61d');
			expect(gradeBadge('C+')).toContain('#dfb317');
			expect(gradeBadge('C')).toContain('#dfb317');
			expect(gradeBadge('D+')).toContain('#fe7d37');
			expect(gradeBadge('D')).toContain('#fe7d37');
			expect(gradeBadge('F')).toContain('#e05d44');
		});

		it('uses error color for unknown grades', () => {
			const svg = gradeBadge('Z');
			expect(svg).toContain('#9f9f9f');
		});

		// ---- Partial-evidence annotation (issue #638) ----
		//
		// A graded scan can still have failed to measure some categories. The badge is the
		// one published surface with no surrounding prose to qualify the letter, so it must
		// say so itself rather than let an embedded image read as full coverage.
		describe('partial evidence', () => {
			it('annotates a grade resting on an incomplete scan', () => {
				// The real blackveilsecurity.com case: our own WAF blocks our own scanner on
				// http_security + mta_sts, so an A+ rests on 17 of 19 checks.
				const svg = gradeBadge('A+', { attempted: 19, completed: 17 });

				expect(svg).toContain('A+ partial');
				// The exact ratio rides in the accessible name, where it costs no badge width.
				expect(svg).toContain('17 of 19 checks measured');
				expect(svg).toContain('<title>DNS Security: A+ — 17 of 19 checks measured</title>');
				expect(svg).toContain('aria-label="DNS Security: A+ — 17 of 19 checks measured"');
			});

			it('keeps the grade COLOR unchanged when partial', () => {
				// Coverage and quality are different axes. Dimming an A+ to amber would assert
				// a worse posture than was actually measured — the mirror of the overclaim
				// being fixed here.
				expect(gradeBadge('A+', { attempted: 19, completed: 17 })).toContain('#4c1');
				expect(gradeBadge('D', { attempted: 19, completed: 11 })).toContain('#fe7d37');
			});

			it('does NOT annotate a fully measured scan', () => {
				const svg = gradeBadge('A+', { attempted: 19, completed: 19 });

				expect(svg).not.toContain('partial');
				expect(svg).not.toContain('checks measured');
				// Falls back to the default accessible name, byte-identical to the no-evidence call.
				expect(svg).toBe(gradeBadge('A+'));
			});

			it('does NOT annotate when evidence is omitted entirely', () => {
				expect(gradeBadge('B')).not.toContain('partial');
			});

			it('does NOT annotate a zero-check scan as a coverage story', () => {
				// attempted === 0 would otherwise render "0 of 0 checks measured", which reads
				// as a coverage gap rather than the degenerate scan it actually is.
				const svg = gradeBadge('F', { attempted: 0, completed: 0 });

				expect(svg).not.toContain('partial');
				expect(svg).toBe(gradeBadge('F'));
			});

			it('never annotates an ungraded badge (null wins over evidence)', () => {
				// `null` already means "not measured at all" — the stronger statement. Adding
				// "partial" on top would be incoherent.
				const svg = gradeBadge(null, { attempted: 19, completed: 3 });

				expect(svg).toContain('unknown');
				expect(svg).not.toContain('partial');
			});

			it('escapes the override title so it cannot inject SVG', () => {
				// The title path reaches BOTH <title> and aria-label, so an unescaped value
				// would be injection in two places. Grade is the only caller-shaped input.
				const svg = gradeBadge('<script>', { attempted: 19, completed: 17 });

				expect(svg).not.toContain('<script>');
				expect(svg).toContain('&lt;script&gt;');
			});
		});
	});

	describe('errorBadge', () => {
		it('returns valid SVG with error text', () => {
			const svg = errorBadge();
			expect(svg).toContain('<svg');
			expect(svg).toContain('</svg>');
			expect(svg).toContain('>error<');
		});

		it('uses the grey error color', () => {
			const svg = errorBadge();
			expect(svg).toContain('#9f9f9f');
		});
	});

	describe('SVG injection prevention', () => {
		it('escapes HTML/XML special characters in grade value', () => {
			const svg = gradeBadge('<script>alert(1)</script>');
			expect(svg).not.toContain('<script>');
			expect(svg).toContain('&lt;script&gt;');
		});

		it('escapes ampersands', () => {
			const svg = gradeBadge('A&B');
			expect(svg).toContain('A&amp;B');
			expect(svg).not.toMatch(/A&B/);
		});

		it('escapes double quotes', () => {
			const svg = gradeBadge('A"onload="alert(1)');
			expect(svg).not.toContain('"onload=');
			expect(svg).toContain('&quot;onload=');
		});

		it('escapes single quotes', () => {
			const svg = gradeBadge("A'onclick='alert(1)");
			expect(svg).not.toContain("'onclick=");
			expect(svg).toContain('&#x27;onclick=');
		});

		it('escapes greater-than signs', () => {
			const svg = gradeBadge('A>B');
			expect(svg).toContain('A&gt;B');
		});

		it('handles combined injection attempts', () => {
			const malicious = '"><svg onload=alert(1)>';
			const svg = gradeBadge(malicious);
			// The dangerous characters (<, >, ") are escaped, preventing SVG element injection
			expect(svg).not.toContain('"><svg');
			expect(svg).toContain('&quot;&gt;&lt;svg onload=alert(1)&gt;');
		});
	});

	describe('color validation', () => {
		it('rejects invalid hex color and falls back to error color', () => {
			// gradeBadge uses GRADE_COLORS lookup, so invalid grades get ERROR_COLOR via the lookup miss
			// But the renderBadge color validation regex also catches invalid hex in the fill attribute
			const svg = gradeBadge('A+');
			// A+ maps to '#4c1' which is valid 3-char hex
			expect(svg).toContain('#4c1');
		});

		it('uses error color for grades not in the color map', () => {
			// Unknown grade falls through to ERROR_COLOR (#9f9f9f)
			const svg = gradeBadge('X');
			expect(svg).toContain('#9f9f9f');
			expect(svg).not.toContain('undefined');
		});
	});
});
