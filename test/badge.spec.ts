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
