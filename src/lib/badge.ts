// SPDX-License-Identifier: MIT

/**
 * SVG badge generator for DNS security grades.
 * Produces shields.io-style flat badges compatible with Cloudflare Workers runtime.
 */

/** Grade-to-color mapping for the badge right side */
const GRADE_COLORS: Record<string, string> = {
	'A+': '#4c1',
	A: '#4c1',
	'B+': '#a4a61d',
	B: '#a4a61d',
	'C+': '#dfb317',
	C: '#dfb317',
	'D+': '#fe7d37',
	D: '#fe7d37',
	E: '#e05d44',
	F: '#e05d44',
};

/** Color used for error badges */
const ERROR_COLOR = '#9f9f9f';

/**
 * Generate a shields.io-style flat SVG badge.
 *
 * @param label - Left side text (e.g., "DNS Security")
 * @param value - Right side text (e.g., "A+", "error")
 * @param color - Hex color for the right side background
 * @returns SVG string
 */
function renderBadge(label: string, value: string, color: string): string {
	// Approximate character widths for Verdana 11px
	const charWidth = 6.5;
	const padding = 10;
	const labelWidth = Math.round(label.length * charWidth + padding * 2);
	const valueWidth = Math.round(value.length * charWidth + padding * 2);
	const totalWidth = labelWidth + valueWidth;

	const labelX = labelWidth / 2;
	const valueX = labelWidth + valueWidth / 2;

	return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${value}">
  <title>${label}: ${value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="${labelX * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(labelWidth - padding) * 10}">${label}</text>
    <text x="${labelX * 10}" y="140" transform="scale(.1)" fill="#fff" textLength="${(labelWidth - padding) * 10}">${label}</text>
    <text aria-hidden="true" x="${valueX * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(valueWidth - padding) * 10}">${value}</text>
    <text x="${valueX * 10}" y="140" transform="scale(.1)" fill="#fff" textLength="${(valueWidth - padding) * 10}">${value}</text>
  </g>
</svg>`;
}

/**
 * Generate an SVG badge displaying a DNS security grade.
 *
 * @param grade - The letter grade (e.g., "A+", "B", "F")
 * @returns SVG string
 */
export function gradeBadge(grade: string): string {
	const color = GRADE_COLORS[grade] ?? ERROR_COLOR;
	return renderBadge('DNS Security', grade, color);
}

/**
 * Generate an SVG error badge.
 *
 * @returns SVG string with "error" as the value
 */
export function errorBadge(): string {
	return renderBadge('DNS Security', 'error', ERROR_COLOR);
}
