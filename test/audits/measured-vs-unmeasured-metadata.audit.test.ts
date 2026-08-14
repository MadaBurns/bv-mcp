// SPDX-License-Identifier: BUSL-1.1

/**
 * AUDIT: a finding may not claim both "we measured and it is absent" and "we
 * could not measure".
 *
 * `missingControl: true` zeroes its category — it asserts a MEASUREMENT: the
 * control was looked for and is not there. `inconclusive: true` / `errorKind`
 * assert the opposite: the probe never produced an answer, so the category must
 * be EXCLUDED (renormalised, shown n/a) rather than scored 0.
 *
 * The same contradiction has now shipped four separate times — WAF-intercepted
 * checks (#646), the MTA-STS policy fetch (#638), `check_http_security`'s
 * total-budget timeout (#662) and `brand_discovery`'s all-signals-failed and
 * zero-candidate paths (#670). Every instance was written by someone reaching for
 * "make the score reflect that this is bad" and picking the flag that happened to
 * do it, and every instance is LATENT: `checkStatus` is what actually drives
 * exclusion today, so the wrong flag sits harmless until that precedence shifts.
 * Latent is why they accumulated — nothing failed, so nothing objected.
 *
 * This audit objects. It reads source rather than behaviour deliberately: the
 * contradiction is a claim about what a call site MEANS, and a runtime test can
 * only catch the paths a fixture happens to reach.
 */

import { describe, it, expect } from 'vitest';

interface GlobbingImportMeta {
	glob(patterns: string[], options: { eager: true; query: '?raw'; import: 'default' }): Record<string, string>;
}

const SOURCES = (import.meta as unknown as GlobbingImportMeta).glob(
	['../../src/**/*.ts', '../../packages/dns-checks/src/**/*.ts'],
	{ eager: true, query: '?raw', import: 'default' },
);

/**
 * Remove comments while preserving string/template contents and total length is
 * irrelevant here — only that a `missingControl: true` written inside a comment
 * (this repo has several, explaining why a check DECLINES to set the flag) is not
 * mistaken for a call site. CLAUDE.md warns about exactly this grep hazard.
 */
function stripComments(src: string): string {
	let out = '';
	let quote: string | null = null;
	for (let i = 0; i < src.length; i++) {
		const c = src[i];
		const next = src[i + 1];
		if (quote) {
			out += c;
			if (c === '\\') {
				out += next ?? '';
				i++;
			} else if (c === quote) quote = null;
			continue;
		}
		if (c === "'" || c === '"' || c === '`') {
			quote = c;
			out += c;
			continue;
		}
		if (c === '/' && next === '/') {
			while (i < src.length && src[i] !== '\n') i++;
			out += '\n';
			continue;
		}
		if (c === '/' && next === '*') {
			i += 2;
			while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++;
			i++;
			continue;
		}
		out += c;
	}
	return out;
}

/**
 * Extract the brace-delimited object literal that starts at `open`, respecting
 * nesting and skipping over string/template contents so a `}` inside prose (very
 * common in these detail strings) does not terminate the literal early.
 */
function readObjectLiteral(src: string, open: number): string {
	let depth = 0;
	let i = open;
	let quote: string | null = null;
	for (; i < src.length; i++) {
		const c = src[i];
		if (quote) {
			if (c === '\\') i++;
			else if (c === quote) quote = null;
			continue;
		}
		if (c === "'" || c === '"' || c === '`') {
			quote = c;
			continue;
		}
		if (c === '{') depth++;
		else if (c === '}') {
			depth--;
			if (depth === 0) return src.slice(open, i + 1);
		}
	}
	return src.slice(open, i);
}

/** Every object literal in the file that sets `missingControl: true`. */
function literalsAssertingMissingControl(src: string): string[] {
	const out: string[] = [];
	const marker = /missingControl:\s*true/g;
	let m: RegExpExecArray | null;
	while ((m = marker.exec(src)) !== null) {
		// Walk back to the opening brace of the literal containing this property.
		let depth = 0;
		let start = -1;
		for (let i = m.index; i >= 0; i--) {
			const c = src[i];
			if (c === '}') depth++;
			else if (c === '{') {
				if (depth === 0) {
					start = i;
					break;
				}
				depth--;
			}
		}
		if (start >= 0) out.push(readObjectLiteral(src, start));
	}
	return out;
}

describe('audit: a finding cannot be both measured-absent and unmeasured', () => {
	it('no metadata literal sets missingControl alongside inconclusive or errorKind', () => {
		const violations: string[] = [];

		for (const [path, src] of Object.entries(SOURCES)) {
			// Tests legitimately construct contradictory fixtures to assert we reject them.
			if (path.includes('__tests__') || path.includes('.test.') || path.includes('.spec.')) continue;

			for (const literal of literalsAssertingMissingControl(stripComments(src))) {
				const alsoInconclusive = /\binconclusive:\s*true/.test(literal);
				const alsoErrorKind = /\berrorKind:/.test(literal);
				if (alsoInconclusive || alsoErrorKind) {
					const conflicting = [alsoInconclusive && 'inconclusive: true', alsoErrorKind && 'errorKind'].filter(Boolean).join(' + ');
					violations.push(`${path.replace('../../', '')}: missingControl: true alongside ${conflicting}`);
				}
			}
		}

		expect(
			violations,
			[
				'A finding claimed BOTH that the control was measured-and-absent and that it could not be measured.',
				'',
				'  missingControl: true  → zeroes the category. Only for "we looked, it is not there".',
				'  inconclusive / errorKind → excludes the category. For "the probe never answered".',
				'',
				'If the intent was to make an unmeasured check score badly, that is what checkStatus',
				"is for — see buildDnsErrorResult in src/lib/dns-error-result.ts for the shape ('error'",
				'+ score 0 + passed false + partial true). Do not reach for missingControl to get there.',
			].join('\n'),
		).toEqual([]);
	});

	it('the detector actually fires (guards the guard)', () => {
		// A contradictory literal of the exact shape #670 removed from brand_discovery.
		const contrived = `
			createFinding('brand_discovery', 'Discovery could not complete', 'high', 'All signals failed', {
				missingControl: true,
				confidence: 'heuristic',
				errorKind: 'dns_error',
			}),
		`;
		const found = literalsAssertingMissingControl(contrived);
		expect(found).toHaveLength(1);
		expect(/\berrorKind:/.test(found[0])).toBe(true);
	});

	it('does not flag a legitimate missingControl literal', () => {
		// A real measured absence: no errorKind, no inconclusive.
		const legitimate = `
			createFinding('mx', 'No MX records found', 'high', 'The domain publishes no MX records.', {
				missingControl: true,
				confidence: 'deterministic',
			}),
		`;
		const found = literalsAssertingMissingControl(legitimate);
		expect(found).toHaveLength(1);
		expect(/\binconclusive:\s*true/.test(found[0])).toBe(false);
		expect(/\berrorKind:/.test(found[0])).toBe(false);
	});
});
