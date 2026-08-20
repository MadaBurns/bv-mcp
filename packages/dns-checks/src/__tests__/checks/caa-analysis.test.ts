// SPDX-License-Identifier: BUSL-1.1

/**
 * CAA tag-completeness analysis.
 *
 * Ported from the Worker-side `test/caa-analysis.spec.ts`, which exercised a
 * duplicate copy at `src/tools/caa-analysis.ts` that nothing in the production
 * path imported — `src/tools/check-caa.ts` delegates to this package. The tests
 * passed while validating dead code, so the live implementation was untested.
 * The duplicate is removed; this file is the coverage, pointed at what runs.
 */

import { describe, expect, it } from 'vitest';

import {
	MAX_CAA_PARAMETER_DETAIL_LENGTH,
	MAX_CAA_TOKEN_LENGTH,
	MAX_CAA_VALIDATION_METHODS,
	TRUNCATION_MARKER,
	getCaaConfiguredFinding,
	getCaaParameterBindingFindings,
	getCaaValidationFindings,
	parseCaaParameters,
	summarizeCaaTags,
} from '../../checks/caa-analysis';
import { inferFindingConfidence, scoreIndicatesMissingControl } from '../../scoring';

describe('caa-analysis', () => {
	it('summarizes presence of key CAA tags', () => {
		expect(
			summarizeCaaTags([
				{ flags: 0, tag: 'issue', value: 'letsencrypt.org' },
				{ flags: 0, tag: 'iodef', value: 'mailto:admin@example.com' },
			]),
		).toEqual({ hasIssue: true, hasIssuewild: false, hasIodef: true, hasIssuemail: false });
	});

	it('emits findings for missing tags', () => {
		const findings = getCaaValidationFindings({ hasIssue: false, hasIssuewild: false, hasIodef: true });
		expect(findings.map((finding) => finding.title)).toEqual(['No CAA issue tag', 'No CAA issuewild tag']);
	});

	it('produces the configured finding when all tags are present', () => {
		expect(getCaaValidationFindings({ hasIssue: true, hasIssuewild: true, hasIodef: true })).toHaveLength(0);
		expect(getCaaConfiguredFinding().severity).toBe('info');
	});

	it('summarizes the RFC 9495 issuemail tag', () => {
		expect(summarizeCaaTags([{ flags: 0, tag: 'issuemail', value: 'digicert.com' }])).toEqual({
			hasIssue: false,
			hasIssuewild: false,
			hasIodef: false,
			hasIssuemail: true,
		});
	});
});

describe('parseCaaParameters (RFC 8657)', () => {
	it('parses an accounturi parameter out of an issue value', () => {
		const params = parseCaaParameters('letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123');
		expect(params.accounturi).toBe('https://acme-v02.api.letsencrypt.org/acme/acct/123');
	});

	it('parses a single validationmethods value as a one-element list', () => {
		expect(parseCaaParameters('letsencrypt.org; validationmethods=dns-01').validationmethods).toEqual(['dns-01']);
	});

	it('parses comma-separated validationmethods into a list', () => {
		expect(parseCaaParameters('letsencrypt.org; validationmethods=dns-01,http-01').validationmethods).toEqual(['dns-01', 'http-01']);
	});

	it('matches parameter tags case-insensitively', () => {
		const params = parseCaaParameters('letsencrypt.org; AccountURI=https://acme.example/acct/9; ValidationMethods=DNS-01');
		expect(params.accounturi).toBe('https://acme.example/acct/9');
		expect(params.validationmethods).toEqual(['DNS-01']);
	});

	it('tolerates whitespace around the separator, tag and value', () => {
		const params = parseCaaParameters(
			'  letsencrypt.org ;  accounturi =  https://acme.example/acct/7  ;  validationmethods = dns-01 , http-01 ',
		);
		expect(params.issuerDomain).toBe('letsencrypt.org');
		expect(params.accounturi).toBe('https://acme.example/acct/7');
		expect(params.validationmethods).toEqual(['dns-01', 'http-01']);
	});

	it('strips surrounding quotes from a parameter value', () => {
		expect(parseCaaParameters('letsencrypt.org; accounturi="https://acme.example/acct/5"').accounturi).toBe('https://acme.example/acct/5');
	});

	it('parses parameters on an issuewild value exactly as on issue', () => {
		const params = parseCaaParameters('sectigo.com; accounturi=https://acme.example/acct/42; validationmethods=dns-01');
		expect(params.issuerDomain).toBe('sectigo.com');
		expect(params.accounturi).toBe('https://acme.example/acct/42');
		expect(params.validationmethods).toEqual(['dns-01']);
	});

	it('reads the explicit no-issuance form as forbidding issuance, not as a parameterless grant', () => {
		const params = parseCaaParameters(';');
		expect(params.noIssuance).toBe(true);
		expect(params.issuerDomain).toBe('');
		expect(params.accounturi).toBeUndefined();
	});

	it('does not treat an ordinary parameterless grant as no-issuance', () => {
		const params = parseCaaParameters('letsencrypt.org');
		expect(params.noIssuance).toBe(false);
		expect(params.issuerDomain).toBe('letsencrypt.org');
	});
});

describe('getCaaParameterBindingFindings', () => {
	it('emits an info finding when CAA carries an account binding', () => {
		const findings = getCaaParameterBindingFindings([
			{ flags: 0, tag: 'issue', value: 'letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123' },
		]);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].metadata?.caaAccountBound).toBe(true);
	});

	it('emits an info finding when CAA carries a validation-method binding', () => {
		const findings = getCaaParameterBindingFindings([{ flags: 0, tag: 'issuewild', value: 'letsencrypt.org; validationmethods=dns-01' }]);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].metadata?.caaValidationMethods).toEqual(['dns-01']);
	});

	// The load-bearing arm. RFC 8657 parameters are a BONUS signal: ~97-99% of
	// CAA-publishing domains carry none, so any finding here — even a `low` — would
	// fire as a penalty against essentially every domain that did the right thing by
	// publishing CAA at all. Absence is not a defect and must stay silent.
	it('emits NO finding when CAA has no RFC 8657 parameters', () => {
		expect(
			getCaaParameterBindingFindings([
				{ flags: 0, tag: 'issue', value: 'letsencrypt.org' },
				{ flags: 0, tag: 'issuewild', value: 'letsencrypt.org' },
				{ flags: 0, tag: 'iodef', value: 'mailto:admin@example.com' },
			]),
		).toEqual([]);
	});

	it('emits no finding for the explicit no-issuance form, which carries no parameters', () => {
		expect(getCaaParameterBindingFindings([{ flags: 0, tag: 'issue', value: ';' }])).toEqual([]);
	});
});

// ── F3: the prose must never trip the missing-control zeroing heuristic ────────
//
// `scoreIndicatesMissingControl` (scoring/model.ts) runs MISSING_CONTROL_REGEX
// over BOTH title and detail, and when it matches at `high`/`critical` severity
// with deterministic confidence the WHOLE `caa` category is zeroed — a category
// wipe, not a deduction. This finding is `info` today, so the hazard is latent;
// it arms itself the instant anyone promotes the severity or copy-edits the
// prose back toward the regex. The same landmine is already commented at the
// "No CAA records" emission site in check-caa.ts.
//
// The behavioural guard is the SEVERITY-PROMOTED arm: it exercises the real
// scorer at the severity where the regex actually bites, so a future edit that
// re-introduces a matching word fails here rather than in production scores.
describe('getCaaParameterBindingFindings — missing-control regex safety (F3)', () => {
	/** Mirror of MISSING_CONTROL_REGEX (scoring/model.ts), split per alternation branch. */
	const MISSING_CONTROL_BRANCHES: ReadonlyArray<readonly [string, RegExp]> = [
		['no <…> record', /no\s+[^\r\n]{1,64}\srecord/i],
		['missing', /missing/i],
		['required', /required/i],
		['not found', /not\s+found/i],
	];

	const finding = getCaaParameterBindingFindings([
		{
			flags: 0,
			tag: 'issue',
			value: 'letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123; validationmethods=dns-01',
		},
	])[0];

	it.each(MISSING_CONTROL_BRANCHES)('detail and title do not match the %s branch', (_label, branch) => {
		expect(branch.test(finding.detail)).toBe(false);
		expect(branch.test(finding.title)).toBe(false);
	});

	it('is not read as a missing control at its shipped info severity', () => {
		expect(scoreIndicatesMissingControl([finding])).toBe(false);
	});

	// The load-bearing arm: at `high` the regex is live, so this fails the moment
	// the prose drifts back into a matching phrase.
	it('is STILL not read as a missing control when promoted to high severity', () => {
		const promoted = { ...finding, severity: 'high' as const };
		// Prove the guard is the REGEX and not the confidence gate: a heuristic
		// confidence would make this pass vacuously.
		expect(inferFindingConfidence(promoted)).toBe('deterministic');
		expect(scoreIndicatesMissingControl([promoted])).toBe(false);
	});
});

// ── F4: bounding attacker-controlled CAA parameter input ──────────────────────
//
// CAA values are DNS data, so for any domain an attacker controls they are
// attacker-authored. Before the caps, the distinct-method list and the emitted
// detail string were both unbounded and deduped with a linear `includes` scan
// inside a loop (O(n²)): a single realistic ~64 KB DoH response measured 197.7 ms
// of CPU and an ~80 KB finding detail flowing into the MCP `structuredContent`
// LLM channel; a 200k-token value measured ~20 s and a 1.9 MB detail.
//
// The primary guards below assert BOUNDS (deterministic), not wall-clock.
describe('getCaaParameterBindingFindings — bounded under pathological input (F4)', () => {
	/** N records each carrying M distinct validation-method tokens. */
	function pathologicalRecords(records: number, methodsPerRecord: number) {
		return Array.from({ length: records }, (_unused, r) => ({
			flags: 0,
			tag: 'issue',
			value: `ca${r}.example; validationmethods=${Array.from({ length: methodsPerRecord }, (_u, m) => `m-${r}-${m}-01`).join(',')}`,
		}));
	}

	it('caps retained validation methods, metadata and detail length for a 200k-method RRset', () => {
		const findings = getCaaParameterBindingFindings(pathologicalRecords(400, 500));
		expect(findings).toHaveLength(1);

		const methods = findings[0].metadata?.caaValidationMethods as string[];
		expect(methods.length).toBeLessThanOrEqual(MAX_CAA_VALIDATION_METHODS);
		expect(findings[0].detail.length).toBeLessThanOrEqual(MAX_CAA_PARAMETER_DETAIL_LENGTH);
		// Truncation must be SIGNALLED — a clipped list must never read as complete.
		expect(findings[0].metadata?.caaValidationMethodsTruncated).toBe(true);
		expect(findings[0].detail).toMatch(/truncated/i);
	});

	it('caps a single oversized method token and a flood of issuer domains', () => {
		const giantMethod = 'a'.repeat(64_000);
		const findings = getCaaParameterBindingFindings([
			{ flags: 0, tag: 'issue', value: `ca.example; validationmethods=${giantMethod}` },
			...Array.from({ length: 1_000 }, (_u, i) => ({
				flags: 0,
				tag: 'issue',
				value: `issuer-${i}.${'x'.repeat(200)}.example; accounturi=https://acme.example/acct/${i}`,
			})),
		]);
		expect(findings).toHaveLength(1);
		expect(findings[0].detail.length).toBeLessThanOrEqual(MAX_CAA_PARAMETER_DETAIL_LENGTH);
		for (const method of (findings[0].metadata?.caaValidationMethods as string[]) ?? []) {
			expect(method.length).toBeLessThanOrEqual(MAX_CAA_TOKEN_LENGTH + TRUNCATION_MARKER.length);
		}
	});

	it('leaves a normal RRset completely unaffected — no clipping, no truncation flag', () => {
		const findings = getCaaParameterBindingFindings([
			{ flags: 0, tag: 'issue', value: 'letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123' },
			{ flags: 0, tag: 'issuewild', value: 'letsencrypt.org; validationmethods=dns-01,http-01,tls-alpn-01' },
		]);
		expect(findings).toHaveLength(1);
		expect(findings[0].metadata?.caaValidationMethods).toEqual(['dns-01', 'http-01', 'tls-alpn-01']);
		expect(findings[0].metadata?.caaValidationMethodsTruncated).toBeUndefined();
		expect(findings[0].detail).toContain('dns-01, http-01, tls-alpn-01');
		expect(findings[0].detail).not.toMatch(/truncated/i);
	});

	// SECONDARY sanity check only — the bounds above are the real guard. The
	// threshold is deliberately ~50x the post-fix measurement so it cannot flake
	// on a loaded CI box, while still failing loudly if the O(n²) dedupe returns.
	it('[secondary] completes the pathological RRset well inside a generous budget', () => {
		const records = pathologicalRecords(400, 500);
		const start = performance.now();
		getCaaParameterBindingFindings(records);
		expect(performance.now() - start).toBeLessThan(2_000);
	});
});
