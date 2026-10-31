// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { checkCspQuality } from '../../checks/check-csp-quality';
import { parseCsp, evaluateCsp } from '../../checks/csp-evaluator';
import type { CspIssue, CspRule } from '../../checks/csp-evaluator';
import type { CappedPage } from '../../checks/page-fetch';
import type { CheckResult, FetchFunction } from '../../types';

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Issues of one rule, so a fixture asserts on the rule it targets and not on incidental ones. */
function issuesOf(policy: string, rule: CspRule, delivery: 'header' | 'meta' = 'header'): CspIssue[] {
	return evaluateCsp(policy, { delivery }).filter((i) => i.rule === rule);
}

/** A policy that trips none of the rules, extended with whatever a fixture adds or overrides. */
const BASE = "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

function page(init: { csp?: string; reportOnly?: string; status?: number; body?: string | null } = {}): CappedPage {
	const headers = new Headers();
	if (init.csp !== undefined) headers.set('content-security-policy', init.csp);
	if (init.reportOnly !== undefined) headers.set('content-security-policy-report-only', init.reportOnly);
	return {
		requestedUrl: 'https://example.com/',
		finalUrl: 'https://example.com/',
		status: init.status ?? 200,
		headers,
		setCookies: [],
		body: init.body === undefined ? '<html><head></head></html>' : init.body,
		truncated: false,
		redirects: [],
	};
}

function metaPage(policy: string): CappedPage {
	return page({ body: `<html><head><meta http-equiv="Content-Security-Policy" content="${policy}"></head></html>` });
}

const NEVER_FETCH = vi.fn(async () => {
	throw new Error('fetch must not be called when pages are supplied');
}) as unknown as FetchFunction;

async function run(pages: { apex?: CappedPage | null; www?: CappedPage | null }): Promise<CheckResult> {
	return checkCspQuality('example.com', NEVER_FETCH, { pages });
}

const titles = (r: CheckResult): string[] => r.findings.map((f) => f.title);
const bySeverity = (r: CheckResult, ...s: string[]) => r.findings.filter((f) => s.includes(f.severity));

// ── parseCsp ─────────────────────────────────────────────────────────────────

describe('parseCsp', () => {
	it('splits directives and tokens, lower-cases names, keeps token case', () => {
		const parsed = parseCsp("Script-Src 'self' https://CDN.example.com; img-src data:");
		expect([...parsed.entries()]).toEqual([
			['script-src', ["'self'", 'https://CDN.example.com']],
			['img-src', ['data:']],
		]);
	});

	it('keeps only the first occurrence of a repeated directive (CSP spec)', () => {
		expect(parseCsp("script-src 'self'; script-src *").get('script-src')).toEqual(["'self'"]);
	});

	it('tolerates empty segments and an empty policy', () => {
		expect(parseCsp(';; ;').size).toBe(0);
		expect(parseCsp('').size).toBe(0);
		expect(parseCsp('upgrade-insecure-requests').get('upgrade-insecure-requests')).toEqual([]);
	});
});

// ── evaluateCsp: one fixture per rule ────────────────────────────────────────

describe('evaluateCsp rules', () => {
	it("flags 'unsafe-inline' in the effective script directive as high", () => {
		const [found] = issuesOf("script-src 'self' 'unsafe-inline'", 'unsafe-inline');
		expect(found).toMatchObject({ severity: 'high', directive: 'script-src', token: "'unsafe-inline'" });
	});

	it("falls back to default-src for the effective script directive, and script-src-elem outranks script-src", () => {
		expect(issuesOf("default-src 'self' 'unsafe-inline'", 'unsafe-inline')[0]).toMatchObject({ directive: 'default-src' });
		const both = issuesOf("script-src 'self' 'unsafe-inline'; script-src-elem 'self'", 'unsafe-inline');
		expect(both).toEqual([]);
	});

	it("does not flag 'unsafe-inline' neutralised by a nonce, a hash or 'strict-dynamic'", () => {
		for (const neutraliser of ["'nonce-AbC123=='", "'sha256-AbC123+/='", "'strict-dynamic'"]) {
			expect(issuesOf(`script-src 'unsafe-inline' ${neutraliser}`, 'unsafe-inline')).toEqual([]);
		}
	});

	it("flags 'unsafe-eval' as medium", () => {
		expect(issuesOf("script-src 'self' 'unsafe-eval'", 'unsafe-eval')[0]).toMatchObject({ severity: 'medium', token: "'unsafe-eval'" });
	});

	it("does not mistake 'wasm-unsafe-eval' for 'unsafe-eval'", () => {
		expect(issuesOf("script-src 'self' 'wasm-unsafe-eval'", 'unsafe-eval')).toEqual([]);
	});

	it('flags a wildcard script source as high', () => {
		expect(issuesOf('script-src *', 'wildcard-source')[0]).toMatchObject({ severity: 'high', directive: 'script-src', token: '*' });
	});

	it('flags scheme-only script sources (https:, http:, data:) as high', () => {
		for (const scheme of ['https:', 'http:', 'data:']) {
			expect(issuesOf(`script-src 'self' ${scheme}`, 'scheme-source')[0]).toMatchObject({ severity: 'high', token: scheme });
		}
	});

	it('does not treat a subdomain wildcard as the bare wildcard', () => {
		expect(issuesOf('script-src *.example.com', 'wildcard-source')).toEqual([]);
	});

	it('flags http: host sources as medium, in any source-list directive', () => {
		const found = issuesOf("script-src 'self' http://cdn.example.com; img-src http://img.example.com", 'http-source');
		expect(found.map((i) => [i.directive, i.token, i.severity])).toEqual([
			['script-src', 'http://cdn.example.com', 'medium'],
			['img-src', 'http://img.example.com', 'medium'],
		]);
	});

	it('flags missing object-src as medium unless default-src is none or self', () => {
		expect(issuesOf("script-src 'self'", 'missing-object-src')[0]).toMatchObject({ severity: 'medium', directive: 'object-src' });
		expect(issuesOf("default-src 'self'; script-src 'self'", 'missing-object-src')).toEqual([]);
		expect(issuesOf("default-src 'none'", 'missing-object-src')).toEqual([]);
		expect(issuesOf("default-src https:; script-src 'self'", 'missing-object-src')).toHaveLength(1);
		expect(issuesOf("script-src 'self'; object-src 'none'", 'missing-object-src')).toEqual([]);
	});

	it('flags missing base-uri as medium', () => {
		expect(issuesOf("default-src 'none'", 'missing-base-uri')[0]).toMatchObject({ severity: 'medium', directive: 'base-uri' });
		expect(issuesOf("base-uri 'self'", 'missing-base-uri')).toEqual([]);
	});

	it('flags missing frame-ancestors as low for a header policy only', () => {
		expect(issuesOf("default-src 'none'", 'missing-frame-ancestors', 'header')[0]).toMatchObject({ severity: 'low' });
		expect(issuesOf("default-src 'none'", 'missing-frame-ancestors', 'meta')).toEqual([]);
		expect(issuesOf("frame-ancestors 'self'", 'missing-frame-ancestors')).toEqual([]);
	});

	it('flags allowlisted hosts known to host JSONP or AngularJS as "Script allowlist bypassable"', () => {
		for (const host of ['https://cdnjs.cloudflare.com', 'ajax.googleapis.com', '*.googleapis.com', 'https://www.google.com/recaptcha/', 'cdn.jsdelivr.net']) {
			const [found] = issuesOf(`script-src 'self' ${host}`, 'allowlist-bypass');
			expect(found, host).toMatchObject({ severity: 'medium', title: 'Script allowlist bypassable', token: host });
		}
	});

	it('does not flag an unrelated host, or a look-alike suffix, as bypassable', () => {
		expect(issuesOf("script-src 'self' https://static.example.com https://evilcdnjs.cloudflare.com.example.org", 'allowlist-bypass')).toEqual([]);
	});

	it('flags the tag-manager hosts as bypassable only when unsafe-eval is also allowed', () => {
		expect(issuesOf("script-src https://www.googletagmanager.com", 'allowlist-bypass')).toEqual([]);
		expect(issuesOf("script-src https://www.googletagmanager.com 'unsafe-eval'", 'allowlist-bypass')).toHaveLength(1);
	});

	it("reports 'strict-dynamic' without a nonce or hash as ineffective (info)", () => {
		expect(issuesOf("script-src 'self' 'strict-dynamic'", 'strict-dynamic-ineffective')[0]).toMatchObject({ severity: 'info' });
		expect(issuesOf("script-src 'nonce-abc123' 'strict-dynamic'", 'strict-dynamic-ineffective')).toEqual([]);
	});

	it('reports report-uri without report-to as info', () => {
		expect(issuesOf('report-uri /csp', 'report-uri-deprecated')[0]).toMatchObject({ severity: 'info', directive: 'report-uri' });
		expect(issuesOf('report-uri /csp; report-to csp', 'report-uri-deprecated')).toEqual([]);
	});

	it('flags an unknown directive as low and suggests the near miss for a typo', () => {
		const [typo] = issuesOf("script-scr 'self'", 'unknown-directive');
		expect(typo).toMatchObject({ severity: 'low', directive: 'script-scr', token: 'script-scr' });
		expect(typo!.detail).toContain('Did you mean "script-src"?');
		const [unrelated] = issuesOf('totally-made-up-directive x', 'unknown-directive');
		expect(unrelated!.detail).not.toContain('Did you mean');
	});

	it('flags a bare keyword that lacks its quotes as low', () => {
		const [found] = issuesOf('script-src self', 'unquoted-keyword');
		expect(found).toMatchObject({ severity: 'low', directive: 'script-src', token: 'self' });
	});

	it('flags directives a <meta> policy cannot carry, only for a meta policy', () => {
		const meta = issuesOf("frame-ancestors 'none'; report-uri /csp; sandbox", 'meta-ignored-directive', 'meta');
		expect(meta.map((i) => i.directive)).toEqual(['frame-ancestors', 'report-uri', 'sandbox']);
		expect(issuesOf("frame-ancestors 'none'; sandbox", 'meta-ignored-directive', 'header')).toEqual([]);
	});

	it('flags a policy with no script restriction at all as medium', () => {
		expect(issuesOf("frame-ancestors 'self'", 'missing-script-src')[0]).toMatchObject({ severity: 'medium' });
		expect(issuesOf("script-src 'self'", 'missing-script-src')).toEqual([]);
	});

	it('positive control: a strict nonce + strict-dynamic policy yields no high or medium issue', () => {
		const strict =
			"script-src 'nonce-r4nd0m123' 'strict-dynamic' 'unsafe-inline' https: http:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-to csp";
		const found = evaluateCsp(strict);
		expect(found.filter((i) => i.severity === 'high' || i.severity === 'medium')).toEqual([]);
		expect(found).toEqual([]);
	});

	it('positive control: BASE trips no rule at all, so a fixture failure is its own rule', () => {
		expect(evaluateCsp(BASE)).toEqual([]);
	});

	it('negative control: the same weaknesses are flagged once strict-dynamic and the nonce are removed', () => {
		const loose = "script-src 'unsafe-inline' https: http:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
		const rules = evaluateCsp(loose).map((i) => i.rule);
		expect(rules).toEqual(expect.arrayContaining(['unsafe-inline', 'scheme-source']));
	});
});

// ── checkCspQuality ──────────────────────────────────────────────────────────

describe('checkCspQuality', () => {
	it('reports "No Content-Security-Policy" (medium) when a measured page serves none', async () => {
		const result = await run({ apex: page(), www: page() });
		expect(result.category).toBe('csp_quality');
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]).toMatchObject({ title: 'No Content-Security-Policy', severity: 'medium' });
		expect(result.findings[0]!.metadata).toMatchObject({ hosts: ['example.com', 'www.example.com'], missingControl: true });
		expect(result.controlPresent).toBe(false);
	});

	it('evaluates the enforced header and merges the same finding seen on apex and www', async () => {
		const policy = "default-src 'self'; script-src 'self' 'unsafe-inline'";
		const result = await run({ apex: page({ csp: policy }), www: page({ csp: policy }) });
		const inline = result.findings.filter((f) => f.metadata?.rule === 'unsafe-inline');
		expect(inline).toHaveLength(1);
		expect(inline[0]).toMatchObject({ severity: 'high', metadata: { directive: 'script-src', token: "'unsafe-inline'", enforced: true, hosts: ['example.com', 'www.example.com'] } });
		expect(result.controlPresent).toBe(true);
	});

	it('keeps host-specific findings separate when apex and www differ', async () => {
		const result = await run({ apex: page({ csp: "default-src 'none'; script-src 'self' 'unsafe-eval'" }), www: page({ csp: BASE }) });
		const evalFinding = result.findings.find((f) => f.metadata?.rule === 'unsafe-eval');
		expect(evalFinding?.metadata?.hosts).toEqual(['example.com']);
	});

	it('labels report-only findings "not enforced", demotes them to info, and still reports no enforced policy', async () => {
		const result = await run({ apex: page({ reportOnly: "script-src 'self' 'unsafe-inline'" }), www: page({ reportOnly: "script-src 'self' 'unsafe-inline'" }) });
		const inline = result.findings.find((f) => f.metadata?.rule === 'unsafe-inline');
		expect(inline).toMatchObject({ severity: 'info', metadata: { enforced: false, ruleSeverity: 'high' } });
		expect(inline!.title).toContain('report-only, not enforced');
		expect(titles(result)).toContain('No enforced Content-Security-Policy');
		expect(bySeverity(result, 'high')).toEqual([]);
	});

	it('does not report "no CSP" when only the report-only header is absent but an enforced one exists', async () => {
		const result = await run({ apex: page({ csp: BASE }), www: page({ csp: BASE }) });
		expect(titles(result).filter((t) => t.includes('No '))).toEqual([]);
		expect(result.findings).toEqual([]);
	});

	it('evaluates a <meta> policy as enforced and notes directives meta cannot carry', async () => {
		const result = await run({ apex: metaPage("script-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'") });
		const ignored = result.findings.find((f) => f.metadata?.rule === 'meta-ignored-directive');
		expect(ignored).toMatchObject({ severity: 'low', metadata: { delivery: 'meta', directive: 'frame-ancestors', enforced: true } });
		expect(titles(result)).not.toContain('No Content-Security-Policy');
		expect(result.findings.some((f) => f.metadata?.rule === 'missing-frame-ancestors')).toBe(false);
	});

	it('evaluates each policy of a multi-policy header and says the policies intersect', async () => {
		const result = await run({ apex: page({ csp: "script-src 'self' 'unsafe-inline', default-src 'none'; object-src 'none'; base-uri 'none'" }) });
		expect(titles(result)).toContain('Multiple Content-Security-Policy policies enforced');
		const inline = result.findings.find((f) => f.metadata?.rule === 'unsafe-inline');
		expect(inline).toMatchObject({ metadata: { policyIndex: 1, policyCount: 2 } });
		expect(inline!.detail).toMatch(/^Policy 1 of 2 \(the policies intersect/);
	});

	it('combines a header policy and a <meta> policy as an intersection', async () => {
		const withMeta = page({
			csp: BASE,
			body: `<meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline'">`,
		});
		const result = await run({ apex: withMeta });
		expect(titles(result)).toContain('Multiple Content-Security-Policy policies enforced');
		expect(result.findings.find((f) => f.metadata?.rule === 'unsafe-inline')?.metadata).toMatchObject({ delivery: 'meta', policyIndex: 2, policyCount: 2 });
	});

	it('caps the result at 25 findings, keeps the most severe, and reports how many were dropped', async () => {
		const noisy = Array.from({ length: 40 }, (_, i) => `bogus-directive-${i} x`).join('; ');
		const result = await run({ apex: page({ csp: `script-src * 'unsafe-inline' 'unsafe-eval'; ${noisy}` }), www: null });
		expect(result.findings).toHaveLength(25);
		expect(result.findings.slice(0, 2).map((f) => f.severity)).toEqual(['high', 'high']);
		expect((result.metadata as { findingsTruncated: number }).findingsTruncated).toBeGreaterThan(0);
	});

	it('assesses the host that answered and notes the one that did not, without calling it policy-free', async () => {
		const result = await run({ apex: page({ csp: BASE }), www: null });
		expect(result.checkStatus).toBeUndefined();
		expect(result.metadata).toMatchObject({ hostsAssessed: ['example.com'], hostsNotAssessed: [{ host: 'www.example.com', reason: 'no response' }] });
		expect(titles(result)).toEqual(['CSP not assessed for one host']);
		expect(titles(result)).not.toContain('No Content-Security-Policy');
	});

	it('treats a non-2xx page as not assessed, not as a policy-free host', async () => {
		const result = await run({ apex: page({ status: 403 }), www: page({ status: 404 }) });
		expect(result).toMatchObject({ checkStatus: 'error', score: 0, passed: false, partial: true });
		expect(titles(result)).toEqual(['CSP not assessed']);
		expect(result.findings[0]!.detail).toContain('HTTP 403');
		expect(result.findings[0]!.metadata?.missingControl).toBeUndefined();
	});

	it('abstains with the not-assessed shape when no host answers', async () => {
		const result = await run({ apex: null, www: null });
		expect(result).toMatchObject({ category: 'csp_quality', checkStatus: 'error', score: 0, passed: false, partial: true });
	});

	it('fetches both hosts itself when no pages are supplied, and passes the timeout on', async () => {
		const seen: string[] = [];
		const fetchFn = (async (url: string, init?: RequestInit) => {
			seen.push(url);
			expect(init?.signal).toBeInstanceOf(AbortSignal);
			return new Response('<html></html>', { status: 200, headers: { 'content-security-policy': BASE } });
		}) as unknown as FetchFunction;
		const result = await checkCspQuality('example.com', fetchFn, { timeout: 1234 });
		expect(seen.sort()).toEqual(['https://example.com/', 'https://www.example.com/']);
		expect(result.findings).toEqual([]);
		expect(result.metadata).toMatchObject({ hostsAssessed: ['example.com', 'www.example.com'] });
	});

	it('uses a supplied page for one host and fetches only the other', async () => {
		const fetchFn = vi.fn(async () => new Response('', { status: 200, headers: { 'content-security-policy': BASE } })) as unknown as FetchFunction & ReturnType<typeof vi.fn>;
		await checkCspQuality('example.com', fetchFn, { pages: { apex: page({ csp: BASE }) } });
		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect((fetchFn as ReturnType<typeof vi.fn>).mock.calls[0]![0]).toBe('https://www.example.com/');
	});

	it('does not add a second www. host when the domain is already a www host', async () => {
		const fetchFn = vi.fn(async () => new Response('', { status: 200, headers: { 'content-security-policy': BASE } })) as unknown as FetchFunction & ReturnType<typeof vi.fn>;
		await checkCspQuality('www.example.com', fetchFn);
		expect(fetchFn).toHaveBeenCalledTimes(1);
	});

	it('never declares a present-but-weak policy a missing control (so category zeroing cannot fire on prose)', async () => {
		const result = await run({ apex: page({ csp: "script-src * 'unsafe-inline'" }), www: null });
		const weak = result.findings.filter((f) => f.metadata?.rule !== 'no-csp' && f.metadata?.rule !== undefined);
		expect(weak.length).toBeGreaterThan(0);
		for (const f of weak) expect(f.metadata?.missingControl).toBe(false);
	});
});
