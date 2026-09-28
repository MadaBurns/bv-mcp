/**
 * #1128 — a non-resolving apex (NXDOMAIN) must abstain on the individual check_*
 * tools exactly as `scan_domain` does (`buildNonResolvingResult`), instead of
 * scoring the absence of every record as a measured negative (or a clean 100).
 *
 * The gate lives at the `TOOL_REGISTRY` dispatch boundary in
 * `src/handlers/tools.ts`, so these specs drive `handleToolsCall` and read the raw
 * `CheckResult` through `resultCapture`.
 *
 * Three arms per the #1128 brief:
 *   - NXDOMAIN apex → the #946 not-assessed shape + one info finding naming the reason;
 *   - resolving apex → output unchanged (no gate marker, the check ran);
 *   - SERVFAIL apex → unchanged (only NXDOMAIN abstains, as in scan_domain).
 */
import { describe, it, expect, afterEach, beforeAll, vi } from 'vitest';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse } from './helpers/dns-mock';
import type { CheckResult } from '../src/lib/scoring';

const { restore } = setupFetchMock();
afterEach(() => restore());

// Cold-importing the handler graph can exceed the 15s per-test budget on a loaded machine.
beforeAll(async () => {
	await import('../src/handlers/tools');
}, 60_000);

/** The 11 tools #1128 observed scoring an NXDOMAIN, with the category each reports. */
const GATED: Array<[tool: string, category: string]> = [
	['check_spf', 'spf'],
	['check_dmarc', 'dmarc'],
	['check_mx', 'mx'],
	['check_ns', 'ns'],
	['check_dnssec', 'dnssec'],
	['check_dnssec_chain', 'dnssec_chain'],
	['check_caa', 'caa'],
	['check_dkim', 'dkim'],
	['check_zone_hygiene', 'zone_hygiene'],
	['check_subdomain_takeover', 'subdomain_takeover'],
	['check_ssl', 'ssl'],
];

let seq = 0;
/** Unique per test so the in-memory check cache can never serve a prior case. */
function freshDomain(tag: string): string {
	seq += 1;
	return `nx1128-${tag.replace(/_/g, '-')}-${seq}-${Date.now()}.com`;
}

function urlOf(input: string | URL | Request): string {
	return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
}

function isDoh(url: string): boolean {
	return url.includes('name=');
}

/** Every DNS name answers with `rcode`; every HTTPS fetch gets a Cloudflare 530 (what a non-existent host returns). */
function mockEveryName(rcode: number) {
	const fetchMock = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = urlOf(input);
		if (isDoh(url)) return Promise.resolve(createDohResponse([], [], { status: rcode }));
		return Promise.resolve(new Response('origin DNS error', { status: 530 }));
	});
	globalThis.fetch = fetchMock;
	return fetchMock;
}

/** A resolving domain: NS at the apex, an SPF + DMARC record, empty everything else. */
function mockResolving(domain: string) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = urlOf(input);
		if (isDoh(url)) {
			if (url.includes('type=NS') && url.includes(`name=${domain}&`)) {
				return Promise.resolve(nsResponse(domain, ['ns1.example.net.', 'ns2.example.net.']));
			}
			if (url.includes('type=TXT') && url.includes(`name=_dmarc.${domain}`)) {
				return Promise.resolve(txtResponse(`_dmarc.${domain}`, ['v=DMARC1; p=reject']));
			}
			if (url.includes('type=TXT') && url.includes(`name=${domain}&`)) {
				return Promise.resolve(txtResponse(domain, ['v=spf1 -all']));
			}
			return Promise.resolve(createDohResponse([], []));
		}
		return Promise.resolve(new Response('ok', { status: 200 }));
	});
}

async function callCapturing(name: string, args: Record<string, unknown>): Promise<{ result: CheckResult; text: string }> {
	const { handleToolsCall } = await import('../src/handlers/tools');
	let captured: CheckResult | undefined;
	const out = await handleToolsCall({ name, arguments: args }, undefined, {
		resultCapture: (r: CheckResult) => {
			captured = r;
		},
	});
	expect(captured, `${name} did not reach resultCapture`).toBeDefined();
	const first = out.content[0] as { text?: string };
	return { result: captured!, text: first.text ?? '' };
}

function isNxdomainAbstention(r: CheckResult): boolean {
	return r.findings.some((f) => f.metadata?.notAssessedReason === 'domain_does_not_resolve');
}

describe('#1128 — check_* tools abstain on an NXDOMAIN apex (scan_domain parity)', () => {
	it.each(GATED)('%s → not-assessed shape, one info finding naming NXDOMAIN', async (tool, category) => {
		const domain = freshDomain(tool);
		mockEveryName(3);
		const { result, text } = await callCapturing(tool, { domain });

		// #946 abstention contract: checkStatus 'error' ⇒ score 0, passed false, partial true.
		expect(result.category).toBe(category);
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.partial).toBe(true);
		// No presence claim either way — nothing was measured.
		expect(result.controlPresent).toBeUndefined();
		expect(result.recordPresent).toBeUndefined();

		expect(result.findings).toHaveLength(1);
		const [finding] = result.findings;
		expect(finding.severity).toBe('info');
		expect(finding.category).toBe(category);
		expect(finding.detail).toContain(`${domain} does not resolve (NXDOMAIN)`);
		expect(finding.metadata?.missingControl).toBeUndefined();
		expect(finding.metadata?.domainResolves).toBe(false);
		expect(finding.metadata?.notAssessedReason).toBe('domain_does_not_resolve');

		// Rendered as ungraded, never a Passed/Failed verdict with a score.
		expect(text).not.toMatch(/\*\*Score:\*\*/);
		expect(text).not.toMatch(/Passed|Failed/);
	});

	it('is not cached — like scan_domain, a later call re-probes (the domain may since have been registered)', async () => {
		const domain = freshDomain('nocache');
		const fetchMock = mockEveryName(3);
		await callCapturing('check_spf', { domain });
		const callsAfterFirst = fetchMock.mock.calls.length;
		const { result } = await callCapturing('check_spf', { domain });
		expect(isNxdomainAbstention(result)).toBe(true);
		expect(fetchMock.mock.calls.length).toBeGreaterThan(callsAfterFirst);
	});

	it('check_subdomain_takeover with an explicit subdomain list is NOT gated (FQDNs may sit outside the NXDOMAIN apex)', async () => {
		const domain = freshDomain('takeover-explicit');
		mockEveryName(3);
		const { result } = await callCapturing('check_subdomain_takeover', { domain, subdomains: ['cdn.example.org'] });
		expect(isNxdomainAbstention(result)).toBe(false);
	});
});

/** Direct (ungated) invocation of the check behind each tool, for "output unchanged" comparisons. */
const DIRECT: Record<string, (domain: string) => Promise<CheckResult>> = {
	check_spf: async (d) => (await import('../src/tools/check-spf')).checkSpf(d),
	check_dmarc: async (d) => (await import('../src/tools/check-dmarc')).checkDmarc(d),
	check_caa: async (d) => (await import('../src/tools/check-caa')).checkCaa(d),
	check_ns: async (d) => (await import('../src/tools/check-ns')).checkNs(d),
	check_dnssec: async (d) => (await import('../src/tools/check-dnssec')).checkDnssec(d),
};

/** The verdict-bearing fields of a result — what a consumer reads. */
function verdictOf(r: CheckResult) {
	return {
		category: r.category,
		score: r.score,
		passed: r.passed,
		checkStatus: r.checkStatus,
		partial: r.partial,
		findings: r.findings.map((f) => [f.severity, f.title]),
	};
}

describe('#1128 — resolving apex: output unchanged', () => {
	it.each([['check_spf'], ['check_dmarc'], ['check_caa'], ['check_ns']])('%s returns what the check returns directly', async (tool) => {
		const domain = freshDomain(`ok-${tool}`);
		mockResolving(domain);
		const { result } = await callCapturing(tool, { domain });
		expect(isNxdomainAbstention(result)).toBe(false);
		const direct = await DIRECT[tool](domain);
		expect(verdictOf(result)).toEqual(verdictOf(direct));
	});
});

describe('#1128 — SERVFAIL apex: unchanged (only NXDOMAIN abstains, as in scan_domain)', () => {
	it.each([['check_spf'], ['check_dmarc'], ['check_caa'], ['check_dnssec']])('%s returns what the check returns directly', async (tool) => {
		const domain = freshDomain(`sf-${tool}`);
		mockEveryName(2);
		const { result } = await callCapturing(tool, { domain });
		expect(isNxdomainAbstention(result)).toBe(false);
		const direct = await DIRECT[tool](domain);
		expect(verdictOf(result)).toEqual(verdictOf(direct));
	});

	it('a transport failure on the probe falls through to the check (fail-open, as in scan_domain)', async () => {
		const domain = freshDomain('probe-throws');
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('network down'));
		const { result } = await callCapturing('check_spf', { domain });
		expect(isNxdomainAbstention(result)).toBe(false);
	});
});
