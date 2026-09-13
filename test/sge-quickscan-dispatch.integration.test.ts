// SPDX-License-Identifier: BUSL-1.1

/**
 * `sge_quickscan` — exercised through the REAL ENTRY PATH.
 *
 * WHY THIS FILE EXISTS, GIVEN `test/sge-quickscan.spec.ts` ALREADY PASSES
 *
 * `test/sge-quickscan.spec.ts` imports `buildSgeQuickscanReport` /
 * `formatSgeQuickscan` and hands them hand-built `CheckResult[]`. That proves
 * the renderer, and nothing else. It cannot prove the tool is REACHABLE: it
 * never touches `TOOL_SCHEMA_MAP`, never touches `extractAndValidateDomain`,
 * never touches `DIRECT_DISPATCH_TOOLS`, and never runs `scanDomain`. A lane
 * whose every test replaces the function that talks to the world is exactly the
 * lane that can fail on its FIRST real call while its suite stays green — the
 * recorded 2026-09-12 failure where 318 green tests sat over a guard that
 * rejected the only input shape the lane ever receives in production.
 *
 * So this file enters where a caller enters: `handleToolsCall`, the dispatch
 * layer that `mcp/execute` hands a `tools/call` to. Everything from argument
 * validation through the domain guard, `scanDomain`, the evaluator and the
 * renderer runs for real. Only DNS/HTTPS is mocked, so the test stays hermetic
 * (no network in CI) while the ENTRY PATH is the genuine one.
 *
 * WHAT IS DELIBERATELY NOT ASSERTED HERE
 *
 * Per-control SATISFIED outcomes for the mail domain. `scan_domain`
 * post-processing rebuilds some `CheckResult`s through
 * `buildCheckResult(category, findings)`, which carries no `metadata`, so the
 * evaluator's `spfAllQualifier()` / `mtaStsPolicyMode()` readers can lose their
 * signal between the check and the report. That divergence is a live defect
 * (bv-mcp issue filed 2026-09-14, measured against health.govt.nz), NOT
 * something this file should pin in either direction. The assertions below are
 * the invariants that hold regardless of it: reachability, the guard, the
 * three-state vocabulary, no clean bill of health, and honest abstention.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { createDohResponse, dnssecResponse, httpResponse, nsResponse, setupFetchMock, txtResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { SGE_TRANSPORT_TLS_CAVEAT } from '../src/tools/sge-quickscan';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	IN_MEMORY_CACHE.clear();
});

const DOMAIN = 'example.com';

/** The six control labels the renderer must emit on EVERY run, unfiltered and in order. */
const CONTROL_LABELS = ['DMARC', 'SPF', 'DKIM', 'SMTP TLS', 'MTA-STS', 'TLS-RPT'] as const;

/**
 * A mail-bearing domain: MX present, DMARC at p=reject, an SPF record with a real
 * authorizing mechanism (a bare `v=spf1 -all` would trip the no-send-policy
 * post-processor and make this fixture about something else), DKIM, MTA-STS at
 * mode: enforce, TLS-RPT.
 */
function mockMailDomain() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse(`version: STSv1\nmode: enforce\nmx: mx.${DOMAIN}\nmax_age: 86400`));
		}

		if (url.includes('dns-query') || url.includes('dns.google') || url.includes('cloudflare-dns.com')) {
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(
					createDohResponse([{ name: DOMAIN, type: 15 }], [{ name: DOMAIN, type: 15, TTL: 300, data: `0 mx.${DOMAIN}.` }]),
				);
			}
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) return Promise.resolve(txtResponse(`_dmarc.${DOMAIN}`, ['v=DMARC1; p=reject; sp=reject; pct=100']));
				if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse(`_mta-sts.${DOMAIN}`, ['v=STSv1; id=20260914000000']));
				if (url.includes('_smtp._tls.'))
					return Promise.resolve(txtResponse(`_smtp._tls.${DOMAIN}`, [`v=TLSRPTv1; rua=mailto:tls@${DOMAIN}`]));
				if (url.includes('_domainkey.'))
					return Promise.resolve(txtResponse(`selector1._domainkey.${DOMAIN}`, ['v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN']));
				return Promise.resolve(txtResponse(DOMAIN, ['v=spf1 ip4:203.0.113.10 -all']));
			}
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse(DOMAIN, [`ns1.${DOMAIN}.`, `ns2.${DOMAIN}.`]));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse(DOMAIN, true));
			}
			return Promise.resolve(createDohResponse([], []));
		}

		if (url.startsWith('https://')) return Promise.resolve({ ...httpResponse('OK'), url });
		return Promise.resolve(httpResponse('OK'));
	});
}

/** Nothing answers. Every check attempts and none completes — the abstaining case. */
function mockTotalResolutionFailure() {
	globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
}

async function callDispatch(args: Record<string, unknown>) {
	// Dynamic import is mandatory in this repo for mock isolation.
	const { handleToolsCall } = await import('../src/handlers/tools');
	return handleToolsCall({ name: 'sge_quickscan', arguments: args });
}

/** The machine half of the tool result — the same block a structured consumer parses. */
function structured(result: { content: Array<{ text: string }> }) {
	const joined = result.content.map((c) => c.text).join('\n');
	const match = joined.match(/STRUCTURED_RESULT\n([\s\S]*?)\nSTRUCTURED_RESULT/);
	if (!match) throw new Error('tool result carried no STRUCTURED_RESULT block');
	return JSON.parse(match[1]) as {
		verdict: string;
		assessed: boolean;
		caveat: string | null;
		transportTlsCaveat: string | null;
		controls: Array<{ control: string; label: string; status: string; notMeasuredReason?: string }>;
		counts: { satisfied: number; notSatisfied: number; notMeasured: number };
	};
}

describe('sge_quickscan — the tool is REACHABLE through the dispatch layer', () => {
	// THE first-call test. If `sge_quickscan` were missing from `TOOL_SCHEMA_MAP`,
	// missing its `case` in the dispatch switch, or rejected at the domain guard,
	// this fails — and none of the direct-import specs would notice.
	it('a normal, well-formed domain produces a rendered report, not a boundary rejection', async () => {
		mockMailDomain();
		const result = await callDispatch({ domain: DOMAIN });

		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('# NZ Secure Government Email (SGE): example.com');
		expect(structured(result).controls).toHaveLength(6);
	});

	// The guard must reject the shapes it exists for, or the test above proves
	// only that nothing is checked. Both directions, in one place.
	it.each([
		['a bare TLD', 'nz'],
		['a reserved single label', 'localhost'],
		['a CRLF injection attempt', 'exa\r\nmple.com'],
	])('rejects %s at the dispatch boundary', async (_label, domain) => {
		mockMailDomain();
		const result = await callDispatch({ domain });

		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain('Domain validation failed');
	});

	it('rejects a non-string domain before the scan is ever started', async () => {
		const fetchSpy = vi.fn();
		globalThis.fetch = fetchSpy;
		const result = await callDispatch({ domain: 123 });

		expect(result.isError).toBe(true);
		expect(fetchSpy).not.toHaveBeenCalled();
	});
});

describe('sge_quickscan through dispatch — all three states survive to the rendered text', () => {
	it('renders every one of the six controls, never filtered and never reordered', async () => {
		mockMailDomain();
		const result = await callDispatch({ domain: DOMAIN });
		const rendered = result.content[0].text;

		expect(structured(result).controls.map((c) => c.label)).toEqual([...CONTROL_LABELS]);
		for (const label of CONTROL_LABELS) {
			expect(rendered).toContain(`**${label}**`);
		}
	});

	// The counts are a partition of six. A control that vanished from one bucket
	// without arriving in another would let a reader tally a pass out of silence.
	it('the three counts always partition the six controls', async () => {
		mockMailDomain();
		const { counts, controls } = structured(await callDispatch({ domain: DOMAIN }));

		expect(counts.satisfied + counts.notSatisfied + counts.notMeasured).toBe(controls.length);
		expect(controls).toHaveLength(6);
	});
});

describe('sge_quickscan through dispatch — no clean bill of health while SMTP TLS is unmeasured', () => {
	// Structural, not incidental: this scanner never opens an SMTP session, so on a
	// mail-bearing domain control 4 of 6 is ALWAYS unmeasured and `compliant` is
	// therefore unreachable. A future change that made this verdict `compliant`
	// without a transport observation would be claiming something never measured.
	it('a mail-bearing domain is INDETERMINATE, carries the transport caveat, and is never COMPLIANT', async () => {
		mockMailDomain();
		const result = await callDispatch({ domain: DOMAIN });
		const report = structured(result);
		const smtpTls = report.controls.find((c) => c.control === 'smtp_tls');

		expect(report.verdict).not.toBe('compliant');
		expect(smtpTls?.status).toBe('not_measured');
		expect(smtpTls?.notMeasuredReason).toBe('no_transport_probe');

		// The caveat reaches BOTH surfaces, from the one exported SSOT — a machine
		// consumer that only reads the structured block gets the same qualifier the
		// prose reader does.
		expect(report.transportTlsCaveat).toBe(SGE_TRANSPORT_TLS_CAVEAT);
		expect(result.content[0].text).toContain(SGE_TRANSPORT_TLS_CAVEAT);
	});
});

describe('sge_quickscan through dispatch — an abstaining scan reads as NOT MEASURED', () => {
	// Never a pass, never a failure, never omitted. This is the one shape where a
	// renderer bug is most expensive: five ticks over an unmeasured domain.
	it('a domain nothing could be measured for reports six NOT MEASURED controls and says so', async () => {
		mockTotalResolutionFailure();
		const result = await callDispatch({ domain: 'nonexistent-sge-probe-20260914.com' });
		const report = structured(result);
		const rendered = result.content[0].text;

		expect(result.isError).toBeUndefined();
		expect(report.counts).toEqual({ satisfied: 0, notSatisfied: 0, notMeasured: 6 });
		expect(report.controls.every((c) => c.status === 'not_measured')).toBe(true);

		// `assessed` is NOT asserted here, and that is a measured fact rather than an
		// oversight: it answers "did ANY check in the 19-category scan complete", not
		// "was any of the SIX SGE controls measured". With every DNS lookup failing,
		// a non-DNS category can still complete and leave `assessed: true` — so the
		// `SGE_UNASSESSED_CAVEAT` is suppressed while all six controls are unmeasured.
		// Measured through this dispatch path 2026-09-14. The stronger invariant —
		// that all six read NOT MEASURED and neither glyph appears — is asserted above
		// and below, and it holds either way.
		expect(rendered).toContain('NOT MEASURED — no verdict was reached (neither a pass nor a failure)');
		// The pass and fail glyphs must be absent entirely — not merely outnumbered.
		expect(rendered).not.toContain('✅');
		expect(rendered).not.toContain('❌');
		expect(rendered).not.toContain('NOT SATISFIED');
	});

	// Degrading, not throwing: a total resolution failure is an ordinary tool
	// result with an honest verdict, not an error the caller has to interpret.
	it('degrades to a structured INDETERMINATE result rather than raising', async () => {
		mockTotalResolutionFailure();
		const result = await callDispatch({ domain: 'nonexistent-sge-probe-20260914.com' });

		expect(result.isError).toBeUndefined();
		expect(structured(result).verdict).toBe('indeterminate');
	});
});
