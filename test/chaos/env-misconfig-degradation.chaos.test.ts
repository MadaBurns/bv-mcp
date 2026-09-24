// SPDX-License-Identifier: BUSL-1.1
//
// Chaos H: environment misconfiguration must DEGRADE, never crash.
//
// Five independent hypotheses, phrased per testing-methodology principle 8
// ("Given [failure], the system should [expected degradation]") with a
// negative control alongside each one so a vacuously-passing assertion would
// be caught. Full hypothesis + negative-control writeup and any FALSIFIED
// findings are also recorded as SQ-195 ticket comments.
//
//  H1 — Given SCORING_CONFIG is malformed JSON / fails schema validation,
//       scan_domain scores with the default config and (per the code, only
//       for the schema-validation-failure branch) emits one structured
//       warning; scores equal a control run with SCORING_CONFIG unset.
//  H2 — Given SCAN_TIMEOUT_MS / PER_CHECK_TIMEOUT_MS / CACHE_TTL_SECONDS are
//       garbage strings or negative numbers, the parse* helpers fall back to
//       documented defaults (never 0/NaN) and scan_domain completes.
//  H3 — Given ALERT_WEBHOOK_URL is unparseable or points at a rejecting
//       host, sendAlert resolves (never throws) and is not retried in a loop.
//  H4 — Given BV_RECON is absent, each of the 11 recon tools returns the
//       `unprovisioned` fail-soft shape via handleToolsCall, and scan_domain
//       is unaffected. Given BV_RECON is present but its fetch rejects, the
//       tools degrade without ever producing an MCP-level error or a 500.
//  H5 — Given a client sends an unsupported MCP-Protocol-Version header, POST
//       /mcp (strict) and GET /mcp SSE (lenient) apply opposite postures.
//
// Scope note (per dispatch instructions — grepped test/ first, duplicates
// skipped):
//  - test/chaos/oauth-misconfiguration.chaos.test.ts already covers OAuth
//    secret misconfiguration chaos; not duplicated here.
//  - test/config.spec.ts already unit-tests parseScanTimeout /
//    parsePerCheckTimeout / parseCacheTtl exhaustively (clamping, NaN,
//    non-numeric, sub-floor). H2 below does not re-litigate that matrix; it
//    asserts the fallback value once and focuses on the previously-untested
//    seam — that scan_domain actually COMPLETES when fed the
//    fallback-resolved budgets through runtimeOptions, exactly as
//    src/index.ts wires them.
//  - test/scoring-config-cached.spec.ts already unit-tests
//    parseScoringConfigCached's memoization; H1 below does not re-litigate
//    caching, only the malformed/invalid-input degradation contract and the
//    scan_domain wiring.

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../../src/index';
import { resetSessions } from '../../src/lib/session';
import { resetAllRateLimits } from '../../src/lib/rate-limiter';
import { resetQuotaCoordinatorState } from '../../src/lib/quota-coordinator';
import { IN_MEMORY_CACHE } from '../../src/lib/cache';
import { createDohResponse, setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from '../helpers/dns-mock';

const { restore: restoreFetch } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => {
	restoreFetch();
	vi.restoreAllMocks();
});

/**
 * Minimal "mocked-healthy DNS" fixture for scan_domain — a trimmed copy of
 * test/scan-domain.spec.ts's mockAllChecks(), inlined per the dispatch
 * instruction to keep helpers in-file. Routes by URL/query-type pattern, not
 * by domain name, so any domain string produces the same deterministic
 * answers — which is exactly what H1c/H2's before/after score comparisons
 * need.
 */
function mockHealthyDns(): void {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
				if (url.includes('_domainkey.')) return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
				if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				if (url.includes('_smtp._tls.')) return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				if (url.includes('default._bimi.')) return Promise.resolve(txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']));
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}
			if (url.includes('type=NS') || url.includes('type=2')) return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			if (url.includes('type=CAA') || url.includes('type=257')) return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('example.com', true));
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		}
		return Promise.resolve(httpResponse('OK'));
	});
}

// ---------------------------------------------------------------------------
// H1 — malformed / schema-invalid SCORING_CONFIG degrades, never crashes
// ---------------------------------------------------------------------------
describe('H1: malformed/invalid SCORING_CONFIG degrades to defaults, never crashes', () => {
	beforeEach(async () => {
		const { resetScoringConfigCache } = await import('../../src/lib/scoring-config');
		resetScoringConfigCache();
	});

	it('H1a — [FALSIFIED] malformed-JSON SCORING_CONFIG resolves to DEFAULT_SCORING_CONFIG SILENTLY: parseScoringConfig short-circuits on JSON.parse failure before the warn path ever runs, so no warning is emitted (contract text says "emits one structured warning" — that only holds for the schema-validation-failure branch, see H1b)', async () => {
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
		const { parseScoringConfigCached } = await import('../../src/lib/scoring-config');
		const { DEFAULT_SCORING_CONFIG } = await import('@blackveil/dns-checks/scoring');

		const result = parseScoringConfigCached('{this is not valid json');

		expect(result).toEqual(DEFAULT_SCORING_CONFIG);
		// Negative control lives in H1b: a config that IS valid JSON but fails
		// schema validation DOES warn — proving this assertion is not just a
		// mock/spy wiring failure.
		expect(warnSpy).not.toHaveBeenCalled();
	});

	it('H1b — SCORING_CONFIG that parses as JSON but fails schema validation (typo’d profile name) resolves to defaults AND emits exactly one console.warn; a VALID override (negative control) resolves without warning and actually changes the config', async () => {
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
		const { parseScoringConfigCached } = await import('../../src/lib/scoring-config');
		const { DEFAULT_SCORING_CONFIG } = await import('@blackveil/dns-checks/scoring');

		const invalid = parseScoringConfigCached(JSON.stringify({ profileWeights: { mial_enabled: { spf: 99 } } }));
		expect(invalid).toEqual(DEFAULT_SCORING_CONFIG);
		expect(warnSpy).toHaveBeenCalledTimes(1);
		expect(String(warnSpy.mock.calls[0]?.[0])).toContain('[dns-checks] SCORING_CONFIG');

		// Negative control: a real profile name + real category key must NOT warn,
		// and must actually take effect — proving the harness can tell a rejected
		// override from an accepted one.
		warnSpy.mockClear();
		const { resetScoringConfigCache } = await import('../../src/lib/scoring-config');
		resetScoringConfigCache();
		const valid = parseScoringConfigCached(JSON.stringify({ profileWeights: { mail_enabled: { spf: 5 } } }));
		expect(warnSpy).not.toHaveBeenCalled();
		expect(valid.profileWeights.mail_enabled.spf).toBe(5);
	});

	it('H1c — scan_domain (mocked-healthy DNS) scores IDENTICALLY whether SCORING_CONFIG is malformed JSON or unset', async () => {
		mockHealthyDns();
		const { scanDomain } = await import('../../src/tools/scan-domain');
		const { parseScoringConfigCached, resetScoringConfigCache } = await import('../../src/lib/scoring-config');

		resetScoringConfigCache();
		const controlConfig = parseScoringConfigCached(undefined);
		IN_MEMORY_CACHE.clear();
		const controlResult = await scanDomain('h1-control.example.com', undefined, { scoringConfig: controlConfig });

		resetScoringConfigCache();
		const brokenConfig = parseScoringConfigCached('{this is not valid json');
		IN_MEMORY_CACHE.clear();
		const brokenResult = await scanDomain('h1-broken.example.com', undefined, { scoringConfig: brokenConfig });

		// Negative control: both runs actually measured something — a scan that
		// silently produced zero checks (crashed scoring bundle) would make this
		// equality vacuous.
		expect(controlResult.checks.length).toBeGreaterThan(0);
		expect(brokenResult.checks.length).toBeGreaterThan(0);
		expect(brokenResult.score.overall).toBe(controlResult.score.overall);
		expect(brokenResult.score.grade).toBe(controlResult.score.grade);
	});
});

// ---------------------------------------------------------------------------
// H2 — garbage/negative timeout & TTL env vars fall back to defaults
// ---------------------------------------------------------------------------
describe('H2: garbage/negative SCAN_TIMEOUT_MS / PER_CHECK_TIMEOUT_MS / CACHE_TTL_SECONDS fall back to defaults, scan_domain still completes', () => {
	it('parse* helpers fall back to the documented defaults for garbage and negative input — never 0 or NaN (matrix already exhaustively covered by test/config.spec.ts; asserted once here as setup for the scan_domain-completes assertion below)', async () => {
		const { parseScanTimeout, parsePerCheckTimeout, parseCacheTtl, SCAN_TIMEOUT_MS, PER_CHECK_TIMEOUT_MS, DEFAULT_CACHE_TTL_SECONDS } =
			await import('../../src/lib/config');

		for (const garbage of ['not-a-number', '-500', 'NaN']) {
			const scanMs = parseScanTimeout(garbage);
			const perCheckMs = parsePerCheckTimeout(garbage);
			const ttlSeconds = parseCacheTtl(garbage);
			expect(scanMs).toBe(SCAN_TIMEOUT_MS);
			expect(perCheckMs).toBe(PER_CHECK_TIMEOUT_MS);
			expect(ttlSeconds).toBe(DEFAULT_CACHE_TTL_SECONDS);
			// Negative control against the exact failure this hypothesis guards
			// against: a regression that let garbage input through as 0 or NaN.
			expect(scanMs).not.toBe(0);
			expect(Number.isNaN(scanMs)).toBe(false);
			expect(perCheckMs).not.toBe(0);
			expect(Number.isNaN(perCheckMs)).toBe(false);
			expect(ttlSeconds).not.toBe(0);
			expect(Number.isNaN(ttlSeconds)).toBe(false);
		}
	});

	it('scan_domain (mocked-healthy DNS) completes when wired with the fallback-resolved budgets exactly as src/index.ts wires them from a garbage env', async () => {
		mockHealthyDns();
		const { scanDomain } = await import('../../src/tools/scan-domain');
		const { parseScanTimeout, parsePerCheckTimeout, parseCacheTtl } = await import('../../src/lib/config');
		IN_MEMORY_CACHE.clear();

		const result = await scanDomain('h2-garbage-timeouts.example.com', undefined, {
			scanTimeoutMs: parseScanTimeout('garbage'),
			perCheckTimeoutMs: parsePerCheckTimeout('-999'),
			cacheTtlSeconds: parseCacheTtl('NaN'),
		});

		// Negative control: if the fallback ever regressed to a 0ms/NaN budget,
		// the scan would either throw synchronously or complete with zero
		// measured checks (every check timing out instantly) — assert the
		// opposite: a real, finite, graded result.
		expect(result.checks.length).toBeGreaterThan(0);
		expect(typeof result.score.overall).toBe('number');
		expect(Number.isFinite(result.score.overall as number)).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// H3 — ALERT_WEBHOOK_URL failures resolve, never throw, never retry
// ---------------------------------------------------------------------------
describe('H3: ALERT_WEBHOOK_URL misconfiguration resolves (never throws), and is not retried in a loop', () => {
	it('H3a — [FALSIFIED] an unparseable ALERT_WEBHOOK_URL resolves false WITHOUT calling fetch or logging: sendAlert’s catch on `new URL()` returns false directly, never reaching postWebhookJson’s log call — contract text says "the alert failure is logged"; that only holds once a real HTTP attempt is made (see H3b/H3c)', async () => {
		const logModule = await import('../../src/lib/log');
		const logErrorSpy = vi.spyOn(logModule, 'logError');
		const fetchSpy = vi.fn();
		globalThis.fetch = fetchSpy;

		const { sendAlert } = await import('../../src/lib/alerting');
		const delivered = await sendAlert('not a valid url at all', { text: 'chaos H3a' });

		expect(delivered).toBe(false);
		expect(fetchSpy).not.toHaveBeenCalled();
		expect(logErrorSpy).not.toHaveBeenCalled();
	});

	it('H3b — a rejecting host (non-2xx response) makes sendAlert resolve false, call fetch exactly once (no retry loop), and log exactly one warning', async () => {
		const logModule = await import('../../src/lib/log');
		const logErrorSpy = vi.spyOn(logModule, 'logError');
		const fetchSpy = vi.fn().mockResolvedValue(new Response('nope', { status: 500 }));
		globalThis.fetch = fetchSpy;

		const { sendAlert } = await import('../../src/lib/alerting');
		const delivered = await sendAlert('https://hooks.example.com/webhook', { text: 'chaos H3b' });

		expect(delivered).toBe(false);
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect(logErrorSpy).toHaveBeenCalledTimes(1);
		expect(String(logErrorSpy.mock.calls[0]?.[0])).toContain('HTTP 500');
	});

	it('H3c — a host that refuses the connection (fetch throws) makes sendAlert resolve false, call fetch exactly once, and log exactly one warning; negative control: a healthy 2xx endpoint resolves true and logs nothing', async () => {
		const logModule = await import('../../src/lib/log');
		const logErrorSpy = vi.spyOn(logModule, 'logError');
		const fetchSpy = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
		globalThis.fetch = fetchSpy;

		const { sendAlert } = await import('../../src/lib/alerting');
		const delivered = await sendAlert('https://hooks.example.com/webhook', { text: 'chaos H3c' });

		expect(delivered).toBe(false);
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect(logErrorSpy).toHaveBeenCalledTimes(1);

		// Negative control: a healthy call must resolve true and must NOT log —
		// proving H3b/H3c's `toHaveBeenCalledTimes(1)` is measuring the failure
		// path, not a spy that always fires.
		logErrorSpy.mockClear();
		fetchSpy.mockResolvedValueOnce(new Response('ok', { status: 200 }));
		const ok = await sendAlert('https://hooks.example.com/webhook', { text: 'chaos H3c control' });
		expect(ok).toBe(true);
		expect(logErrorSpy).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// H4 — BV_RECON absent/failing degrades every recon tool, never a 500
// ---------------------------------------------------------------------------
describe('H4: BV_RECON absent or failing degrades every recon tool, never a 500', () => {
	// The 11 operator-only recon tools (bv-mcp-operations SKILL.md: "powers the
	// 11 recon tools"). osint_investigate_username_start/email_start additionally
	// require an allowed authTier before they ever reach the recon binding, so
	// authTier is included on every case for uniformity (harmless for the rest).
	const RECON_TOOL_CASES: Array<{ name: string; arguments: Record<string, unknown> }> = [
		{ name: 'check_realtime_threat_feed', arguments: { domain: 'example.com' } },
		{ name: 'scan_buckets_start', arguments: { target: 'example.com' } },
		{ name: 'scan_buckets_status', arguments: { scanId: 'scan-1' } },
		{ name: 'scan_buckets_findings', arguments: { scanId: 'scan-1' } },
		{ name: 'osint_investigate_domain_start', arguments: { query: 'example.com' } },
		{ name: 'osint_investigate_infrastructure_start', arguments: { query: 'example.com' } },
		{ name: 'osint_investigate_supply_chain_start', arguments: { query: 'example.com' } },
		{ name: 'osint_investigate_username_start', arguments: { query: 'someuser' } },
		{ name: 'osint_investigate_email_start', arguments: { query: 'someone@example.com' } },
		{ name: 'osint_investigation_status', arguments: { investigationId: 'inv-1' } },
		{ name: 'osint_investigation_report', arguments: { investigationId: 'inv-1' } },
	];

	it('sanity: exactly 11 recon tool cases are exercised below', () => {
		expect(RECON_TOOL_CASES).toHaveLength(11);
	});

	it('H4a — with BV_RECON absent (the BSL self-host default: no binding wired unless a test supplies one), each of the 11 recon tools returns the `unprovisioned` fail-soft shape through handleToolsCall, never throwing', async () => {
		const { handleToolsCall } = await import('../../src/handlers/tools');

		for (const toolCase of RECON_TOOL_CASES) {
			const result = await handleToolsCall({ name: toolCase.name, arguments: toolCase.arguments }, undefined, { authTier: 'owner' });
			expect(result.isError, `${toolCase.name} must not be an MCP-level error`).not.toBe(true);
			expect(JSON.stringify(result), `${toolCase.name} must report unprovisioned when BV_RECON is absent`).toContain('"unprovisioned":true');
		}
	});

	it('negative control: scan_domain is unaffected by BV_RECON absence (mocked-healthy DNS, no recon binding wired anywhere)', async () => {
		mockHealthyDns();
		const { scanDomain } = await import('../../src/tools/scan-domain');
		IN_MEMORY_CACHE.clear();
		const result = await scanDomain('h4-control.example.com', undefined, {});
		expect(result.checks.length).toBeGreaterThan(0);
		expect(typeof result.score.overall).toBe('number');
		expect(Number.isFinite(result.score.overall as number)).toBe(true);
	});

	it('H4b — [FALSIFIED] with BV_RECON present but its fetch rejecting, the contract’s "structured error with an allowlisted prefix, not a 500" does not describe the measured behavior: every one of the 11 tools degrades to a normal, non-error CheckResult (isError falsy) carrying `upstreamUnavailable`/`unprovisioned` metadata — it never reaches the JSON-RPC client-error allowlist at all, and it never was going to be a 500 either way (recon-binding.ts fail-soft catches every throw)', async () => {
		const { handleToolsCall } = await import('../../src/handlers/tools');
		const rejectingBinding = { fetch: vi.fn().mockRejectedValue(new Error('ECONNRESET')) };

		for (const toolCase of RECON_TOOL_CASES) {
			const result = await handleToolsCall({ name: toolCase.name, arguments: toolCase.arguments }, undefined, {
				reconBinding: rejectingBinding,
				reconAuthToken: 'tok',
				authTier: 'owner',
			});
			expect(result.isError, `${toolCase.name} must not be an MCP-level error (no 500-equivalent)`).not.toBe(true);
			const text = JSON.stringify(result);
			expect(
				text.includes('"upstreamUnavailable":true') || text.includes('"unprovisioned":true'),
				`${toolCase.name} must degrade to a structured, non-error fail-soft result`,
			).toBe(true);
		}
	});
});

// ---------------------------------------------------------------------------
// H5 — MCP-Protocol-Version header: opposite postures on POST vs GET /mcp
// ---------------------------------------------------------------------------
describe('H5: unsupported MCP-Protocol-Version header — opposite postures on POST vs GET /mcp', () => {
	beforeEach(() => {
		resetAllRateLimits();
		resetQuotaCoordinatorState();
		resetSessions();
	});

	function postMcp(body: unknown, extraHeaders?: Record<string, string>): Request {
		return new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...extraHeaders },
			body: JSON.stringify(body),
		});
	}

	async function initSession(): Promise<string> {
		const ctx = createExecutionContext();
		const res = await worker.fetch(postMcp({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }), env, ctx);
		await waitOnExecutionContext(ctx);
		const id = res.headers.get('mcp-session-id');
		if (!id) throw new Error('initialize did not return a session id');
		return id;
	}

	it('H5a — POST /mcp (strict channel): an unsupported MCP-Protocol-Version header on a post-init request is rejected with HTTP 400', async () => {
		const sessionId = await initSession();
		const ctx = createExecutionContext();
		const res = await worker.fetch(
			postMcp({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }, { 'MCP-Protocol-Version': '1999-01-01', 'Mcp-Session-Id': sessionId }),
			env,
			ctx,
		);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error?: { message?: string } };
		expect(body.error?.message).toContain('Unsupported MCP-Protocol-Version header');
	});

	it('negative control: POST /mcp with a SUPPORTED MCP-Protocol-Version header on the same request succeeds', async () => {
		const sessionId = await initSession();
		const ctx = createExecutionContext();
		const res = await worker.fetch(
			postMcp({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }, { 'MCP-Protocol-Version': '2025-06-18', 'Mcp-Session-Id': sessionId }),
			env,
			ctx,
		);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(200);
	});

	it('H5b — GET /mcp (lenient SSE channel): the SAME unsupported MCP-Protocol-Version header is accepted — the opposite posture from POST, because app.get(\'/mcp\') never calls classifyProtocolVersionHeader at all', async () => {
		const sessionId = await initSession();
		const ctx = createExecutionContext();
		const req = new Request('http://example.com/mcp', {
			method: 'GET',
			headers: { Accept: 'text/event-stream', 'Mcp-Session-Id': sessionId, 'MCP-Protocol-Version': '1999-01-01' },
		});
		const res = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(200);
		expect(res.headers.get('content-type')).toBe('text/event-stream');
	});
});
