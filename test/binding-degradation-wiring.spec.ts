// SPDX-License-Identifier: BUSL-1.1
/**
 * R1 wiring spec: the analytics `degradation` event must actually be emitted at
 * runtime when a PRESENT operator binding (BV_RECON / BV_TLS_PROBE) fails during
 * a tool call routed through `handleToolsCall`.
 *
 * The binding-level telemetry (warn log + sink invocation on present-but-failing
 * branches) is already covered by `recon-binding.spec.ts` / `tls-probe-binding.spec.ts`.
 * This spec verifies the MISSING upstream wiring: that the registry forwards
 * `ro.onBindingDegradation` into each recon/tls tool's options object, and that the
 * dispatch seam builds that sink from `ro.analytics` (so `emitDegradationEvent`
 * fires with the right degradationType + component). Absent-binding must stay SILENT;
 * a recon 404 (the /osint/check route is absent upstream — SQ-502) is a degradation.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { TLS_VERSION_ENRICHMENT_ENABLED } from '../src/lib/tls-probe-binding';
import type { AnalyticsClient } from '../src/lib/analytics';

afterEach(() => {
	vi.restoreAllMocks();
	IN_MEMORY_CACHE.clear();
});

/** Minimal analytics client whose emitDegradationEvent is observable. */
function fakeAnalytics(): { client: AnalyticsClient; emit: ReturnType<typeof vi.fn> } {
	const emit = vi.fn();
	const noop = () => {};
	const client: AnalyticsClient = {
		enabled: true,
		emitRequestEvent: noop,
		emitToolEvent: noop,
		emitRateLimitEvent: noop,
		emitSessionEvent: noop,
		emitDegradationEvent: emit,
		emitUngradedNotCachedEvent: noop,
		emitDohPrimarySummary: noop,
		emitQuotaShardEvent: noop,
		emitQueueBatchEvent: noop,
		emitTailAggregate: noop,
	};
	return { client, emit };
}

/**
 * Build the ToolRuntimeOptions sink the SAME way the dispatch seam does
 * (`options.analytics ? (e) => options.analytics.emitDegradationEvent(e) : undefined`),
 * so the test exercises the production wiring rather than a hand-rolled sink.
 */
function sinkFromAnalytics(client: AnalyticsClient | undefined) {
	return client
		? (e: {
				degradationType: 'binding_unavailable' | 'binding_5xx' | 'binding_timeout' | 'binding_route_absent';
				component: string;
				domain?: string;
			}) => client.emitDegradationEvent(e)
		: undefined;
}

/** A recon binding whose fetch resolves with a given status / body. */
function reconBindingStatus(status: number, body: unknown = { error: 'x' }) {
	return {
		fetch: vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })),
	};
}

/** A recon binding whose fetch rejects (network error → binding_unavailable). */
function reconBindingNetworkError() {
	return {
		fetch: vi.fn(async () => {
			throw new Error('boom');
		}),
	};
}

describe('R1 binding-degradation sink wiring (recon path via handleToolsCall)', () => {
	async function callRealtimeThreatFeed(domain: string, opts: { reconBinding?: { fetch: typeof fetch }; analytics?: AnalyticsClient }) {
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name: 'check_realtime_threat_feed', arguments: { domain } }, undefined, {
			reconBinding: opts.reconBinding,
			reconAuthToken: 'tok',
			analytics: opts.analytics,
			onBindingDegradation: sinkFromAnalytics(opts.analytics),
		});
	}

	it('emits a `degradation` event (binding_5xx, component=recon) on a present-but-5xx binding', async () => {
		const { client, emit } = fakeAnalytics();
		await callRealtimeThreatFeed('recon-fivexx.com', { reconBinding: reconBindingStatus(503), analytics: client });
		expect(emit).toHaveBeenCalledTimes(1);
		expect(emit).toHaveBeenCalledWith({ degradationType: 'binding_5xx', component: 'recon', domain: 'recon-fivexx.com' });
	});

	it('emits a `degradation` event (binding_unavailable, component=recon) on a network error', async () => {
		const { client, emit } = fakeAnalytics();
		await callRealtimeThreatFeed('recon-neterr.com', { reconBinding: reconBindingNetworkError(), analytics: client });
		expect(emit).toHaveBeenCalledTimes(1);
		expect(emit).toHaveBeenCalledWith({ degradationType: 'binding_unavailable', component: 'recon', domain: 'recon-neterr.com' });
	});

	it('stays SILENT when the binding is ABSENT (BSL self-host — expected, not alertable)', async () => {
		const { client, emit } = fakeAnalytics();
		await callRealtimeThreatFeed('recon-absent.com', { reconBinding: undefined, analytics: client });
		expect(emit).not.toHaveBeenCalled();
	});

	it('emits binding_route_absent on a recon 404 and never reports a clean "no hits" (route absent upstream — SQ-502/SQ-514)', async () => {
		const { client, emit } = fakeAnalytics();
		const res = await callRealtimeThreatFeed('recon-route404.com', { reconBinding: reconBindingStatus(404), analytics: client });
		expect(emit).toHaveBeenCalledTimes(1);
		expect(emit).toHaveBeenCalledWith({ degradationType: 'binding_route_absent', component: 'recon', domain: 'recon-route404.com' });
		const text = JSON.stringify(res);
		expect(text).not.toContain('No realtime threat-feed hits');
		expect(text).not.toContain('No threat-intelligence match');
	});

	it('does NOT emit when no analytics client is wired (sink undefined — only the warn log fires)', async () => {
		const warn = vi.spyOn(console, 'log').mockImplementation(() => {});
		// No analytics → dispatch builds an undefined sink → registry forwards undefined.
		await callRealtimeThreatFeed('recon-noanalytics.com', { reconBinding: reconBindingStatus(503), analytics: undefined });
		// The binding still warn-logs its degradation even with no sink.
		const logged = warn.mock.calls.map((c) => String(c[0])).join('\n');
		expect(logged).toContain('binding_degradation');
	});
});

describe('R1 binding-degradation sink wiring (tls-probe path via handleToolsCall / check_ssl)', () => {
	/**
	 * check_ssl runs the normal SSL check first, then calls the tls-probe binding.
	 * We only need the probe path to fail to assert the sink fires; the underlying
	 * SSL DNS/HTTP fetches are irrelevant to the degradation wiring. We force the
	 * probe binding to 5xx and assert the tls_probe degradation event is emitted.
	 *
	 * ⚠️ Origin TLS-version enrichment is WITHDRAWN (`TLS_VERSION_ENRICHMENT_ENABLED`
	 * = false): check_ssl short-circuits before `callTlsProbe`, so the probe is never
	 * dispatched and this seam is unreachable. Rather than delete the emission gate —
	 * which would let the wiring rot silently and resurface as a telemetry blind spot
	 * the day enrichment is restored — the two expectations below are mutually
	 * exclusive on the flag: exactly one runs, so flipping the flag back on
	 * automatically re-arms the emission gate instead of leaving a dead test behind.
	 */
	function tlsProbeStatus(status: number) {
		return { fetch: vi.fn(async () => new Response(JSON.stringify({ error: 'x' }), { status })) };
	}

	/** Drive check_ssl through the dispatch seam with a present-but-5xx probe binding. */
	async function callCheckSslWith5xxProbe(domain: string) {
		const { client, emit } = fakeAnalytics();
		const binding = tlsProbeStatus(502);
		// Keep the SSL check's own fetches deterministic — the probe uses the
		// binding's fetch (not global), so a simple OK response is enough here.
		globalThis.fetch = vi.fn(async () => new Response('OK', { status: 200 })) as unknown as typeof fetch;
		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall({ name: 'check_ssl', arguments: { domain } }, undefined, {
			tlsProbeBinding: binding,
			tlsProbeAuthToken: 'tls-probe-degradation-key-32-bytes-minimum',
			analytics: client,
			onBindingDegradation: sinkFromAnalytics(client),
		});
		return { emit, binding };
	}

	it.skipIf(!TLS_VERSION_ENRICHMENT_ENABLED)(
		'emits a `degradation` event (binding_5xx, component=tls_probe) on a present-but-5xx probe binding',
		async () => {
			const { emit } = await callCheckSslWith5xxProbe('tlsfail-probe.com');
			expect(emit).toHaveBeenCalledWith(expect.objectContaining({ degradationType: 'binding_5xx', component: 'tls_probe' }));
		},
	);

	it.skipIf(TLS_VERSION_ENRICHMENT_ENABLED)(
		'stays SILENT while TLS-version enrichment is withdrawn — the probe is never dispatched, so nothing can degrade',
		async () => {
			const { emit, binding } = await callCheckSslWith5xxProbe('tls-withdrawn-probe.com');
			expect(binding.fetch).not.toHaveBeenCalled();
			expect(emit).not.toHaveBeenCalled();
		},
	);
});

describe('sidecar binding-degradation wiring (infra-probe / whois / certstream via handleToolsCall)', () => {
	const savedFetch = globalThis.fetch;
	afterEach(() => {
		globalThis.fetch = savedFetch;
	});

	/** Every non-binding outbound request (RDAP, CT fallbacks, DoH) is a 503. */
	function upstreamDown() {
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) {
				return new Response(
					JSON.stringify({
						version: '1.0',
						publication: '2024-01-01T00:00:00Z',
						services: [[['com'], ['https://rdap.example.com/com/v1/']]],
					}),
					{ status: 200, headers: { 'Content-Type': 'application/json' } },
				);
			}
			return new Response('upstream unavailable', { status: 503 });
		}) as unknown as typeof fetch;
	}

	async function call(name: string, args: Record<string, unknown>, ro: Record<string, unknown>) {
		const { client, emit } = fakeAnalytics();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall({ name, arguments: args }, undefined, {
			...ro,
			analytics: client,
			onBindingDegradation: sinkFromAnalytics(client),
		});
		return emit;
	}

	it('infra-probe: a present-but-5xx BV_INFRA_PROBE emits binding_5xx (component=infra_probe)', async () => {
		upstreamDown();
		const infraProbe = { fetch: vi.fn(async () => new Response(JSON.stringify({ error: 'x' }), { status: 503 })) };
		const emit = await call('check_root_server_set', {}, { infraProbe });
		expect(infraProbe.fetch).toHaveBeenCalled();
		expect(emit).toHaveBeenCalledWith(expect.objectContaining({ degradationType: 'binding_5xx', component: 'infra_probe' }));
	});

	it('whois: a present-but-failing BV_WHOIS emits binding_unavailable (component=whois)', async () => {
		upstreamDown();
		const whoisBinding = {
			fetch: vi.fn(async () => {
				throw new TypeError('whois shim unreachable');
			}),
		};
		const emit = await call('rdap_lookup', { domain: 'whois.example.com' }, { whoisBinding });
		expect(whoisBinding.fetch).toHaveBeenCalled();
		expect(emit).toHaveBeenCalledWith({ degradationType: 'binding_unavailable', component: 'whois', domain: 'whois.example.com' });
	});

	it('certstream: a present-but-5xx BV_CERTSTREAM emits binding_5xx (component=certstream)', async () => {
		upstreamDown();
		const certstream = { fetch: vi.fn(async () => new Response('down', { status: 502 })) };
		const emit = await call('discover_subdomains', { domain: 'certstream.example.com' }, { certstream, certstreamAuthToken: 'tok' });
		expect(certstream.fetch).toHaveBeenCalled();
		expect(emit).toHaveBeenCalledWith(
			expect.objectContaining({ degradationType: 'binding_5xx', component: 'certstream', domain: 'certstream.example.com' }),
		);
	});

	it('stays SILENT when the sidecar bindings are absent (BSL self-host — expected, not alertable)', async () => {
		upstreamDown();
		const emit = await call('check_root_server_set', {}, {});
		expect(emit).not.toHaveBeenCalled();
	});
});

describe('withBindingDegradationTelemetry', () => {
	async function wrap(impl: () => Promise<Response>) {
		const { withBindingDegradationTelemetry } = await import('../src/lib/binding-degradation');
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const sink = vi.fn();
		const binding = { fetch: vi.fn(impl) as unknown as typeof fetch };
		return { wrapped: withBindingDegradationTelemetry(binding, 'whois', sink)!, sink };
	}

	it.each(['discovery', 'certificate metadata', 'caller cancellation'])('classifies an actual certstream wait during %s', async (mode) => {
		const { withBindingDegradationTelemetry } = await import('../src/lib/binding-degradation');
		const { fetchCertIssuerFromCertstream } = await import('../src/tools/scan/cdn-heuristics');
		const { CT_SOURCE_TIMEOUT_MS, discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const sink = vi.fn();
		const fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
			const abort = () => reject(new DOMException('aborted', 'AbortError'));
			if (init?.signal?.aborted) abort();
			else init?.signal?.addEventListener('abort', abort, { once: true });
		}));
		const binding = withBindingDegradationTelemetry({ fetch: fetch as typeof globalThis.fetch }, 'certstream', sink)!;
		vi.useFakeTimers();
		try {
			const outer = new AbortController();
			const pending = mode === 'certificate metadata'
				? fetchCertIssuerFromCertstream('example.com', binding, undefined, CT_SOURCE_TIMEOUT_MS)
				: discoverSubdomains('example.com', binding, undefined, {
					forceRefresh: true, signal: outer.signal, deadlineMs: Date.now() + CT_SOURCE_TIMEOUT_MS,
				});
			if (mode === 'caller cancellation') {
				vi.setSystemTime(Date.now() + CT_SOURCE_TIMEOUT_MS);
				outer.abort(new DOMException('Caller deadline elapsed', 'TimeoutError'));
			}
			await vi.advanceTimersByTimeAsync(CT_SOURCE_TIMEOUT_MS);
			await pending;
		} finally {
			vi.useRealTimers();
		}
		expect(fetch).toHaveBeenCalledOnce();
		if (mode === 'caller cancellation') expect(sink).not.toHaveBeenCalled();
		else expect(sink).toHaveBeenCalledWith({ degradationType: 'binding_timeout', component: 'certstream' });
	});

	it('records a timeout as binding_timeout and passes the rejection through', async () => {
		const { wrapped, sink } = await wrap(async () => {
			throw new DOMException('timed out', 'TimeoutError');
		});
		await expect(wrapped.fetch('https://bv-whois/lookup')).rejects.toMatchObject({ name: 'TimeoutError' });
		expect(sink).toHaveBeenCalledWith({ degradationType: 'binding_timeout', component: 'whois' });
	});

	it('does not record a 4xx answer or a caller abort, and returns the response untouched', async () => {
		const notFound = new Response('no data', { status: 404 });
		const answered = await wrap(async () => notFound);
		expect(await answered.wrapped.fetch('https://bv-whois/lookup')).toBe(notFound);
		expect(answered.sink).not.toHaveBeenCalled();

		const aborted = await wrap(async () => {
			throw new DOMException('aborted', 'AbortError');
		});
		await expect(aborted.wrapped.fetch('https://bv-whois/lookup')).rejects.toMatchObject({ name: 'AbortError' });
		expect(aborted.sink).not.toHaveBeenCalled();
	});

	it('wraps once: re-instrumenting an instrumented binding (a nested tool call) does not double-report', async () => {
		const { withBindingDegradationTelemetry } = await import('../src/lib/binding-degradation');
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const sink = vi.fn();
		const once = withBindingDegradationTelemetry(
			{ fetch: vi.fn(async () => new Response('', { status: 500 })) as unknown as typeof fetch },
			'whois',
			sink,
		)!;
		const twice = withBindingDegradationTelemetry(once, 'whois', sink)!;
		await twice.fetch('https://bv-whois/lookup');
		expect(twice).toBe(once);
		expect(sink).toHaveBeenCalledTimes(1);
	});
});
