// SPDX-License-Identifier: BUSL-1.1
/**
 * Shared binding-degradation telemetry for operator-only service bindings
 * (BV_RECON / BV_TLS_PROBE report from their own clients; BV_INFRA_PROBE /
 * BV_WHOIS / BV_CERTSTREAM through `withSidecarDegradationTelemetry`). Unified
 * here so every client imports ONE definition and cannot drift.
 */

import { logEvent } from './log';

/**
 * Binding-degradation kinds for a PRESENT-but-failing operator service binding.
 * Deliberately excludes absent-binding (BSL self-host — expected, not alertable).
 * Mirrors the matching members on the analytics `degradation` event
 * (`binding_unavailable` | `binding_5xx` | `binding_timeout` | `binding_route_absent`).
 *
 * `binding_route_absent` is a recon 404 on `/osint/check`: the binding answered but
 * the upstream does not serve that route (SQ-502/SQ-514). The caller still reports
 * the enrichment as unavailable, but it is a known standing condition rather than an
 * outage, so `queryBindingDegradation` excludes it from the paging alert while it
 * stays queryable in Analytics Engine (and is the signal that bv2-recon has started
 * serving the route once it stops appearing).
 */
export type BindingDegradationKind = 'binding_unavailable' | 'binding_5xx' | 'binding_timeout' | 'binding_route_absent';

/**
 * Optional telemetry callback invoked ONLY when a present binding fails. The
 * caller forwards a sink that emits the analytics `degradation` event; the
 * binding additionally emits a structured warn log on its own. Fail-soft: the
 * binding never throws if the sink does.
 *
 * `component` carries which binding failed (`recon` | `tls_probe` | `infra_probe` |
 * `whois` | `certstream`).
 */
export type BindingDegradationSink = (event: { degradationType: BindingDegradationKind; component: string; domain?: string }) => void;

/** A fetch-only service binding, as the sidecar runtime options type them. */
export interface FetchBinding {
	fetch: typeof fetch;
}

/** Wrappers already instrumented, so a nested tool call cannot report one failure twice. */
const INSTRUMENTED = new WeakSet<FetchBinding>();

/**
 * Wrap a PRESENT sidecar binding so a failed call reaches the binding-degradation
 * alert path: a structured warn log plus the optional sink. The response or the
 * rejection is passed through untouched, so each caller keeps its own fail-soft
 * handling. Recorded: a thrown fetch (`binding_timeout` for a timeout, else
 * `binding_unavailable`) and HTTP >= 500 (`binding_5xx`). Not recorded: a 4xx (a
 * sidecar answering "no data" or "bad input" is up) and a caller abort (the caller
 * stopped, the binding did not fail). An absent binding stays absent and silent.
 */
export function withBindingDegradationTelemetry(
	binding: FetchBinding | undefined,
	component: string,
	sink: BindingDegradationSink | undefined,
	domain?: () => string | undefined,
): FetchBinding | undefined {
	if (!binding || INSTRUMENTED.has(binding)) return binding;
	const record = (kind: BindingDegradationKind, details: { status?: number; errorName?: string }) => {
		try {
			logEvent({
				timestamp: new Date().toISOString(),
				severity: 'warn',
				category: 'binding_degradation',
				result: kind,
				details: { component, ...details },
			});
			const d = domain?.();
			sink?.({ degradationType: kind, component, ...(d ? { domain: d } : {}) });
		} catch {
			// Telemetry must never change what the caller sees from the binding.
		}
	};
	const wrapped: FetchBinding = {
		fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
			let response: Response;
			try {
				response = await binding.fetch(input, init);
			} catch (err) {
				const errorName = typeof (err as { name?: unknown })?.name === 'string' ? (err as { name: string }).name : '';
				const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
				if (signal?.aborted) {
					// Some bindings reject with AbortError even for an explicit local timeout.
					if (signal.reason?.name === 'TimeoutError') record('binding_timeout', { errorName: 'TimeoutError' });
				} else if (errorName !== 'AbortError') {
					record(errorName === 'TimeoutError' ? 'binding_timeout' : 'binding_unavailable', errorName ? { errorName } : {});
				}
				throw err;
			}
			if (response.status >= 500) record('binding_5xx', { status: response.status });
			return response;
		}) as typeof fetch,
	};
	INSTRUMENTED.add(wrapped);
	return wrapped;
}

/**
 * Instrument the sidecar bindings on a tool call's runtime options: BV_INFRA_PROBE
 * (`infra_probe`), BV_WHOIS (`whois`) and BV_CERTSTREAM (`certstream`). Their callers
 * degrade fail-soft on their own, so without this a sidecar outage raised no alert.
 * Recon and tls-probe report from inside their own clients and are not wrapped here.
 */
export function withSidecarDegradationTelemetry<
	T extends {
		onBindingDegradation?: BindingDegradationSink;
		infraProbe?: FetchBinding;
		whoisBinding?: FetchBinding;
		certstream?: FetchBinding;
	},
>(options: T, domain?: () => string | undefined): T {
	if (!options.infraProbe && !options.whoisBinding && !options.certstream) return options;
	const sink = options.onBindingDegradation;
	return {
		...options,
		...(options.infraProbe ? { infraProbe: withBindingDegradationTelemetry(options.infraProbe, 'infra_probe', sink, domain) } : {}),
		...(options.whoisBinding ? { whoisBinding: withBindingDegradationTelemetry(options.whoisBinding, 'whois', sink, domain) } : {}),
		...(options.certstream ? { certstream: withBindingDegradationTelemetry(options.certstream, 'certstream', sink, domain) } : {}),
	} as T;
}
