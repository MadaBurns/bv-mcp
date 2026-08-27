// SPDX-License-Identifier: BUSL-1.1
/**
 * Fail-soft client for the operator-only bv-recon service binding.
 *
 * Fail-soft: no function throws, so callers degrade to their pre-binding behavior.
 * Mirrors the BV_WHOIS fail-soft pattern in check-rdap-lookup.ts.
 *
 * The async (investigation / bucket-scan) calls return a discriminated
 * `ReconOutcome<T>` rather than `T | null`, so a caller can tell "not provisioned"
 * from "no such id" from "upstream is down" — see `ReconFailureReason`. The
 * synchronous `callReconScan` keeps `T | null`: it has four call sites that only
 * ever ask "did I get intel?", and it already resolves the one distinction that
 * mattered (404 => benign no-match) internally.
 */
import { z } from 'zod';

import { logEvent } from './log';
import type { BindingDegradationKind, BindingDegradationSink } from './binding-degradation';
import { disposeUnreadResponseBody, readJsonResponseCapped } from './response-body';

// Re-export the shared telemetry types so existing importers of these symbols
// from `recon-binding` keep working; the canonical definition lives in
// `./binding-degradation` (unified with the tls-probe client to prevent drift).
export type { BindingDegradationKind, BindingDegradationSink } from './binding-degradation';

/** Minimal Fetcher shape — matches a Cloudflare service binding. */
export interface ReconBinding {
	fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

const RECON_COMPONENT = 'recon';

/** Map a thrown fetch error to a degradation kind. AbortSignal.timeout → timeout. */
function errorToKind(err: unknown): BindingDegradationKind {
	const name = err instanceof Error ? err.name : '';
	return name === 'TimeoutError' || name === 'AbortError' ? 'binding_timeout' : 'binding_unavailable';
}

/**
 * Emit a structured warn log AND invoke the optional sink for a present-but-failing
 * binding. Fail-soft: a throwing sink can never break the fail-soft contract.
 */
function recordReconDegradation(
	kind: BindingDegradationKind,
	telemetry: BindingDegradationSink | undefined,
	context: { route: string; status?: number; domain?: string; errorName?: string },
): void {
	logEvent({
		timestamp: new Date().toISOString(),
		severity: 'warn',
		category: 'binding_degradation',
		result: kind,
		details: {
			component: RECON_COMPONENT,
			route: context.route,
			...(context.status !== undefined ? { status: context.status } : {}),
			...(context.errorName ? { errorName: context.errorName } : {}),
		},
	});
	try {
		telemetry?.({ degradationType: kind, component: RECON_COMPONENT, domain: context.domain });
	} catch {
		// Telemetry must never break the fail-soft binding contract.
	}
}

const RECON_TIMEOUT_MS = 8_000;
const RECON_MAX_BODY_BYTES = 5 * 1024 * 1024;

export type ReconScanType = 'MALICIOUS_ASN' | 'CT_LOOKALIKE' | 'ATTACKER_INFRASTRUCTURE' | 'REALTIME_THREAT_FEED';

/** Defensive shape of a bv-recon /osint/check DNSCheckResult response.
 *  All fields optional/lenient so unknown extra fields never fail validation. */
const ReconScanResponseSchema = z
	.object({
		checkType: z.string().optional(),
		status: z.string().optional(),
		score: z.number().nullable().optional(),
		details: z.string().optional(),
		records: z.array(z.unknown()).optional(),
		metadata: z.record(z.string(), z.unknown()).optional(),
	})
	.passthrough();
export type ReconScanResult = z.infer<typeof ReconScanResponseSchema>;

/**
 * Returns true when a DNSCheckResult status indicates a threat signal.
 * Benign statuses ('info', 'pass', 'ok', 'low', undefined) return false.
 */
export function isReconHit(status: string | undefined): boolean {
	return !!status && ['warning', 'fail', 'critical', 'high', 'medium'].includes(status.toLowerCase());
}

function composeSignal(caller?: AbortSignal): AbortSignal {
	const t = AbortSignal.timeout(RECON_TIMEOUT_MS);
	return caller ? AbortSignal.any([t, caller]) : t;
}

export async function callReconScan(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	type: ReconScanType,
	target: { domain?: string; ip?: string; asn?: number },
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconScanResult | null> {
	// Absent binding (BSL self-host) is expected, NOT a degradation — stay silent.
	if (!binding) return null;
	try {
		const qs = new URLSearchParams({ type });
		if (target.domain) qs.set('domain', target.domain);
		if (target.ip) qs.set('ip', target.ip);
		if (target.asn != null) qs.set('asn', String(target.asn));
		const resp = await binding.fetch(`https://bv-recon/osint/check?${qs.toString()}`, {
			method: 'GET',
			headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
			signal: composeSignal(signal),
		});
		// A 404 from the intelligence /check means the threat feed has no entry for
		// this target — i.e. no adverse intel (benign), NOT a provisioning failure.
		// Return a benign result so callers render "no hits" instead of "unavailable".
		// (The route 404 is fixed + regression-tested in bv-recon, so a 404 here is a
		// data miss, not a misroute.) Stays SILENT — not a degradation.
		if (resp.status === 404) {
			await disposeUnreadResponseBody(resp);
			return { status: 'info', details: 'No threat-intelligence match for this target.' };
		}
		// Other non-2xx (5xx / auth) are a present-binding failure: record + null.
		if (!resp.ok) {
			await disposeUnreadResponseBody(resp);
			recordReconDegradation('binding_5xx', telemetry, { route: '/osint/check', status: resp.status, domain: target.domain });
			return null;
		}
		const parsed = ReconScanResponseSchema.safeParse(await readJsonResponseCapped(resp, RECON_MAX_BODY_BYTES));
		return parsed.success ? parsed.data : null;
	} catch (err) {
		recordReconDegradation(errorToKind(err), telemetry, {
			route: '/osint/check',
			domain: target.domain,
			errorName: err instanceof Error ? err.name : undefined,
		});
		return null;
	}
}

export type ReconInvestigationType = 'domain' | 'deep_infrastructure' | 'supply_chain' | 'username' | 'email';

const InvestigationStartSchema = z
	.object({
		investigationId: z.string(),
		workflowId: z.string().optional(),
		status: z.string().optional(),
		pollUrl: z.string().optional(),
	})
	.passthrough();
export type InvestigationStart = z.infer<typeof InvestigationStartSchema>;

const BucketScanStartSchema = z.object({ scanId: z.string(), status: z.string().optional() }).passthrough();
export type BucketScanStart = z.infer<typeof BucketScanStartSchema>;

/** Status/report/findings bodies pass through opaquely. Require an object (rejects null/array/scalar). */
const OpaqueObjectSchema = z.record(z.string(), z.unknown());
export type ReconOpaque = Record<string, unknown>;

/**
 * Why an async recon call produced no data.
 *
 * These are NOT interchangeable, and collapsing them is what #695 was really about:
 *
 * - `unbound`      — no BV_RECON binding (BSL self-host). Structural + permanent. Expected,
 *                    so it is SILENT: not a degradation, never alertable.
 * - `not_found`    — upstream answered **definitively** with 404: no such investigation/scan,
 *                    or it has expired, or the caller raced a `*_start`. Also SILENT — a data
 *                    miss is not a binding failure. `binding-degradation.ts` already documents
 *                    that the kind set "deliberately excludes ... the benign recon 404"; before
 *                    this discriminant existed only `callReconScan` honored it, so every poll of
 *                    an unknown id on THIS path emitted a false `binding_5xx` into the operator
 *                    degradation alert.
 * - `unauthorized` — 401/403. The binding is bound but the credential was rejected: an operator
 *                    misconfiguration, distinct from an outage and from a data miss.
 * - `upstream_status` — any other non-2xx. Genuine upstream failure.
 * - `malformed`    — 2xx whose body failed schema validation. Contract drift, not an outage.
 * - `transport`    — the fetch threw (network, timeout, abort).
 *
 * Everything except `unbound` and `not_found` still records a degradation, with the SAME
 * `BindingDegradationKind` mapping as before this refactor — the discriminant is for callers;
 * re-tuning alert routing is a separate, operator-visible decision and is deliberately not
 * bundled in here.
 */
export type ReconFailureReason = 'unbound' | 'not_found' | 'unauthorized' | 'upstream_status' | 'malformed' | 'transport';

/** Discriminated result of an async recon call. Replaces the former `T | null`. */
export type ReconOutcome<T> = { ok: true; data: T } | { ok: false; reason: ReconFailureReason; status?: number };

/** True when the failure is a transient upstream condition worth retrying on the next poll. */
export function isRetryableReconFailure(reason: ReconFailureReason): boolean {
	return reason === 'upstream_status' || reason === 'transport' || reason === 'not_found';
}

function reconFailure<T>(reason: ReconFailureReason, status?: number): ReconOutcome<T> {
	return status === undefined ? { ok: false, reason } : { ok: false, reason, status };
}

async function reconJson(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	path: string,
	init: RequestInit,
	schema: z.ZodType,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconOutcome<unknown>> {
	// Absent binding (BSL self-host) is expected, NOT a degradation — stay silent.
	if (!binding) return reconFailure('unbound');
	try {
		const resp = await binding.fetch(`https://bv-recon${path}`, {
			...init,
			headers: { ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}), ...(init.headers ?? {}) },
			signal: composeSignal(signal),
		});
		// A 404 is a DATA MISS (unknown/expired id, or a poll that raced its own start), not a
		// binding failure. Stay SILENT, matching `callReconScan` and the contract documented on
		// `BindingDegradationKind`.
		if (resp.status === 404) {
			await disposeUnreadResponseBody(resp);
			return reconFailure('not_found', 404);
		}
		if (resp.status === 401 || resp.status === 403) {
			await disposeUnreadResponseBody(resp);
			recordReconDegradation('binding_5xx', telemetry, { route: path, status: resp.status });
			return reconFailure('unauthorized', resp.status);
		}
		if (!resp.ok) {
			await disposeUnreadResponseBody(resp);
			recordReconDegradation('binding_5xx', telemetry, { route: path, status: resp.status });
			return reconFailure('upstream_status', resp.status);
		}
		// `.catch(() => null)` matches `callReconScan`: a 2xx whose body is not even JSON (an HTML
		// error page, a truncated response) is CONTRACT DRIFT, not an outage. Without the guard the
		// throw escapes to the outer catch and is reported as `transport` WITH a `binding_unavailable`
		// degradation — a false operator alert, the same defect class as the 404 this refactor fixed.
		const parsed = schema.safeParse(await readJsonResponseCapped(resp, RECON_MAX_BODY_BYTES));
		return parsed.success ? { ok: true, data: parsed.data } : reconFailure('malformed', resp.status);
	} catch (err) {
		recordReconDegradation(errorToKind(err), telemetry, { route: path, errorName: err instanceof Error ? err.name : undefined });
		return reconFailure('transport');
	}
}

export function callReconInvestigateStart(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	type: ReconInvestigationType,
	query: string,
	options?: Record<string, unknown>,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconOutcome<InvestigationStart>> {
	return reconJson(
		binding,
		authToken,
		`/osint/api/investigate/${type}`,
		{ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query, options: options ?? {} }) },
		InvestigationStartSchema,
		signal,
		telemetry,
	) as Promise<ReconOutcome<InvestigationStart>>;
}

export function callReconInvestigationStatus(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	id: string,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconOutcome<ReconOpaque>> {
	return reconJson(
		binding,
		authToken,
		`/osint/api/investigation/${encodeURIComponent(id)}`,
		{ method: 'GET' },
		OpaqueObjectSchema,
		signal,
		telemetry,
	) as Promise<ReconOutcome<ReconOpaque>>;
}

export function callReconInvestigationReport(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	id: string,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconOutcome<ReconOpaque>> {
	return reconJson(
		binding,
		authToken,
		`/osint/api/investigation/${encodeURIComponent(id)}/findings`,
		{ method: 'GET' },
		OpaqueObjectSchema,
		signal,
		telemetry,
	) as Promise<ReconOutcome<ReconOpaque>>;
}

export function callReconBucketScanStart(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	body: Record<string, unknown>,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconOutcome<BucketScanStart>> {
	return reconJson(
		binding,
		authToken,
		`/buckets/api/scan/trigger`,
		{ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
		BucketScanStartSchema,
		signal,
		telemetry,
	) as Promise<ReconOutcome<BucketScanStart>>;
}

export function callReconBucketScanStatus(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	scanId: string,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconOutcome<ReconOpaque>> {
	return reconJson(
		binding,
		authToken,
		`/buckets/api/scan/status/${encodeURIComponent(scanId)}`,
		{ method: 'GET' },
		OpaqueObjectSchema,
		signal,
		telemetry,
	) as Promise<ReconOutcome<ReconOpaque>>;
}

export function callReconBucketFindings(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	scanId: string | undefined,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconOutcome<ReconOpaque>> {
	const qs = scanId ? `?scanId=${encodeURIComponent(scanId)}` : '';
	return reconJson(binding, authToken, `/buckets/api/findings${qs}`, { method: 'GET' }, OpaqueObjectSchema, signal, telemetry) as Promise<
		ReconOutcome<ReconOpaque>
	>;
}
