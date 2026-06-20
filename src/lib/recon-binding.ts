// SPDX-License-Identifier: BUSL-1.1
/**
 * Fail-soft client for the operator-only bv-recon service binding.
 *
 * Every function returns null on any failure (binding absent, non-2xx,
 * malformed body, network error) so callers degrade to their pre-binding
 * behavior. Mirrors the BV_WHOIS fail-soft pattern in check-rdap-lookup.ts.
 */
import { z } from 'zod';

import { logEvent } from './log';
import type { BindingDegradationKind, BindingDegradationSink } from './binding-degradation';

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
			return { status: 'info', details: 'No threat-intelligence match for this target.' };
		}
		// Other non-2xx (5xx / auth) are a present-binding failure: record + null.
		if (!resp.ok) {
			recordReconDegradation('binding_5xx', telemetry, { route: '/osint/check', status: resp.status, domain: target.domain });
			return null;
		}
		const parsed = ReconScanResponseSchema.safeParse(await resp.json().catch(() => null));
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

async function reconJson(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	path: string,
	init: RequestInit,
	schema: z.ZodType,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<unknown | null> {
	// Absent binding (BSL self-host) is expected, NOT a degradation — stay silent.
	if (!binding) return null;
	try {
		const resp = await binding.fetch(`https://bv-recon${path}`, {
			...init,
			headers: { ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}), ...(init.headers ?? {}) },
			signal: composeSignal(signal),
		});
		if (!resp.ok) {
			recordReconDegradation('binding_5xx', telemetry, { route: path, status: resp.status });
			return null;
		}
		const parsed = schema.safeParse(await resp.json());
		return parsed.success ? parsed.data : null;
	} catch (err) {
		recordReconDegradation(errorToKind(err), telemetry, { route: path, errorName: err instanceof Error ? err.name : undefined });
		return null;
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
): Promise<InvestigationStart | null> {
	return reconJson(
		binding,
		authToken,
		`/osint/api/investigate/${type}`,
		{ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query, options: options ?? {} }) },
		InvestigationStartSchema,
		signal,
		telemetry,
	) as Promise<InvestigationStart | null>;
}

export function callReconInvestigationStatus(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	id: string,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconOpaque | null> {
	return reconJson(
		binding,
		authToken,
		`/osint/api/investigation/${encodeURIComponent(id)}`,
		{ method: 'GET' },
		OpaqueObjectSchema,
		signal,
		telemetry,
	) as Promise<ReconOpaque | null>;
}

export function callReconInvestigationReport(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	id: string,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconOpaque | null> {
	return reconJson(
		binding,
		authToken,
		`/osint/api/investigation/${encodeURIComponent(id)}/findings`,
		{ method: 'GET' },
		OpaqueObjectSchema,
		signal,
		telemetry,
	) as Promise<ReconOpaque | null>;
}

export function callReconBucketScanStart(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	body: Record<string, unknown>,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<BucketScanStart | null> {
	return reconJson(
		binding,
		authToken,
		`/buckets/api/scan/trigger`,
		{ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
		BucketScanStartSchema,
		signal,
		telemetry,
	) as Promise<BucketScanStart | null>;
}

export function callReconBucketScanStatus(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	scanId: string,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconOpaque | null> {
	return reconJson(
		binding,
		authToken,
		`/buckets/api/scan/status/${encodeURIComponent(scanId)}`,
		{ method: 'GET' },
		OpaqueObjectSchema,
		signal,
		telemetry,
	) as Promise<ReconOpaque | null>;
}

export function callReconBucketFindings(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	scanId: string | undefined,
	signal?: AbortSignal,
	telemetry?: BindingDegradationSink,
): Promise<ReconOpaque | null> {
	const qs = scanId ? `?scanId=${encodeURIComponent(scanId)}` : '';
	return reconJson(
		binding,
		authToken,
		`/buckets/api/findings${qs}`,
		{ method: 'GET' },
		OpaqueObjectSchema,
		signal,
		telemetry,
	) as Promise<ReconOpaque | null>;
}
