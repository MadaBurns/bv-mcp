// SPDX-License-Identifier: BUSL-1.1
/**
 * Fail-soft client for the operator-only bv-recon service binding.
 *
 * Every function returns null on any failure (binding absent, non-2xx,
 * malformed body, network error) so callers degrade to their pre-binding
 * behavior. Mirrors the BV_WHOIS fail-soft pattern in check-rdap-lookup.ts.
 */
import { z } from 'zod';

/** Minimal Fetcher shape — matches a Cloudflare service binding. */
export interface ReconBinding {
	fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
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
): Promise<ReconScanResult | null> {
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
		// data miss, not a misroute.) Other non-2xx (5xx/auth) stay null → unavailable.
		if (resp.status === 404) {
			return { status: 'info', details: 'No threat-intelligence match for this target.' };
		}
		if (!resp.ok) return null;
		const parsed = ReconScanResponseSchema.safeParse(await resp.json().catch(() => null));
		return parsed.success ? parsed.data : null;
	} catch {
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
): Promise<unknown | null> {
	if (!binding) return null;
	try {
		const resp = await binding.fetch(`https://bv-recon${path}`, {
			...init,
			headers: { ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}), ...(init.headers ?? {}) },
			signal: composeSignal(signal),
		});
		if (!resp.ok) return null;
		const parsed = schema.safeParse(await resp.json());
		return parsed.success ? parsed.data : null;
	} catch {
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
): Promise<InvestigationStart | null> {
	return reconJson(
		binding,
		authToken,
		`/osint/api/investigate/${type}`,
		{ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query, options: options ?? {} }) },
		InvestigationStartSchema,
		signal,
	) as Promise<InvestigationStart | null>;
}

export function callReconInvestigationStatus(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	id: string,
	signal?: AbortSignal,
): Promise<ReconOpaque | null> {
	return reconJson(
		binding,
		authToken,
		`/osint/api/investigation/${encodeURIComponent(id)}`,
		{ method: 'GET' },
		OpaqueObjectSchema,
		signal,
	) as Promise<ReconOpaque | null>;
}

export function callReconInvestigationReport(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	id: string,
	signal?: AbortSignal,
): Promise<ReconOpaque | null> {
	return reconJson(
		binding,
		authToken,
		`/osint/api/investigation/${encodeURIComponent(id)}/findings`,
		{ method: 'GET' },
		OpaqueObjectSchema,
		signal,
	) as Promise<ReconOpaque | null>;
}

export function callReconBucketScanStart(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	body: Record<string, unknown>,
	signal?: AbortSignal,
): Promise<BucketScanStart | null> {
	return reconJson(
		binding,
		authToken,
		`/buckets/api/scan/trigger`,
		{ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
		BucketScanStartSchema,
		signal,
	) as Promise<BucketScanStart | null>;
}

export function callReconBucketScanStatus(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	scanId: string,
	signal?: AbortSignal,
): Promise<ReconOpaque | null> {
	return reconJson(
		binding,
		authToken,
		`/buckets/api/scan/status/${encodeURIComponent(scanId)}`,
		{ method: 'GET' },
		OpaqueObjectSchema,
		signal,
	) as Promise<ReconOpaque | null>;
}

export function callReconBucketFindings(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	scanId: string | undefined,
	signal?: AbortSignal,
): Promise<ReconOpaque | null> {
	const qs = scanId ? `?scanId=${encodeURIComponent(scanId)}` : '';
	return reconJson(binding, authToken, `/buckets/api/findings${qs}`, { method: 'GET' }, OpaqueObjectSchema, signal) as Promise<ReconOpaque | null>;
}

