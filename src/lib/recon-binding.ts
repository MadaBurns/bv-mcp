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

/** Minimal, defensive shape of a bv-recon /osint/scan response. Extra fields ignored.
 *  `findings` is REQUIRED (not defaulted) so bodies lacking it fail validation. */
const ReconScanResponseSchema = z
	.object({
		findings: z.array(
			z.object({
				severity: z.string(),
				title: z.string().optional(),
				detail: z.string().optional(),
			}),
		),
	})
	.passthrough();
export type ReconScanResult = z.infer<typeof ReconScanResponseSchema>;

/** Minimal shape of a bv-recon /packages/check response. */
const PackageTrustResponseSchema = z
	.object({
		verdict: z.enum(['MALICIOUS', 'SUSPICIOUS', 'LOW_RISK', 'SAFE', 'UNKNOWN']),
		confidence: z.string().optional(),
		signals: z
			.array(z.object({ id: z.string().optional(), severity: z.string(), detail: z.string() }))
			.default([]),
	})
	.passthrough();
export type PackageTrustResult = z.infer<typeof PackageTrustResponseSchema>;

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
		const resp = await binding.fetch(`https://bv-recon/osint/scan?${qs.toString()}`, {
			method: 'GET',
			headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
			signal: composeSignal(signal),
		});
		if (!resp.ok) return null;
		const parsed = ReconScanResponseSchema.safeParse(await resp.json());
		return parsed.success ? parsed.data : null;
	} catch {
		return null;
	}
}

export async function callReconPackageCheck(
	binding: ReconBinding | undefined,
	authToken: string | undefined,
	params: { registry: string; package: string; version?: string },
	signal?: AbortSignal,
): Promise<PackageTrustResult | null> {
	if (!binding) return null;
	try {
		const qs = new URLSearchParams({ registry: params.registry, package: params.package });
		if (params.version) qs.set('version', params.version);
		const resp = await binding.fetch(`https://bv-recon/packages/check?${qs.toString()}`, {
			method: 'GET',
			headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
			signal: composeSignal(signal),
		});
		if (!resp.ok) return null;
		const parsed = PackageTrustResponseSchema.safeParse(await resp.json());
		return parsed.success ? parsed.data : null;
	} catch {
		return null;
	}
}
