// SPDX-License-Identifier: BUSL-1.1
/**
 * Fail-soft client for the operator-only BV_TLS_PROBE service binding.
 *
 * Every function returns null on any failure (binding absent, non-2xx,
 * malformed body, network error, timeout) so callers degrade to their
 * pre-binding behavior. Mirrors the BV_RECON fail-soft pattern in recon-binding.ts.
 */
import { z } from 'zod';

import type { CheckResult, Finding } from './scoring';
import { buildCheckResult, createFinding } from './scoring';

/** Minimal Fetcher shape — matches a Cloudflare service binding. */
export interface TlsProbeBinding {
	fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

const TLS_PROBE_TIMEOUT_MS = 8_000;
const DEFAULT_PROBE_PORT = 443;

/** Defensive shape of a bv-tls-probe /probe response. All fields optional/lenient
 *  so unknown extras never fail validation. */
const TlsProbeResponseSchema = z
	.object({
		host: z.string().optional(),
		port: z.number().optional(),
		reachable: z.boolean().optional(),
		minVersion: z.string().optional(),
		maxVersion: z.string().optional(),
		supportedVersions: z.array(z.string()).optional(),
		cipher: z
			.object({ name: z.string().optional(), bits: z.number().optional() })
			.passthrough()
			.optional(),
		error: z.string().optional(),
		probedAt: z.string().optional(),
	})
	.passthrough();
export type TlsProbeResult = z.infer<typeof TlsProbeResponseSchema>;

function composeSignal(caller?: AbortSignal): AbortSignal {
	const t = AbortSignal.timeout(TLS_PROBE_TIMEOUT_MS);
	return caller ? AbortSignal.any([t, caller]) : t;
}

/**
 * Returns true when a TLS version token is considered legacy/weak.
 * Normalizes by uppercasing and removing spaces before matching so that
 * "TLSv1.0", "TLS 1.1", "tls1.0", etc. are all caught.
 */
function isWeakTlsVersion(v: string): boolean {
	const n = v.toUpperCase().replace(/\s+/g, '').replace(/^TLSV/, 'TLS');
	return n.includes('SSL2') || n.includes('SSL3') || n.includes('TLS1.0') || n.includes('TLS1.1');
}

/**
 * Call the bv-tls-probe /probe endpoint.
 *
 * Returns null on ANY failure — binding absent, non-2xx, malformed body,
 * network error, or timeout — so callers always degrade gracefully.
 */
export async function callTlsProbe(
	binding: TlsProbeBinding | undefined,
	authToken: string | undefined,
	host: string,
	opts?: { port?: number; signal?: AbortSignal },
): Promise<TlsProbeResult | null> {
	if (!binding) return null;
	try {
		const qs = new URLSearchParams({ host, port: String(opts?.port ?? DEFAULT_PROBE_PORT) });
		const resp = await binding.fetch(`https://bv-tls-probe/probe?${qs.toString()}`, {
			method: 'GET',
			headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
			signal: composeSignal(opts?.signal),
		});
		if (!resp.ok) return null;
		const parsed = TlsProbeResponseSchema.safeParse(await resp.json().catch(() => null));
		return parsed.success ? parsed.data : null;
	} catch {
		return null;
	}
}

/**
 * Merge a bv-tls-probe result into an existing CheckResult.
 *
 * Pure — accepts a `CheckResult` and `TlsProbeResult` and returns an
 * updated `CheckResult`. Returning `result` unchanged on the non-weak /
 * inconclusive paths preserves byte-identical behavior with probe-absent callers.
 *
 * Rules:
 *  - Inconclusive (unreachable, error present, or minVersion absent) → return unchanged.
 *  - Weak minVersion (SSL 2/3, TLS 1.0/1.1) → append one HIGH finding and rebuild.
 *  - All other minVersion values (TLS 1.2, 1.3, …) → return unchanged (no penalty).
 */
export function mergeTlsFinding(result: CheckResult, probe: TlsProbeResult): CheckResult {
	// Inconclusive paths — don't alter the result.
	if (probe.reachable === false) return result;
	if (probe.error && probe.error.length > 0) return result;
	if (!probe.minVersion) return result;

	if (!isWeakTlsVersion(probe.minVersion)) return result;

	const finding: Finding = createFinding(
		'ssl',
		'Legacy TLS version offered (≤ TLS 1.1)',
		'high',
		`The HTTPS endpoint for ${probe.host ?? 'this domain'} still negotiates a legacy TLS version (minimum observed: ${probe.minVersion}). TLS 1.0/1.1 are deprecated (RFC 8996) and forbidden by PCI-DSS; offer TLS 1.2 as the minimum. This signal comes from the operator-only BV_TLS_PROBE service; self-hosted deploys without the probe will not see this finding.`,
		{ tlsProbeEnriched: true, minVersion: probe.minVersion, maxVersion: probe.maxVersion, supportedVersions: probe.supportedVersions },
	);
	return buildCheckResult('ssl', [...result.findings, finding]);
}
