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
import type { ServedCertificate, TlsaVerificationContext } from '@blackveil/dns-checks';
import { buildCheckResult, createFinding } from './scoring';
import { logEvent } from './log';
import type { BindingDegradationKind, BindingDegradationSink } from './binding-degradation';
import { disposeUnreadResponseBody, readJsonResponseCapped } from './response-body';

// Re-export the shared telemetry types so existing importers of these symbols
// from `tls-probe-binding` keep working; the canonical definition lives in
// `./binding-degradation` (unified with the recon client to prevent drift).
export type { BindingDegradationKind, BindingDegradationSink } from './binding-degradation';

/** Minimal Fetcher shape — matches a Cloudflare service binding. */
export interface TlsProbeBinding {
	fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

const TLS_PROBE_COMPONENT = 'tls_probe';

/** Map a thrown fetch error to a degradation kind. AbortSignal.timeout → timeout. */
function errorToKind(err: unknown): BindingDegradationKind {
	const name = err instanceof Error ? err.name : '';
	return name === 'TimeoutError' || name === 'AbortError' ? 'binding_timeout' : 'binding_unavailable';
}

/**
 * Emit a structured warn log AND invoke the optional sink for a present-but-failing
 * probe binding. Fail-soft: a throwing sink can never break the fail-soft contract.
 */
function recordTlsProbeDegradation(
	kind: BindingDegradationKind,
	telemetry: BindingDegradationSink | undefined,
	context: { status?: number; host?: string; errorName?: string },
): void {
	logEvent({
		timestamp: new Date().toISOString(),
		severity: 'warn',
		category: 'binding_degradation',
		result: kind,
		details: {
			component: TLS_PROBE_COMPONENT,
			route: '/probe',
			...(context.status !== undefined ? { status: context.status } : {}),
			...(context.errorName ? { errorName: context.errorName } : {}),
		},
	});
	try {
		telemetry?.({ degradationType: kind, component: TLS_PROBE_COMPONENT, domain: context.host });
	} catch {
		// Telemetry must never break the fail-soft binding contract.
	}
}

const TLS_PROBE_TIMEOUT_MS = 8_000;
const DEFAULT_PROBE_PORT = 443;
const TLS_PROBE_MAX_BODY_BYTES = 256 * 1024;
const MIN_TLS_PROBE_CAPABILITY_BYTES = 32;

/** One served-chain member as bv-tls-probe reports it (digests lowercase hex, DER base64). */
const ServedChainEntrySchema = z
	.object({
		sha256: z.string().optional(),
		sha512: z.string().optional(),
		spkiSha256: z.string().optional(),
		spkiSha512: z.string().optional(),
		der: z.string().optional(),
		spkiDer: z.string().optional(),
	})
	.passthrough();

/**
 * The served-certificate block bv-tls-probe adds to `/probe` for DANE pin verification
 * (#841). Additive to the existing response; every field optional so a probe build that
 * predates it, or omits a field, still validates. The block as a whole is `.catch`-ed:
 * a malformed certificate object degrades to "no certificate" (the DANE check reports an
 * unmeasured pin) instead of failing the whole response and taking the TLS-version
 * enrichment down with it.
 */
const ServedCertificateSchema = z
	.object({
		host: z.string().optional(),
		port: z.number().optional(),
		capturedAt: z.string().optional(),
		leafDer: z.string().optional(),
		leafSpkiDer: z.string().optional(),
		leafSha256: z.string().optional(),
		leafSha512: z.string().optional(),
		leafSpkiSha256: z.string().optional(),
		leafSpkiSha512: z.string().optional(),
		chain: z.array(ServedChainEntrySchema).optional(),
		/** True when the served chain exceeded the probe's entry cap and its tail was dropped. */
		chainTruncated: z.boolean().optional(),
		/** The chain's original length before truncation. */
		chainLength: z.number().optional(),
		subjectName: z.string().optional(),
		subjectAlternativeNames: z.array(z.string()).optional(),
		validFrom: z.number().optional(),
		validTo: z.number().optional(),
	})
	.passthrough();

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
		cipher: z.object({ name: z.string().optional(), bits: z.number().optional() }).passthrough().optional(),
		error: z.string().optional(),
		probedAt: z.string().optional(),
		certificate: ServedCertificateSchema.optional().catch(undefined),
		/** Set when the capture failed ('off-host redirect', 'no security state', …). */
		certificateError: z.string().optional(),
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
	opts?: { port?: number; signal?: AbortSignal; telemetry?: BindingDegradationSink },
): Promise<TlsProbeResult | null> {
	// Absent binding (BSL self-host) is expected, NOT a degradation — stay silent.
	if (!binding) return null;
	// A present external service must never receive an absent/weak credential.
	// Full peer-collision checks happen at the env wiring boundary.
	if (typeof authToken !== 'string' || new TextEncoder().encode(authToken).byteLength < MIN_TLS_PROBE_CAPABILITY_BYTES) return null;
	try {
		const qs = new URLSearchParams({ host, port: String(opts?.port ?? DEFAULT_PROBE_PORT) });
		const resp = await binding.fetch(`https://bv-tls-probe/probe?${qs.toString()}`, {
			method: 'GET',
			headers: { Authorization: `Bearer ${authToken}` },
			signal: composeSignal(opts?.signal),
		});
		// Any non-ok (incl. 404 — unlike recon, NOT benign here) is a present-binding failure.
		if (!resp.ok) {
			await disposeUnreadResponseBody(resp);
			recordTlsProbeDegradation('binding_5xx', opts?.telemetry, { status: resp.status, host });
			return null;
		}
		const parsed = TlsProbeResponseSchema.safeParse(await readJsonResponseCapped(resp, TLS_PROBE_MAX_BODY_BYTES));
		return parsed.success ? parsed.data : null;
	} catch (err) {
		recordTlsProbeDegradation(errorToKind(err), opts?.telemetry, { host, errorName: err instanceof Error ? err.name : undefined });
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
	// Preserve controlPresent — detectDomainContext reads it for profile detection,
	// so dropping it here would flip sslPass to false for legacy-TLS-but-reachable hosts.
	return buildCheckResult('ssl', [...result.findings, finding], result.controlPresent);
}

/**
 * `notAssessedReason` vocabulary for a DANE pin the probe could not verify (#841).
 * `pending` / `failed` are the package defaults; the rest name the specific cause.
 */
export const DANE_CERTIFICATE_PROBE_REASONS = {
	pending: 'certificate_probe_pending',
	failed: 'certificate_probe_failed',
	offHostRedirect: 'off_host_redirect',
	hostMismatch: 'certificate_host_mismatch',
	unreachable: 'host_unreachable',
} as const;

/** A probe result that is still warming its cache (the DEFAULT path on a cold call). */
const PROBE_PENDING_RE = /pending|warming/i;
const OFF_HOST_REDIRECT_RE = /redirect/i;

function normalizeHost(host: string): string {
	return host.trim().toLowerCase().replace(/\.$/, '');
}

function unmeasured(outcome: 'pending' | 'failed', reason: string): TlsaVerificationContext {
	return { servedCertificate: null, certificateProbe: outcome, certificateProbeReason: reason };
}

/**
 * Project a `/probe` response onto the DANE check's verification input (#841).
 *
 * - `certificate` present AND its `host` equals the scanned name → the served certificate.
 *   DANE pins the TLSA owner's EXACT host — apex and `www` can serve different
 *   certificates — so a capture describing any other host (an off-host redirect the
 *   probe followed, a missing host) is a FAILED verification, never a verdict.
 * - `certificateError` → failed (`off_host_redirect` when the probe says so).
 * - `error` matching the probe's "pending — cache warming" verdict → pending: the real
 *   answer arrives on a later call, the check marks itself partial and re-tries.
 * - `reachable: false`, a null result (binding failure), or a response with no
 *   certificate block at all (a probe build predating the contract) → failed.
 *
 * Never throws; never fabricates material — a certificate block missing its leaf
 * digests is treated as absent.
 */
export function servedCertificateFromProbe(probe: TlsProbeResult | null, expectedHost: string): TlsaVerificationContext {
	if (!probe) return unmeasured('failed', DANE_CERTIFICATE_PROBE_REASONS.failed);
	const cert = probe.certificate;
	if (cert) {
		const host = cert.host ? normalizeHost(cert.host) : '';
		if (host.length === 0 || host !== normalizeHost(expectedHost)) {
			return unmeasured('failed', DANE_CERTIFICATE_PROBE_REASONS.hostMismatch);
		}
		if (!cert.leafSha256 || !cert.leafSpkiSha256) return unmeasured('failed', DANE_CERTIFICATE_PROBE_REASONS.failed);
		const served: ServedCertificate = {
			host,
			port: cert.port ?? DEFAULT_PROBE_PORT,
			capturedAt: cert.capturedAt,
			leafDer: cert.leafDer,
			leafSpkiDer: cert.leafSpkiDer,
			leafSha256: cert.leafSha256,
			leafSha512: cert.leafSha512,
			leafSpkiSha256: cert.leafSpkiSha256,
			leafSpkiSha512: cert.leafSpkiSha512,
			chain: (cert.chain ?? []).map((entry) => ({
				sha256: entry.sha256,
				sha512: entry.sha512,
				spkiSha256: entry.spkiSha256,
				spkiSha512: entry.spkiSha512,
				der: entry.der,
				spkiDer: entry.spkiDer,
			})),
			chainTruncated: cert.chainTruncated,
			chainLength: cert.chainLength,
			subjectName: cert.subjectName,
			subjectAlternativeNames: cert.subjectAlternativeNames,
			validFrom: cert.validFrom,
			validTo: cert.validTo,
		};
		return { servedCertificate: served };
	}
	if (probe.certificateError) {
		return unmeasured(
			'failed',
			OFF_HOST_REDIRECT_RE.test(probe.certificateError)
				? DANE_CERTIFICATE_PROBE_REASONS.offHostRedirect
				: DANE_CERTIFICATE_PROBE_REASONS.failed,
		);
	}
	if (probe.error && PROBE_PENDING_RE.test(probe.error)) return unmeasured('pending', DANE_CERTIFICATE_PROBE_REASONS.pending);
	if (probe.reachable === false) return unmeasured('failed', DANE_CERTIFICATE_PROBE_REASONS.unreachable);
	return unmeasured('failed', DANE_CERTIFICATE_PROBE_REASONS.failed);
}
