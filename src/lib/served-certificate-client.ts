// SPDX-License-Identifier: BUSL-1.1

/**
 * Client for the served-certificate lane of the infra-probe sidecar.
 *
 * Never throws. An unbound sidecar, a sidecar too old to know this lane, a timeout
 * and a malformed answer each come back as a `not_assessed` block with a reason, so
 * `check_ssl` always carries the field and never has to guess what its absence means.
 */

import { normalizeInfraHostname, type InfraProbeBinding } from './authoritative-dns-infra/probe-client';
import { sanitizeDnsData } from './output-sanitize';
import { disposeUnreadResponseBody, readJsonResponseCapped } from './response-body';
import {
	SERVED_CERTIFICATE_EXPIRY_BANDS,
	SERVED_CERTIFICATE_NOT_ASSESSED_REASONS,
	type ServedCertificateBlock,
	type ServedCertificateNotAssessedReason,
} from './served-certificate-types';

/** Above the sidecar's own 3s deadline, so its named reason arrives before this gives up. */
const SERVED_CERTIFICATE_CLIENT_TIMEOUT_MS = 4_500;
const SERVED_CERTIFICATE_MAX_BODY_BYTES = 8 * 1024;
const MAX_NAME_LENGTH = 1_024;

function not(reason: ServedCertificateNotAssessedReason): ServedCertificateBlock {
	return { status: 'not_assessed', reason, source: 'handshake' };
}

function isNullableText(value: unknown, maxLength: number): value is string | null {
	return value === null || (typeof value === 'string' && value.length <= maxLength);
}

/**
 * Rebuild the block from validated fields only. The body crossed a process boundary as
 * an unchecked cast, so nothing is passed through: an unknown reason, a wrong type or
 * an extra field ends here instead of in a caller's output.
 */
export function parseServedCertificateBlock(body: unknown): ServedCertificateBlock | null {
	if (typeof body !== 'object' || body === null) return null;
	const b = body as Record<string, unknown>;
	if (b.status === 'not_assessed') {
		const reason = SERVED_CERTIFICATE_NOT_ASSESSED_REASONS.find((r) => r === b.reason);
		return reason ? not(reason) : null;
	}
	if (b.status !== 'observed') return null;
	const expiryBand = SERVED_CERTIFICATE_EXPIRY_BANDS.find((band) => band === b.expiryBand);
	if (!expiryBand) return null;
	if (!isNullableText(b.issuer, MAX_NAME_LENGTH) || !isNullableText(b.subject, MAX_NAME_LENGTH)) return null;
	if (!isNullableText(b.notBefore, 40) || !isNullableText(b.notAfter, 40) || !isNullableText(b.serial, 128)) return null;
	if (b.daysRemaining !== null && !(typeof b.daysRemaining === 'number' && Number.isFinite(b.daysRemaining))) return null;
	if (typeof b.fingerprintSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(b.fingerprintSha256)) return null;
	return {
		status: 'observed',
		// A self-signed certificate lets the host choose these two strings outright, so
		// they are treated like any other scanned-host data before reaching a caller.
		issuer: b.issuer === null ? null : sanitizeDnsData(b.issuer),
		subject: b.subject === null ? null : sanitizeDnsData(b.subject),
		notBefore: b.notBefore,
		notAfter: b.notAfter,
		expiryBand,
		daysRemaining: b.daysRemaining as number | null,
		serial: b.serial,
		fingerprintSha256: b.fingerprintSha256,
		source: 'handshake',
	};
}

export async function fetchServedCertificate(
	domain: string,
	infraProbe: InfraProbeBinding | undefined,
	signal?: AbortSignal,
): Promise<ServedCertificateBlock> {
	if (!infraProbe) return not('probe_not_configured');
	try {
		const timeout = AbortSignal.timeout(SERVED_CERTIFICATE_CLIENT_TIMEOUT_MS);
		const response = await infraProbe.fetch('https://infra-probe.internal/probe/served-certificate', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ hostname: normalizeInfraHostname(domain) }),
			signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
		});
		if (!response.ok) {
			// A sidecar deployed before this lane answers 404 here.
			await disposeUnreadResponseBody(response);
			return not('probe_unavailable');
		}
		const body = await readJsonResponseCapped<unknown>(response, SERVED_CERTIFICATE_MAX_BODY_BYTES);
		return parseServedCertificateBlock(body) ?? not('probe_unavailable');
	} catch {
		return not('probe_unavailable');
	}
}
