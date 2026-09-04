// SPDX-License-Identifier: BUSL-1.1

/** Fail-soft client contract for a future isolated SMTP STARTTLS probe binding. */

import { disposeUnreadResponseBody, readJsonResponseCapped } from './response-body';
import { SmtpStarttlsResultSchema, smtpNotAssessed, type SmtpStarttlsResult } from '../schemas/smtp-starttls';
import { sanitizeDomain, validateDomain } from './sanitize';

export interface SmtpProbeBinding {
	fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

const SMTP_PROBE_ENDPOINT = 'https://bv-smtp-starttls-probe/v1/probe';
const SMTP_PROBE_TIMEOUT_MS = 8_000;
const SMTP_PROBE_MAX_BODY_BYTES = 128 * 1024;
const MIN_CAPABILITY_BYTES = 32;

function composeSignal(caller?: AbortSignal): AbortSignal {
	const timeout = AbortSignal.timeout(SMTP_PROBE_TIMEOUT_MS);
	return caller ? AbortSignal.any([timeout, caller]) : timeout;
}

/**
 * Call an injected, separately privileged probe. Absence, weak credentials,
 * transport errors, non-2xx responses, and malformed bodies all return an
 * explicit not-assessed result. This module declares no Env binding and creates
 * no network service.
 */
export async function callSmtpStarttlsProbe(
	binding: SmtpProbeBinding | undefined,
	authToken: string | undefined,
	domain: string,
	options: { signal?: AbortSignal; now?: () => string } = {},
): Promise<SmtpStarttlsResult> {
	const now = options.now ?? (() => new Date().toISOString());
	const validation = validateDomain(domain);
	if (!validation.valid) return smtpNotAssessed(null, 'invalid_domain', now);
	domain = sanitizeDomain(domain);
	if (!binding || typeof authToken !== 'string' || new TextEncoder().encode(authToken).byteLength < MIN_CAPABILITY_BYTES) {
		return smtpNotAssessed(domain, 'probe_unprovisioned', now);
	}
	try {
		const response = await binding.fetch(SMTP_PROBE_ENDPOINT, {
			method: 'POST',
			headers: { Authorization: `Bearer ${authToken}`, 'Content-Type': 'application/json' },
			body: JSON.stringify({ domain }),
			redirect: 'manual',
			signal: composeSignal(options.signal),
		});
		if (!response.ok) {
			await disposeUnreadResponseBody(response);
			return smtpNotAssessed(domain, 'probe_failed', now);
		}
		const body = await readJsonResponseCapped<unknown>(response, SMTP_PROBE_MAX_BODY_BYTES);
		const parsed = SmtpStarttlsResultSchema.safeParse(body);
		if (!parsed.success || parsed.data.domain !== domain) return smtpNotAssessed(domain, 'probe_response_invalid', now);
		return parsed.data;
	} catch {
		return smtpNotAssessed(domain, 'probe_failed', now);
	}
}
