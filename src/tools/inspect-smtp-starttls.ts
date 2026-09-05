// SPDX-License-Identifier: BUSL-1.1

/** Unregistered, non-scoring beta wrapper for the isolated STARTTLS probe seam. */

import { callSmtpStarttlsProbe, type SmtpProbeBinding } from '../lib/smtp-probe-binding';
import { sanitizeDomain, validateDomain } from '../lib/sanitize';
import { smtpNotAssessed, type SmtpStarttlsResult } from '../schemas/smtp-starttls';

export interface InspectSmtpStarttlsOptions {
	probeBinding?: SmtpProbeBinding;
	probeAuthToken?: string;
	signal?: AbortSignal;
	now?: () => string;
}

/** Validate the domain, then delegate only through an explicitly injected binding. */
export async function inspectSmtpStarttls(domainInput: string, options: InspectSmtpStarttlsOptions = {}): Promise<SmtpStarttlsResult> {
	const now = options.now ?? (() => new Date().toISOString());
	const validation = validateDomain(domainInput);
	if (!validation.valid) return smtpNotAssessed(null, 'invalid_domain', now);
	const domain = sanitizeDomain(domainInput);
	return callSmtpStarttlsProbe(options.probeBinding, options.probeAuthToken, domain, { signal: options.signal, now });
}
