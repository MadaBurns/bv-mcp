// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS-derived evidence that a domain is registered / resolving.
 *
 * Only the fields that constitute positive proof of registration are modelled.
 */
export interface RegistrationEvidence {
	/** NS delegation records. */
	ns: string[];
	/** Whether an A record resolves. */
	hasA: boolean;
	/** MX exchange records (any, including a null MX — a published record is still proof). */
	mx: string[];
	/** Whether a `v=spf1` TXT record is published. */
	hasSpf: boolean;
	/** Parsed DMARC policy (`null` when no DMARC record). */
	dmarcPolicy: string | null;
}

/**
 * The single source of truth for "is this domain registered?" across the passive
 * DNS tools (check_shadow_domains, brand discovery).
 *
 * A domain is registered/resolving if ANY authoritative DNS presence exists — an NS
 * delegation, an A record, MX records, a published SPF TXT, or a DMARC policy. None
 * of those records can exist for an unregistered domain, so inferring registration
 * from NS presence ALONE wrongly labels a resolving domain "unregistered" — and, worse,
 * emits an internally contradictory verdict (e.g. `hasSpf: true` alongside "does not
 * appear to be registered"). Routing every registered/unregistered decision through this
 * predicate keeps the tools' verdicts from diverging on the same domain.
 */
export function hasRegistrationEvidence(e: RegistrationEvidence): boolean {
	return e.ns.length > 0 || e.hasA || e.mx.length > 0 || e.hasSpf || e.dmarcPolicy !== null;
}
