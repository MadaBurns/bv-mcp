// SPDX-License-Identifier: BUSL-1.1
/**
 * The high-level WHOIS lookup composer.
 * Wires: resolveWhoisServer + whoisQuery + parseWhoisResponse.
 */

import { parseWhoisResponse } from '@blackveil/dns-checks/whois';
import { resolveWhoisServer, type KVLike, type WhoisQueryFn } from './resolver';

export interface WhoisLookupResult {
	registrar: string | null;
	registrarIanaId: string | null;
	/** Raw creation/registration date (ISO where the registry emits it). */
	creationDate: string | null;
	/** Raw last-updated/last-modified date. */
	updatedDate: string | null;
	/** Raw expiry/expiration date. */
	expiryDate: string | null;
	/** Registrant organisation/name (may be a privacy-proxy label). */
	registrantOrg: string | null;
	/** True when the registrant record is redacted behind a privacy/proxy service. */
	registrantPrivacy: boolean;
	source: 'whois' | 'redacted' | 'notfound' | 'error';
}

/** Registration-detail fields default to absent — the registrar-only short-circuit paths carry no dates. */
const EMPTY_REGISTRATION_DETAILS = {
	creationDate: null,
	updatedDate: null,
	expiryDate: null,
	registrantOrg: null,
	registrantPrivacy: false,
} as const;

export interface LookupDeps {
	kv: KVLike;
	whoisQuery: WhoisQueryFn;
}

const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i;

/**
 * TLDs whose registry refuses to disclose registrar data via port-43 WHOIS by
 * policy/law. We short-circuit before contacting the server because:
 *   1. The answer is deterministic — `redacted` — regardless of which domain;
 *   2. DENIC and others block Cloudflare Workers' egress IPs, so we get 0-byte
 *      reads and can't distinguish `redacted` from `error` over the wire anyway;
 *   3. Saves a 1-2s TCP round-trip per query.
 */
const ALWAYS_REDACTED_TLDS = new Set<string>([
	'de',
	// These registries either publish registrant/technical records without
	// registrar attribution or do not operate a public WHOIS referral. Treat the
	// registrar field as policy-unavailable, not transiently failed.
	'ch',
	'eg',
	'es',
	'gr',
	'hu',
	'jp',
	'lu',
	'ph',
	'pt',
	'sa',
	'vn',
]);

/**
 * Look up the registrar for a single domain via WHOIS.
 * Returns a structured result classifying the outcome — never throws.
 */
export async function lookupRegistrar(domain: string, deps: LookupDeps): Promise<WhoisLookupResult> {
	if (typeof domain !== 'string' || !DOMAIN_RE.test(domain)) {
		return { registrar: null, registrarIanaId: null, ...EMPTY_REGISTRATION_DETAILS, source: 'error' };
	}

	const labels = domain.toLowerCase().split('.');
	const tld = labels[labels.length - 1];

	if (ALWAYS_REDACTED_TLDS.has(tld)) {
		return { registrar: null, registrarIanaId: null, ...EMPTY_REGISTRATION_DETAILS, source: 'redacted' };
	}

	const server = await resolveWhoisServer(tld, deps);
	if (!server) return { registrar: null, registrarIanaId: null, ...EMPTY_REGISTRATION_DETAILS, source: 'error' };

	let response: string;
	try {
		response = await deps.whoisQuery(server, domain);
	} catch {
		return { registrar: null, registrarIanaId: null, ...EMPTY_REGISTRATION_DETAILS, source: 'error' };
	}

	const parsed = parseWhoisResponse(response);
	// Registration details ride along with every parsed response — a redacted or
	// not-found registrar can still carry public creation/expiry dates.
	const details = {
		creationDate: parsed.creationDate,
		updatedDate: parsed.updatedDate,
		expiryDate: parsed.expiryDate,
		registrantOrg: parsed.registrantOrg,
		registrantPrivacy: parsed.registrantPrivacy,
	};

	if (parsed.registrar) return { registrar: parsed.registrar, registrarIanaId: parsed.registrarIanaId ?? null, ...details, source: 'whois' };
	if (parsed.redacted) return { registrar: null, registrarIanaId: null, ...details, source: 'redacted' };
	if (parsed.notFound) return { registrar: null, registrarIanaId: null, ...details, source: 'notfound' };
	return { registrar: null, registrarIanaId: null, ...details, source: 'error' };
}
