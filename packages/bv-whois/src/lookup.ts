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
	/**
	 * True when the registrant record is redacted behind a privacy/proxy service.
	 * `null` = NOT MEASURED — no registrant record was read (transport error,
	 * short-circuit, unknown TLD, domain not found). Never a confident `false`
	 * on a path that never saw a record (#931: a failed lookup used to read as
	 * "not private").
	 */
	registrantPrivacy: boolean | null;
	source: 'whois' | 'redacted' | 'notfound' | 'error';
	/**
	 * Concrete cause, set iff `source === 'error'`. Lets the caller tell a
	 * refused/timed-out socket from an unrouted TLD instead of one opaque
	 * `whois_error` (#931).
	 */
	failureReason?: WhoisFailureReason;
}

export type WhoisFailureReason = 'invalid_domain' | 'no_whois_server' | 'timeout' | 'connect_error' | 'unrecognised_response';

/**
 * Registration-detail fields default to absent — the registrar-only short-circuit
 * paths carry no dates and MEASURED NOTHING about the registrant, so privacy is
 * `null`, not `false`.
 */
const EMPTY_REGISTRATION_DETAILS = {
	creationDate: null,
	updatedDate: null,
	expiryDate: null,
	registrantOrg: null,
	registrantPrivacy: null,
} as const;

function errorResult(failureReason: WhoisFailureReason): WhoisLookupResult {
	return { registrar: null, registrarIanaId: null, ...EMPTY_REGISTRATION_DETAILS, source: 'error', failureReason };
}

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
		return errorResult('invalid_domain');
	}

	const labels = domain.toLowerCase().split('.');
	const tld = labels[labels.length - 1];

	if (ALWAYS_REDACTED_TLDS.has(tld)) {
		return { registrar: null, registrarIanaId: null, ...EMPTY_REGISTRATION_DETAILS, source: 'redacted' };
	}

	const server = await resolveWhoisServer(tld, deps);
	if (!server) return errorResult('no_whois_server');

	let response: string;
	try {
		response = await deps.whoisQuery(server, domain);
	} catch (err) {
		// `whoisQuery` (transport.ts) throws `WHOIS timeout after Nms` on its
		// deadline; anything else is a socket-level failure (refused, reset,
		// DNS, egress block).
		const message = err instanceof Error ? err.message : String(err);
		return errorResult(/^WHOIS timeout/i.test(message) ? 'timeout' : 'connect_error');
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
	// No registrant record exists, so there is nothing to measure privacy on.
	if (parsed.notFound) return { registrar: null, registrarIanaId: null, ...details, registrantPrivacy: null, source: 'notfound' };
	// The registry answered with a REGISTRATION RECORD (dates present) that simply
	// carries no registrar attribution. That is registry policy, not a transport
	// failure — the same class as the DENIC short-circuit above, just discovered
	// on the wire. Measured instance (#931): Punktum dk (.dk, whois.punktum.dk:43,
	// referred by whois.iana.org) emits `Registered:` / `Expires:` but omits
	// `Registrar:` for registrant-managed domains — spec:
	// github.com/Punktum-dk/whois-service-specification ("the field is omitted
	// if the domain name is under registrant management"). Reporting it as
	// `error` made bv-mcp tag a deterministic answer `lookup_failed/whois_error`
	// and retry it forever.
	if (parsed.creationDate || parsed.expiryDate || parsed.updatedDate) {
		return { registrar: null, registrarIanaId: null, ...details, source: 'redacted' };
	}
	return errorResult('unrecognised_response');
}
