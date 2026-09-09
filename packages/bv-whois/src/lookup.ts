// SPDX-License-Identifier: BUSL-1.1
/**
 * The high-level WHOIS lookup composer.
 * Wires: resolveWhoisServer + whoisQuery + parseWhoisResponse.
 */

import { parseWhoisResponse } from '@blackveil/dns-checks/whois';
import { resolveWhoisServerDetailed, type KVLike, type WhoisQueryFn } from './resolver';

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
	 * OMITTED (not `false`) when NOT MEASURED — no registrant record was read
	 * (transport error, short-circuit, unknown TLD, domain not found) or the
	 * template is one whose privacy markers the parser does not know. Never a
	 * confident `false` on a path that never saw a record (#931). Omitted rather
	 * than `null` so a pre-#931 bv-mcp (`z.boolean().optional()`) still
	 * validates the payload — deploy order between shim and bv-mcp is free.
	 */
	registrantPrivacy?: boolean;
	source: 'whois' | 'redacted' | 'notfound' | 'error';
	/**
	 * Concrete cause, set iff `source === 'error'`. Lets the caller tell a
	 * refused/timed-out socket from an unrouted TLD instead of one opaque
	 * `whois_error` (#931).
	 */
	failureReason?: WhoisFailureReason;
}

/**
 * Why a lookup produced `source: 'error'`.
 *  - `invalid_domain` — input failed the syntactic domain check; nothing was queried.
 *  - `no_whois_server` — IANA ANSWERED and has no WHOIS referral for the TLD (deterministic).
 *  - `timeout` — the registry socket opened but the per-query deadline elapsed (transient).
 *  - `connect_error` — the registry or IANA socket could not be established / was reset (transient).
 *  - `unrecognised_response` — the registry answered but nothing parseable (no registrar,
 *    dates, redaction notice or not-found marker) came back — banners, bans, unknown templates.
 * bv-mcp surfaces these as `registrarFailureReason: whois_<reason>`.
 */
export type WhoisFailureReason = 'invalid_domain' | 'no_whois_server' | 'timeout' | 'connect_error' | 'unrecognised_response';

/**
 * Registration-detail fields default to absent — the registrar-only short-circuit
 * paths carry no dates and MEASURED NOTHING about the registrant, so
 * `registrantPrivacy` is simply not emitted.
 */
const EMPTY_REGISTRATION_DETAILS = {
	creationDate: null,
	updatedDate: null,
	expiryDate: null,
	registrantOrg: null,
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
 * TLDs whose registry DOES answer port-43 with a registration record but omits
 * registrar attribution BY POLICY for (some) domains. Unlike
 * {@link ALWAYS_REDACTED_TLDS} we still query — the public dates are worth
 * having and registrar-managed domains do carry `Registrar:`. Allowlisted
 * rather than inferred from "dates but no registrar" because that shape is
 * also what a parser miss looks like (EURid/DNS-Belgium `Registrar:\n  Name: X`
 * blocks, banners with a date line) and a parser miss must not be reported as
 * registry policy.
 *
 *  - `dk` — Punktum dk (formerly DK Hostmaster), whois.punktum.dk:43 per the
 *    IANA referral. Spec: github.com/Punktum-dk/whois-service-specification —
 *    "[Registrar] is omitted if the domain name is under registrant
 *    management". Measured live 2026-09-09 (#931).
 */
const REGISTRAR_OMITTED_BY_POLICY_TLDS = new Set<string>(['dk']);

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

	const resolved = await resolveWhoisServerDetailed(tld, deps);
	if (resolved.server === null) {
		// Only an ANSWERED "no record" is deterministic; a thrown IANA query is a
		// transport failure and must not read as "this TLD has no WHOIS server".
		return errorResult(resolved.reason === 'no_record' ? 'no_whois_server' : 'connect_error');
	}

	let response: string;
	try {
		response = await deps.whoisQuery(resolved.server, domain);
	} catch (err) {
		// `whoisQuery` (transport.ts) throws `WhoisTimeoutError` on its deadline
		// (matched by name; the message regex covers a plain Error from an
		// injected transport); anything else is a socket-level failure (refused,
		// reset, DNS, egress block).
		const isTimeout = err instanceof Error && (err.name === 'WhoisTimeoutError' || /^WHOIS timeout/i.test(err.message));
		return errorResult(isTimeout ? 'timeout' : 'connect_error');
	}

	const parsed = parseWhoisResponse(response);
	// Registration details ride along with every parsed response — a redacted or
	// not-found registrar can still carry public creation/expiry dates.
	const dates = {
		creationDate: parsed.creationDate,
		updatedDate: parsed.updatedDate,
		expiryDate: parsed.expiryDate,
		registrantOrg: parsed.registrantOrg,
	};
	// A record was read on a template whose markers the parser knows: the
	// boolean is a measurement either way.
	const details = { ...dates, registrantPrivacy: parsed.registrantPrivacy };

	if (parsed.registrar) return { registrar: parsed.registrar, registrarIanaId: parsed.registrarIanaId ?? null, ...details, source: 'whois' };
	// `redacted` fires on DENIC's disclosure notice AND on "not permitted" /
	// "exceeded the limit" banners (parse.ts) — bodies with NO registrant record,
	// so "no privacy marker" is not a measurement there either. Positive only.
	if (parsed.redacted) {
		return { registrar: null, registrarIanaId: null, ...dates, ...(parsed.registrantPrivacy ? { registrantPrivacy: true } : {}), source: 'redacted' };
	}
	// No registrant record exists, so there is nothing to measure privacy on — key omitted.
	if (parsed.notFound) return { registrar: null, registrarIanaId: null, ...dates, source: 'notfound' };
	// The registry answered with a REGISTRATION RECORD (dates present) that
	// carries no registrar attribution, and the TLD is one where that is
	// documented registry policy (see REGISTRAR_OMITTED_BY_POLICY_TLDS). Same
	// class as the DENIC short-circuit, discovered on the wire. Reporting it as
	// `error` made bv-mcp tag a deterministic answer `lookup_failed/whois_error`
	// and retry it forever (#931).
	//
	// Privacy on this path: the parser's marker set is ICANN/gTLD-shaped and
	// does NOT recognise e.g. Punktum's literal `DATA REDACTED`, so "no marker
	// found" is not a measurement here. A positive marker still is.
	if (REGISTRAR_OMITTED_BY_POLICY_TLDS.has(tld) && (parsed.creationDate || parsed.expiryDate || parsed.updatedDate)) {
		return {
			registrar: null,
			registrarIanaId: null,
			...dates,
			...(parsed.registrantPrivacy ? { registrantPrivacy: true } : {}),
			source: 'redacted',
		};
	}
	return errorResult('unrecognised_response');
}
