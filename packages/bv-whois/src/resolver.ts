// SPDX-License-Identifier: BUSL-1.1
/**
 * TLD → registry WHOIS server resolution with KV cache.
 *
 * Lookup order:
 *  1. Hardcoded fast path for popular TLDs (zero round trips, survives IANA outage)
 *  2. KV cache (`iana:<tld>`)
 *  3. Live IANA query (`whois.iana.org:43`) and cache the result
 *
 * Negative (null) results are not cached — keeps misses cheap to recover from.
 */

import { parseIanaReferral } from '@blackveil/dns-checks/whois';

/** 7 days. Registries rarely change their WHOIS hostnames. */
export const IANA_TTL_SECONDS = 7 * 24 * 60 * 60;

/**
 * 24 hours. Shorter than positive TTL so legitimately new TLDs (or a registry
 * that briefly returned an empty referral) aren't blackholed forever, but long
 * enough that a batch of audits over non-existent TLDs only hits IANA once.
 */
export const IANA_NEGATIVE_TTL_SECONDS = 24 * 60 * 60;

/**
 * 5 minutes. A THROWN IANA query (socket refused / timed out) says nothing
 * about whether the TLD has a record, so it must not sit in the 24h negative
 * cache reading as "no WHOIS server" (#931 review). Long enough to absorb a
 * batch, short enough that a blip recovers.
 */
export const IANA_UNREACHABLE_TTL_SECONDS = 5 * 60;

/** Present on every genuine whois.iana.org reply (`% This query returned 0 objects.` / `... 1 object`). */
const IANA_ANSWER_RE = /returned \d+ objects?/i;

/** Why a negative entry exists: IANA answered "no record" vs IANA could not be reached / answered garbage. */
export type NoServerReason = 'no_record' | 'iana_unreachable';

interface CacheEnvelope {
	server: string | null;
	reason?: NoServerReason;
}

/** Discriminated resolution result — `reason` only when `server` is null. */
export type ResolvedWhoisServer = { server: string } | { server: null; reason: NoServerReason };

function parseCacheEntry(raw: string): CacheEnvelope {
	try {
		const parsed = JSON.parse(raw) as unknown;
		if (parsed && typeof parsed === 'object' && 'server' in parsed) {
			const { server, reason } = parsed as { server: unknown; reason?: unknown };
			// Pre-#931 negative entries carry no reason; they were written for BOTH
			// "no record" and "IANA threw", so read them as the deterministic kind
			// (the old behaviour) until they expire.
			if (server === null) return { server: null, reason: reason === 'iana_unreachable' ? 'iana_unreachable' : 'no_record' };
			if (typeof server === 'string' && server.length > 0) return { server };
		}
	} catch {
		// Fall through to bare-string back-compat.
	}
	// Pre-Phase-5 entries are bare hostnames.
	return { server: raw };
}

/** Minimal KV shape we depend on — matches the Cloudflare KVNamespace. */
export interface KVLike {
	get(key: string): Promise<string | null>;
	put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
}

/** WHOIS query function — supplied by the caller so tests can inject a fake. */
export type WhoisQueryFn = (server: string, query: string) => Promise<string>;

/** Hardcoded popular TLDs — bypasses both IANA and KV for the fast path. */
const HARDCODED_SERVERS: Record<string, string> = {
	com: 'whois.verisign-grs.com',
	net: 'whois.verisign-grs.com',
	org: 'whois.publicinterestregistry.org',
	info: 'whois.afilias.net',
	io: 'whois.nic.io',
	co: 'whois.registry.co',
	me: 'whois.nic.me',
	us: 'whois.nic.us',
	sh: 'whois.nic.sh',
	ai: 'whois.nic.ai',
	app: 'whois.nic.google',
	de: 'whois.denic.de',
	uk: 'whois.nic.uk',
	ca: 'whois.cira.ca',
	fr: 'whois.nic.fr',
	ae: 'whois.aeda.net.ae',
	at: 'whois.nic.at',
	au: 'whois.auda.org.au',
	ch: 'whois.nic.ch',
	cl: 'whois.nic.cl',
	eg: 'whois.egregistry.eg',
	es: 'whois.nic.es',
	fi: 'whois.fi',
	gr: 'whois.ics.forth.gr',
	hk: 'whois.hkirc.hk',
	hu: 'whois.nic.hu',
	it: 'whois.nic.it',
	kr: 'whois.kr',
	lu: 'whois.dns.lu',
	pt: 'whois.dns.pt',
	qa: 'whois.registry.qa',
	sa: 'whois.nic.net.sa',
	tr: 'whois.trabis.gov.tr',
	vn: 'whois.vnnic.vn',
};

const KV_PREFIX = 'iana:';
const IANA_SERVER = 'whois.iana.org';

/**
 * Resolve a TLD to its authoritative registry WHOIS server.
 *
 * Returns null if the TLD has no IANA record or all lookups failed (caller
 * should treat as "fallback unavailable for this TLD" — fail-soft).
 */
export async function resolveWhoisServer(
	tld: string,
	deps: { kv: KVLike; whoisQuery: WhoisQueryFn },
): Promise<string | null> {
	return (await resolveWhoisServerDetailed(tld, deps)).server;
}

/**
 * As {@link resolveWhoisServer}, but a null server carries WHY: `no_record`
 * (IANA answered — deterministic) vs `iana_unreachable` (the referral query
 * threw — transient, cached only briefly). The lookup composer maps these to
 * distinct failure reasons so a flaky IANA socket never reads as "this TLD has
 * no WHOIS server".
 */
export async function resolveWhoisServerDetailed(
	tld: string,
	deps: { kv: KVLike; whoisQuery: WhoisQueryFn },
): Promise<ResolvedWhoisServer> {
	const normalized = tld.toLowerCase();

	const hardcoded = HARDCODED_SERVERS[normalized];
	if (hardcoded) return { server: hardcoded };

	const cached = await deps.kv.get(KV_PREFIX + normalized);
	if (cached) {
		const envelope = parseCacheEntry(cached);
		return envelope.server === null ? { server: null, reason: envelope.reason ?? 'no_record' } : { server: envelope.server };
	}

	let response: string;
	try {
		response = await deps.whoisQuery(IANA_SERVER, normalized);
	} catch {
		// Cache the transient failure briefly so a batch over flaky TLDs doesn't
		// re-hit IANA on every call — but tag it, and keep the TTL short: a thrown
		// referral is not evidence the TLD has no server.
		await deps.kv.put(KV_PREFIX + normalized, JSON.stringify({ server: null, reason: 'iana_unreachable' }), {
			expirationTtl: IANA_UNREACHABLE_TTL_SECONDS,
		});
		return { server: null, reason: 'iana_unreachable' };
	}

	const server = parseIanaReferral(response);
	if (!server) {
		// Only a genuine IANA ANSWER is deterministic. Every real whois.iana.org
		// reply carries `% This query returned N object(s)` — 0 for a TLD IANA
		// does not know, 1 for a record that simply lists no `whois:` server
		// (measured 2026-09-09). A body without that line (rate-limit banner,
		// truncated read, wrong peer) is not evidence the TLD has no server and
		// must not sit in the 24h negative cache as `no_record` (#935 review).
		const reason: NoServerReason = IANA_ANSWER_RE.test(response) ? 'no_record' : 'iana_unreachable';
		await deps.kv.put(KV_PREFIX + normalized, JSON.stringify({ server: null, reason }), {
			expirationTtl: reason === 'no_record' ? IANA_NEGATIVE_TTL_SECONDS : IANA_UNREACHABLE_TTL_SECONDS,
		});
		return { server: null, reason };
	}

	await deps.kv.put(KV_PREFIX + normalized, JSON.stringify({ server }), { expirationTtl: IANA_TTL_SECONDS });
	return { server };
}
