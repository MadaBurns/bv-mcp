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

interface CacheEnvelope {
	server: string | null;
}

function parseCacheEntry(raw: string): CacheEnvelope {
	try {
		const parsed = JSON.parse(raw) as unknown;
		if (parsed && typeof parsed === 'object' && 'server' in parsed) {
			const server = (parsed as { server: unknown }).server;
			if (server === null) return { server: null };
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
	const normalized = tld.toLowerCase();

	const hardcoded = HARDCODED_SERVERS[normalized];
	if (hardcoded) return hardcoded;

	const cached = await deps.kv.get(KV_PREFIX + normalized);
	if (cached) {
		const envelope = parseCacheEntry(cached);
		return envelope.server;
	}

	let response: string;
	try {
		response = await deps.whoisQuery(IANA_SERVER, normalized);
	} catch {
		// Cache the transient/permanent failure so a batch over non-existent or
		// flaky TLDs doesn't re-hit IANA on every call. TTL is shorter than the
		// positive path so a legit-but-temporarily-flaky TLD recovers within a day.
		await deps.kv.put(KV_PREFIX + normalized, JSON.stringify({ server: null }), {
			expirationTtl: IANA_NEGATIVE_TTL_SECONDS,
		});
		return null;
	}

	const server = parseIanaReferral(response);
	if (!server) {
		await deps.kv.put(KV_PREFIX + normalized, JSON.stringify({ server: null }), {
			expirationTtl: IANA_NEGATIVE_TTL_SECONDS,
		});
		return null;
	}

	await deps.kv.put(KV_PREFIX + normalized, JSON.stringify({ server }), { expirationTtl: IANA_TTL_SECONDS });
	return server;
}
