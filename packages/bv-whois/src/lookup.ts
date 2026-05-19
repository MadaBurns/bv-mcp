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
	source: 'whois' | 'redacted' | 'notfound' | 'error';
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
const ALWAYS_REDACTED_TLDS = new Set<string>(['de']);

/**
 * Look up the registrar for a single domain via WHOIS.
 * Returns a structured result classifying the outcome — never throws.
 */
export async function lookupRegistrar(domain: string, deps: LookupDeps): Promise<WhoisLookupResult> {
	if (typeof domain !== 'string' || !DOMAIN_RE.test(domain)) {
		return { registrar: null, registrarIanaId: null, source: 'error' };
	}

	const labels = domain.toLowerCase().split('.');
	const tld = labels[labels.length - 1];

	if (ALWAYS_REDACTED_TLDS.has(tld)) {
		return { registrar: null, registrarIanaId: null, source: 'redacted' };
	}

	const server = await resolveWhoisServer(tld, deps);
	if (!server) return { registrar: null, registrarIanaId: null, source: 'error' };

	let response: string;
	try {
		response = await deps.whoisQuery(server, domain);
	} catch {
		return { registrar: null, registrarIanaId: null, source: 'error' };
	}

	const parsed = parseWhoisResponse(response);

	if (parsed.registrar) return { registrar: parsed.registrar, registrarIanaId: parsed.registrarIanaId ?? null, source: 'whois' };
	if (parsed.redacted) return { registrar: null, registrarIanaId: null, source: 'redacted' };
	if (parsed.notFound) return { registrar: null, registrarIanaId: null, source: 'notfound' };
	return { registrar: null, registrarIanaId: null, source: 'error' };
}
