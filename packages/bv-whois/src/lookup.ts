// SPDX-License-Identifier: BUSL-1.1
/**
 * The high-level WHOIS lookup composer.
 * Wires: resolveWhoisServer + whoisQuery + parseWhoisResponse.
 */

import { parseWhoisResponse } from '@blackveil/dns-checks/whois';
import { resolveWhoisServer, type KVLike, type WhoisQueryFn } from './resolver';

export interface WhoisLookupResult {
	registrar: string | null;
	source: 'whois' | 'redacted' | 'notfound' | 'error';
}

export interface LookupDeps {
	kv: KVLike;
	whoisQuery: WhoisQueryFn;
}

const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i;

/**
 * Look up the registrar for a single domain via WHOIS.
 * Returns a structured result classifying the outcome — never throws.
 */
export async function lookupRegistrar(domain: string, deps: LookupDeps): Promise<WhoisLookupResult> {
	if (typeof domain !== 'string' || !DOMAIN_RE.test(domain)) {
		return { registrar: null, source: 'error' };
	}

	const labels = domain.toLowerCase().split('.');
	const tld = labels[labels.length - 1];

	const server = await resolveWhoisServer(tld, deps);
	if (!server) return { registrar: null, source: 'error' };

	let response: string;
	try {
		response = await deps.whoisQuery(server, domain);
	} catch {
		return { registrar: null, source: 'error' };
	}

	const parsed = parseWhoisResponse(response);

	if (parsed.registrar) return { registrar: parsed.registrar, source: 'whois' };
	if (parsed.redacted) return { registrar: null, source: 'redacted' };
	if (parsed.notFound) return { registrar: null, source: 'notfound' };
	return { registrar: null, source: 'error' };
}
