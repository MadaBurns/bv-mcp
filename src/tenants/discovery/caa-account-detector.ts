// SPDX-License-Identifier: BUSL-1.1

/**
 * CAA account-ID clustering (Phase-5 brand-discovery, corroboration signal).
 *
 * RFC 8657 + DigiCert/Let's Encrypt extensions encode the CA *customer
 * account* in CAA records:
 *
 *   example.com.  IN CAA 0 issue "digicert.com; account=12345"
 *
 * Two domains carrying the same `(ca, account)` tuple in CAA records
 * provably share a CA customer account → near-deterministic ownership signal
 * (confidence 0.95 — leaves a sliver for compromised/leaked CAA configs).
 *
 * Matches on CA alone are intentionally NOT signal-bearing: every Cloudflare
 * customer's zone has the same Let's Encrypt CAA, etc. Only `account=` ties
 * stick.
 *
 * Failure convention: NEVER throw on DNS errors. Surface via `queryStatus`.
 */

import { queryDns } from '../../lib/dns-transport';
import type { DohResponse, RecordTypeName } from '../../lib/dns-types';
import { sanitizeDomain, validateDomain } from '../../lib/sanitize';
import type { DiscoveryDnsContext } from './dns-context';

export type CaaDnsQueryFn = (name: string, type: RecordTypeName) => Promise<DohResponse>;

export interface CaaAccountKey {
	/** Lowercase CA hostname from the `issue`/`issuewild` tag value. */
	ca: string;
	/** Account identifier from the `account=...` extension, lowercased. */
	account: string;
}

export interface CaaCoOwnedCandidate {
	domain: string;
	/** Account tuples shared with the seed. */
	sharedAccounts: CaaAccountKey[];
	confidence: number;
}

export interface CaaAccountOptions {
	dnsQuery?: CaaDnsQueryFn;
	dnsContext?: DiscoveryDnsContext;
	candidateDomains?: string[];
}

export interface CaaAccountResult {
	seedDomain: string;
	seedAccounts: CaaAccountKey[];
	coOwnedDomains: CaaCoOwnedCandidate[];
	queryStatus: 'ok' | 'partial' | 'failed';
}

// ---------------------------------------------------------------------------
// CAA value parser (pure)
// ---------------------------------------------------------------------------

/**
 * Parse the value portion of a CAA `issue` / `issuewild` record into
 * `{ ca, accountKeys }`. The wire format is:
 *
 *   "<ca-domain>"            — bare CA, no extensions
 *   "<ca-domain>; key=val; key=val"
 *
 * Returns `null` if the value is empty or `;` (which means "no CA may issue").
 */
export function parseCaaIssueValue(raw: string): { ca: string; accounts: string[] } | null {
	const trimmed = raw.replace(/^"+|"+$/g, '').trim();
	if (!trimmed || trimmed === ';') return null;
	const segments = trimmed.split(';').map((s) => s.trim()).filter(Boolean);
	if (segments.length === 0) return null;
	const ca = segments[0].toLowerCase();
	if (!ca) return null;
	const accounts: string[] = [];
	for (const seg of segments.slice(1)) {
		const eq = seg.indexOf('=');
		if (eq === -1) continue;
		const key = seg.slice(0, eq).trim().toLowerCase();
		const value = seg.slice(eq + 1).trim();
		if ((key === 'account' || key === 'accounturi') && value) {
			accounts.push(value.toLowerCase());
		}
	}
	return { ca, accounts };
}

/** Extract `(ca, account)` tuples from a DoH CAA response. */
export function extractCaaAccounts(response: DohResponse): CaaAccountKey[] {
	const out: CaaAccountKey[] = [];
	for (const answer of response.Answer ?? []) {
		if (typeof answer.data !== 'string') continue;
		// Cloudflare DoH returns CAA as: `<flags> <tag> "<value>"`
		const match = answer.data.match(/^\s*(\d+)\s+(issue|issuewild)\s+(.+)$/i);
		if (!match) continue;
		const parsed = parseCaaIssueValue(match[3]);
		if (!parsed) continue;
		for (const account of parsed.accounts) {
			out.push({ ca: parsed.ca, account });
		}
	}
	// Dedupe.
	const seen = new Set<string>();
	return out.filter((k) => {
		const key = `${k.ca}::${k.account}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

function emptyResponse(name: string): DohResponse {
	return {
		Status: 2, // SERVFAIL — distinguish from empty NOERROR
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name, type: 257 }],
		Answer: [],
	};
}

async function safeQuery(
	fn: CaaDnsQueryFn,
	name: string,
): Promise<{ ok: boolean; response: DohResponse }> {
	try {
		const response = await fn(name, 'CAA');
		// Status 0 = NOERROR (including NXDOMAIN-equivalent empty). Status 3 = NXDOMAIN.
		// Both are "queried successfully", just no records.
		return { ok: true, response };
	} catch {
		return { ok: false, response: emptyResponse(name) };
	}
}

export async function detectCaaAccountCluster(
	seedDomain: string,
	options: CaaAccountOptions = {},
): Promise<CaaAccountResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(validation.error ?? `Invalid seedDomain: ${seedDomain}`);
	}
	const seed = sanitizeDomain(seedDomain);
	const dnsQuery: CaaDnsQueryFn =
		options.dnsQuery ?? options.dnsContext?.query ?? ((name, type) => queryDns(name, type, false));

	const seedResult = await safeQuery(dnsQuery, seed);
	if (!seedResult.ok) {
		return { seedDomain: seed, seedAccounts: [], coOwnedDomains: [], queryStatus: 'failed' };
	}
	const seedAccounts = extractCaaAccounts(seedResult.response);
	if (seedAccounts.length === 0) {
		// Seed has no account-bearing CAA — no signal possible.
		return { seedDomain: seed, seedAccounts: [], coOwnedDomains: [], queryStatus: 'ok' };
	}
	const seedKeys = new Set(seedAccounts.map((k) => `${k.ca}::${k.account}`));

	const candidates = (options.candidateDomains ?? []).map((d) => d.toLowerCase().replace(/\.$/, ''));
	const matches: CaaCoOwnedCandidate[] = [];
	let anyFailed = false;
	for (const candidate of candidates) {
		if (candidate === seed) continue;
		const candResult = await safeQuery(dnsQuery, candidate);
		if (!candResult.ok) {
			anyFailed = true;
			continue;
		}
		const candAccounts = extractCaaAccounts(candResult.response);
		const shared = candAccounts.filter((k) => seedKeys.has(`${k.ca}::${k.account}`));
		if (shared.length > 0) {
			matches.push({ domain: candidate, sharedAccounts: shared, confidence: 0.95 });
		}
	}

	return {
		seedDomain: seed,
		seedAccounts,
		coOwnedDomains: matches.sort((a, b) => a.domain.localeCompare(b.domain)),
		queryStatus: anyFailed ? 'partial' : 'ok',
	};
}
