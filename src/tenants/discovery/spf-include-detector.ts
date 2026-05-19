// SPDX-License-Identifier: BUSL-1.1

/**
 * SPF-include ownership detector.
 *
 * Checks whether a candidate's SPF record (recursively, RFC 7208 §4.6.4
 * 10-lookup cap) includes the seed domain or any subdomain of the seed.
 * Including the seed's SPF policy requires the seed's operator to authorize
 * the candidate's mail egress — near-deterministic ownership evidence.
 *
 * Shared-provider includes (e.g. `_spf.google.com`, `_spf.salesforce.com`)
 * are filtered out — those indicate SaaS usage, not ownership. The seed
 * itself is exempt from the "shared provider" filter (so when seed IS
 * google.com, an include of `_spf.google.com` is real evidence).
 */

import { validateDomain } from '../../lib/sanitize';
import { mapConcurrent } from '../../lib/map-concurrent';
import { safeFetch } from '../../lib/safe-fetch';
import { getEffectiveTld, extractBrandName } from '../../lib/public-suffix';
import { isInfrastructureProvider } from './infrastructure-providers';
import type { DiscoveryDnsContext } from './dns-context';

const DEFAULT_DOH_URL = 'https://cloudflare-dns.com/dns-query';
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_LOOKUPS = 10; // RFC 7208 §4.6.4
const MAX_SEED_WALK_DEPTH = 5;
const TOTAL_BUDGET_MS = 8_000;

/** Public SPF providers — includes of these are not ownership evidence (unless seed IS the provider). */
const SHARED_SPF_PROVIDERS = new Set([
	'_spf.google.com',
	'spf.protection.outlook.com',
	'amazonses.com',
	'_spf.salesforce.com',
	'sendgrid.net',
	'mailgun.org',
	'_spf.mailgun.org',
	'spf.mandrillapp.com',
	'_spf.mtasv.net',
	'_spf.intermedia.net',
	'mailchimp.com',
	'_spf.brevo.com',
]);

export interface SpfIncludeOptions {
	candidateDomains: string[];
	dohFn?: typeof fetch;
	dohUrl?: string;
	timeoutMs?: number;
	dnsContext?: DiscoveryDnsContext;
}

export interface SpfIncludeResult {
	coOwnedDomains: Array<{
		domain: string;
		confidence: number;
		evidence: { include: string };
	}>;
	queryStatus: 'ok' | 'error';
}

type SpfIncludeCandidate = SpfIncludeResult['coOwnedDomains'][number];

interface DohResponse {
	Status: number;
	Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

type QueryTxtFn = (name: string) => Promise<string[]>;

async function queryTxt(name: string, dohFn: typeof fetch, dohUrl: string, timeoutMs: number): Promise<string[]> {
	const url = `${dohUrl}?name=${encodeURIComponent(name)}&type=TXT`;
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const resp = await dohFn(url, {
			headers: { Accept: 'application/dns-json' },
			signal: controller.signal,
		});
		clearTimeout(timeoutId);
		if (!resp.ok) return [];
		const json = (await resp.json()) as DohResponse;
		if (json.Status !== 0 || !json.Answer) return [];
		// TXT data comes as quoted, possibly multi-string ("a" "b") → concatenate.
		return json.Answer.map((a) =>
			a.data
				.replace(/(?:^|\s)"([^"]*)"/g, (_, s: string) => s)
				.trim(),
		);
	} catch {
		clearTimeout(timeoutId);
		return [];
	}
}

async function queryTxtWithContext(name: string, dnsContext: DiscoveryDnsContext): Promise<string[]> {
	try {
		const json = await dnsContext.query(name, 'TXT');
		if (json.Status !== 0 || !json.Answer) return [];
		return json.Answer.map((a) =>
			a.data
				.replace(/(?:^|\s)"([^"]*)"/g, (_, s: string) => s)
				.trim(),
		);
	} catch {
		return [];
	}
}

/** Find SPF record from a TXT list. RFC 7208: only one SPF record per domain. */
function pickSpfRecord(txts: string[]): string | null {
	for (const txt of txts) {
		if (/^v=spf1\b/i.test(txt)) return txt;
	}
	return null;
}

/** Parse `include:host` mechanisms from an SPF record. */
function parseIncludes(spf: string): string[] {
	const out: string[] = [];
	for (const tok of spf.split(/\s+/)) {
		const m = tok.match(/^include:([^\s]+)$/i);
		if (m) out.push(m[1].toLowerCase().replace(/\.$/, ''));
	}
	return out;
}

/** Parse both `include:host` and `redirect=host` policy-chain targets. */
function parseChainTargets(spf: string): string[] {
	const out: string[] = [];
	for (const tok of spf.split(/\s+/)) {
		const inc = tok.match(/^include:([^\s]+)$/i);
		if (inc && inc[1]) {
			out.push(inc[1].toLowerCase().replace(/\.$/, ''));
			continue;
		}
		const red = tok.match(/^redirect=([^\s]+)$/i);
		if (red && red[1]) {
			out.push(red[1].toLowerCase().replace(/\.$/, ''));
		}
	}
	return out;
}

/**
 * Return the registrable apex of a hostname using the curated PSL.
 * `_spf.brand-gamma.com` → `brand-gamma.com`; `sub.example.co.uk` → `example.co.uk`.
 * Returns null when the input is a bare TLD/PSL or otherwise has no
 * registrable label.
 */
function registrableApex(host: string): string | null {
	const brand = extractBrandName(host);
	const tld = getEffectiveTld(host);
	if (!brand || !tld) return null;
	return `${brand}.${tld}`;
}

/** True if `host` is the seed apex or any subdomain of the seed. */
function isSeedRooted(host: string, seed: string): boolean {
	const h = host.toLowerCase().replace(/\.$/, '');
	const s = seed.toLowerCase().replace(/\.$/, '');
	return h === s || h.endsWith('.' + s);
}

/**
 * Walk a candidate's SPF include graph, bounded by MAX_LOOKUPS. Returns the
 * first seed-rooted include found (excluding shared providers), or null.
 */
async function findSeedRootedInclude(
	candidate: string,
	seed: string,
	queryTxtRecords: QueryTxtFn,
): Promise<string | null> {
	const visited = new Set<string>();
	const queue: string[] = [candidate];
	let lookups = 0;

	while (queue.length > 0 && lookups < MAX_LOOKUPS) {
		const target = queue.shift()!;
		if (visited.has(target)) continue;
		visited.add(target);
		lookups++;

		const txts = await queryTxtRecords(target);
		const spf = pickSpfRecord(txts);
		if (!spf) continue;

		const includes = parseIncludes(spf);
		for (const inc of includes) {
			if (isSeedRooted(inc, seed) && !SHARED_SPF_PROVIDERS.has(inc)) {
				// Allow `_spf.seed.com` even though it looks like a "provider" — it's seed-rooted.
				return inc;
			}
			// Don't descend into known shared providers — bounded recursion saves lookups.
			if (!SHARED_SPF_PROVIDERS.has(inc)) {
				queue.push(inc);
			}
		}
	}

	return null;
}

export async function detectSpfInclude(seedDomain: string, options: SpfIncludeOptions): Promise<SpfIncludeResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const dohFn = options.dohFn ?? safeFetch;
	const dohUrl = options.dohUrl ?? DEFAULT_DOH_URL;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const dnsContext = options.dnsContext;
	const queryTxtRecords = dnsContext
		? (name: string) => queryTxtWithContext(name, dnsContext)
		: (name: string) => queryTxt(name, dohFn, dohUrl, timeoutMs);

	if (options.candidateDomains.length === 0) {
		return { coOwnedDomains: [], queryStatus: 'ok' };
	}

	const settled = await mapConcurrent(options.candidateDomains, 6, async (cand): Promise<PromiseSettledResult<SpfIncludeCandidate | null>> => {
		try {
			const candLower = cand.trim().toLowerCase().replace(/\.$/, '');
			if (!validateDomain(candLower).valid) return { status: 'fulfilled', value: null };
			const include = await findSeedRootedInclude(candLower, seedLower, queryTxtRecords);
			if (!include) return { status: 'fulfilled', value: null };
			return {
				status: 'fulfilled',
				value: { domain: candLower, confidence: 0.85, evidence: { include } },
			};
		} catch (reason) {
			return { status: 'rejected', reason };
		}
	});

	const coOwnedDomains = settled
		.filter((r): r is PromiseFulfilledResult<SpfIncludeCandidate> => r.status === 'fulfilled' && r.value !== null)
		.map((r) => r.value);

	return { coOwnedDomains, queryStatus: 'ok' };
}

// ---------------------------------------------------------------------------
// Forward-discovery: extract candidate apexes FROM the seed's own SPF chain.
// ---------------------------------------------------------------------------

export interface ExtractSeedSpfIncludesOptions {
	dohFn?: typeof fetch;
	dohUrl?: string;
	timeoutMs?: number;
	dnsContext?: DiscoveryDnsContext;
	/** Override the recursion depth cap (default 5; RFC 7208 §4.6.4 caps total lookups at 10). */
	maxDepth?: number;
	/** Override the total wall-clock budget for the chain walk (default 8s). */
	budgetMs?: number;
}

export interface SeedSpfIncludeCandidate {
	/** Registrable apex (e.g. `nike.eu`) — never a subdomain. */
	apex: string;
	/** Constant 0.85 — authoritative mail-policy delegation, near-deterministic. */
	confidence: number;
	/** Depth at which the include first appeared (1 = direct on seed). */
	depth: number;
	/** The raw include/redirect token that yielded this apex (for evidence). */
	via: string;
}

export interface SeedSpfWalkResult {
	candidates: SeedSpfIncludeCandidate[];
	queryStatus: 'ok' | 'no_spf' | 'budget_exceeded' | 'error';
	lookups: number;
}

/**
 * Forward-discovery: walk the SEED's own SPF `include:` and `redirect=` chain
 * (RFC 7208 §4.6.4) and emit each unique registrable apex that differs from
 * the seed's apex as a same-organization candidate.
 *
 * Rationale: a chain entry like `include:_spf.brand-gamma.com` or
 * `include:spf.nike.eu` is an authoritative delegation — the publisher of the
 * seed has explicitly trusted that host to authorize mail egress, so the
 * registrable apex of that host is near-certainly operated by the same
 * organization. Shared SaaS infrastructure providers (Microsoft 365, Google,
 * Amazon SES, …) are filtered via `isInfrastructureProvider()`.
 *
 * Bounded by:
 *   - `maxDepth` (default 5) — recursion depth; direct-on-seed = depth 1.
 *   - `MAX_LOOKUPS` (10) — RFC 7208 hard cap on total DNS lookups.
 *   - `budgetMs` (default 8s) — total wall-clock budget; on overrun returns
 *     partial results with `queryStatus: 'budget_exceeded'`.
 *
 * Never throws on DNS errors — caller interrogates `queryStatus`. Programmer
 * errors (invalid `seedDomain`) DO throw, matching the existing module.
 */
export async function extractSeedSpfIncludes(
	seedDomain: string,
	options: ExtractSeedSpfIncludesOptions = {},
): Promise<SeedSpfWalkResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const seedApex = registrableApex(seedLower);
	const dohFn = options.dohFn ?? safeFetch;
	const dohUrl = options.dohUrl ?? DEFAULT_DOH_URL;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const dnsContext = options.dnsContext;
	const queryTxtRecords = dnsContext
		? (name: string) => queryTxtWithContext(name, dnsContext)
		: (name: string) => queryTxt(name, dohFn, dohUrl, timeoutMs);
	const maxDepth = options.maxDepth ?? MAX_SEED_WALK_DEPTH;
	const budgetMs = options.budgetMs ?? TOTAL_BUDGET_MS;

	// emitted by apex (dedup; keep shallowest depth)
	const emitted = new Map<string, SeedSpfIncludeCandidate>();
	// visited query targets (avoid cycles / wasted lookups)
	const visited = new Set<string>();
	const queue: Array<{ host: string; depth: number }> = [{ host: seedLower, depth: 0 }];
	let lookups = 0;
	let exceeded = false;
	let seedHadSpf = false;

	const start = Date.now();

	const walk = async (): Promise<void> => {
		while (queue.length > 0) {
			if (lookups >= MAX_LOOKUPS) break;
			if (Date.now() - start > budgetMs) {
				exceeded = true;
				break;
			}
			const item = queue.shift()!;
			const target = item.host;
			if (visited.has(target)) continue;
			visited.add(target);
			lookups++;

			const txts = await queryTxtRecords(target);
			const spf = pickSpfRecord(txts);
			if (target === seedLower && spf) seedHadSpf = true;
			if (!spf) continue;

			const childDepth = item.depth + 1;
			for (const rawTarget of parseChainTargets(spf)) {
				if (!rawTarget) continue;
				// Skip macro-bearing tokens — cannot meaningfully resolve to an apex.
				if (rawTarget.includes('%')) continue;
				// Skip shared SaaS infra; subdomain match (e.g. spf.protection.outlook.com).
				if (isInfrastructureProvider(rawTarget)) continue;
				// Skip well-known shared SPF provider exactly-named entries that
				// aren't covered by INFRASTRUCTURE_PROVIDERS apex set.
				if (SHARED_SPF_PROVIDERS.has(rawTarget)) continue;

				const apex = registrableApex(rawTarget);
				if (!apex) continue;
				// Drop self — same registrable apex as the seed.
				if (seedApex && apex === seedApex) {
					// Still descend into self-rooted hosts so we surface
					// cross-org policy delegations nested under the seed.
					if (childDepth < maxDepth && !visited.has(rawTarget)) {
						queue.push({ host: rawTarget, depth: childDepth });
					}
					continue;
				}

				// Emit only when within depth budget. Depth 1 = first include
				// on the seed; depth N must be ≤ maxDepth to emit.
				if (childDepth <= maxDepth) {
					const prior = emitted.get(apex);
					if (!prior || prior.depth > childDepth) {
						emitted.set(apex, {
							apex,
							confidence: 0.85,
							depth: childDepth,
							via: rawTarget,
						});
					}
				}

				// Continue walking — descend even into already-emitted apexes
				// so we surface deeper sibling apexes. Stop at maxDepth.
				if (childDepth < maxDepth && !visited.has(rawTarget)) {
					queue.push({ host: rawTarget, depth: childDepth });
				}
			}
		}
	};

	// Race the walk against the total budget so a hung DoH doesn't strand the caller.
	let status: SeedSpfWalkResult['queryStatus'] = 'ok';
	try {
		await Promise.race([
			walk(),
			new Promise<void>((resolve) =>
				setTimeout(() => {
					exceeded = true;
					resolve();
				}, budgetMs),
			),
		]);
	} catch {
		status = 'error';
	}

	if (status === 'ok' && exceeded) status = 'budget_exceeded';
	// Distinguish "seed had no SPF at all" from "seed has SPF but yielded
	// zero same-org apexes" — only the former is a missing-control signal.
	if (status === 'ok' && !seedHadSpf) status = 'no_spf';

	const candidates = Array.from(emitted.values()).sort(
		(a, b) => a.depth - b.depth || a.apex.localeCompare(b.apex),
	);

	return { candidates, queryStatus: status, lookups };
}
