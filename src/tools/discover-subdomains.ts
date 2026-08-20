// SPDX-License-Identifier: BUSL-1.1
// bv-oversize-ok: single-tool file — CT enumeration + multi-source failover +
// last-known-good resilience + output formatting for discover_subdomains are
// one cohesive responsibility; the pure helpers already sit below the exports.

/**
 * Subdomain Discovery tool.
 * Queries Certificate Transparency logs to discover subdomains that have had
 * certificates issued. Reveals shadow IT, forgotten services, and unauthorized
 * certificate issuance.
 *
 * Source resilience (a CT outage must not read as "no subdomains"):
 *   1. bv-certstream-worker binding (fast, cached) when present, then
 *   2. direct public sources in order — crt.sh → Certspotter — each with a
 *      bounded retry and a per-source `ct_source` health log, then
 *   3. last-known-good KV cache, returned marked `stale` with its age.
 * Only when all of the above are exhausted do we report `sourceUnavailable`.
 *
 * COMPLETENESS HONESTY (this is a SAMPLE, never an inventory):
 * The result carries a `coverage` record whose `basis` is the literal
 * `'ct-sample'` — there is no value meaning "complete inventory", by design.
 * The former `enumerationComplete` boolean is GONE: its narrow per-source truth
 * now lives on as `sourceIndexExhausted`, a name that cannot be misread. See
 * `src/lib/ct-coverage.ts` for the measured evidence (bnz.co.nz, 2026-07-27:
 * 165 names + `enumerationComplete: true` against 420 in crt.sh's unfiltered
 * history, four of the missing ones resolving to live production IPs).
 */

import type { OutputFormat } from '../handlers/tool-args';
import { cacheGet, cacheSet } from '../lib/cache';
import type { CtCoverage, CtSourceAttempt, CtSourceOutcome } from '../lib/ct-coverage';
import { buildCtCoverage, formatCoverageLine } from '../lib/ct-coverage';
import { logEvent } from '../lib/log';
import { sanitizeOutputText } from '../lib/output-sanitize';
import { disposeUnreadResponseBody, readBoundedOrNull } from '../lib/response-body';

/**
 * Synchronous handler budget for `discover_subdomains` (ms).
 *
 * The MCP handler enforces a hard 28s wall-clock guillotine on each tool call
 * (`TOOL_CALL_TIMEOUT_MS`). Cold-cache worst case for this tool can chain:
 *   certstream /enumerate (~10s) → certstream /sans (~10s) → crt.sh fallback (~10s)
 * = ~30s, which trips the guillotine and throws away whatever the earlier
 * stages already gathered. The handler passes this budget as `deadlineMs` so
 * the orchestrator can short-circuit between stages and return the best
 * partial result before the outer race kills it.
 *
 * Sized at 24_000 to leave ~4s of headroom under the 28s guillotine for
 * formatting / log emission / handler overhead.
 *
 * Mirror of the fix shipped for `discover_brand_domains` (PR #236).
 */
export const DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS = 24_000;

/** Per-attempt timeout for a direct public CT source request (ms). */
const CT_SOURCE_TIMEOUT_MS = 10_000;

/**
 * Per-ATTEMPT timeout for the Certspotter fallback (ms) — this bounds the whole
 * paginated run, not one page: `queryDirectSources` composes ONE abort signal per
 * source attempt and threads it through every page fetch.
 *
 * Sized against {@link MAX_CT_PAGES}: 8 pages at the measured ~1.5s/page is ~12s,
 * so 8s (the pre-pagination value, set when this was a single request) would have
 * aborted mid-run around page 5 and silently capped recall — the exact under-
 * delivery this pagination work exists to remove. 14s fits the full 8 pages with
 * headroom.
 *
 * This does NOT risk the ~24s handler budget: {@link CERTSPOTTER_PAGE_BUDGET_MS}
 * is re-checked against the caller's real deadline before every page after the
 * first, so a slow crt.sh attempt ahead of this one still clamps pagination — the
 * caller's budget stays authoritative and the stop is non-fatal (pages already
 * read are kept, `enumerationComplete: false`).
 */
const CERTSPOTTER_TIMEOUT_MS = 14_000;

/**
 * Retry PASSES over the whole source list on a transient outcome (timeout / 5xx
 * / network). A pass retries sources only after every source has been tried once.
 * One retry is enough to ride out a single cold-query blip on crt.sh (Postgres-
 * backed, frequently slow) without blowing the synchronous budget — every
 * attempt is still gated by the caller's `deadlineMs`.
 */
const CT_SOURCE_MAX_RETRIES = 1;

/** Backoff before a same-source retry (ms). */
const CT_SOURCE_RETRY_BACKOFF_MS = 500;

/** Maximum bytes accepted from a direct public CT source response. */
const CT_SOURCE_MAX_BODY_BYTES = 5 * 1024 * 1024;

/**
 * Last-known-good cache key prefix + TTL for the resilience fallback.
 *
 * A successful enumeration is written here; when EVERY live CT source fails we
 * re-serve it (marked `stale`) rather than returning nothing. TTL is a week so
 * the net survives a multi-hour (or multi-day) upstream outage — a week-old
 * subdomain list flagged stale is far more useful to a security caller than an
 * empty "source unavailable". Distinct from the certstream worker's own short
 * fast-path cache: this layer exists precisely for when that worker (or its
 * sources) is unreachable.
 */
const SUBDOMAIN_LKG_KEY_PREFIX = 'cache:subdomains-lkg:';
const SUBDOMAIN_LKG_TTL_SECONDS = 7 * 24 * 60 * 60;

/**
 * Maximum subdomains carried in the STRUCTURED result (CT logs can contain
 * thousands).
 *
 * Raised 100 → 500 for issue #573. The list is sorted `lastSeen` DESCENDING
 * before the cap is applied, so a 100-name cap does not truncate randomly — it
 * truncates the long-lived production hosts that renew infrequently while
 * keeping recently-issued throwaways. On a real bank's estate that dropped
 * `internetbanking`, `payonline`, `mybnz` and kept `test-fc1` / `m.www.sandbox`.
 * 500 covers the overwhelming majority of real estates; whatever it still cuts
 * is now reported explicitly via {@link SubdomainDiscoveryResult.truncated}.
 */
const MAX_SUBDOMAINS = 500;

/**
 * Maximum subdomains RENDERED into the human/LLM-readable text.
 *
 * Deliberately far below {@link MAX_SUBDOMAINS}: `formatFull` emits ~4 lines per
 * host, so 500 hosts is ~100KB of prose that would swamp an LLM context window
 * for no analytical gain. The full list stays available in `structuredContent`;
 * the text says honestly how many it is not showing.
 */
const MAX_RENDERED_SUBDOMAINS = 100;

/**
 * Cap on per-NAME issue rows emitted for a single issue type.
 *
 * The derived COUNTS (`wildcardCerts` / `expiredCerts`) are always whole-set —
 * only the enumerated rows are bounded, with a roll-up row naming the
 * remainder. Without this a 500-name estate could emit 500 issue rows.
 */
const MAX_PER_NAME_ISSUES = 25;

/**
 * Maximum Certspotter pages followed per attempt.
 *
 * Certspotter paginates at 100 issuances and ignores `&limit=` without an API
 * key, so following `Link: <…>; rel="next"` via `&after=<last id>` is the only
 * lever on recall. Measured ~1.5s/page unauthenticated; 8 pages is ~800
 * issuances, more than any realistic estate.
 *
 * TWO INDEPENDENT BOUNDS apply, and the page counter is NOT the binding one in
 * practice — {@link CERTSPOTTER_TIMEOUT_MS} is a single abort signal composed
 * ONCE per source attempt (see `queryDirectSources`), so it caps the WHOLE
 * paginated run, not each page. It is sized to fit `MAX_CT_PAGES` at the
 * measured per-page cost with headroom; if either constant moves, re-check that
 * `MAX_CT_PAGES * ~1.5s` still fits inside it, or pagination will silently stop
 * early. The per-page {@link CERTSPOTTER_PAGE_BUDGET_MS} check additionally
 * yields to the caller's synchronous deadline. Both stop paths are non-fatal:
 * pages already read are kept and `enumerationComplete: false` is reported.
 */
const MAX_CT_PAGES = 8;

/**
 * Budget an additional Certspotter page must fit inside before it is started.
 * Measured page cost is ~1.5s; 2s carries headroom without letting the page
 * loop erode the ~24s handler budget. The caller's `deadlineMs` stays
 * authoritative — see {@link hasBudgetFor}.
 */
const CERTSPOTTER_PAGE_BUDGET_MS = 2_000;

/** Common subdomain prefixes that are expected infrastructure. */
const COMMON_SUBDOMAINS = new Set([
	'www',
	'api',
	'mail',
	'smtp',
	'imap',
	'pop',
	'pop3',
	'ftp',
	'ns',
	'ns1',
	'ns2',
	'ns3',
	'ns4',
	'dns',
	'mx',
	'mx1',
	'mx2',
	'webmail',
	'vpn',
	'remote',
	'cdn',
	'static',
	'assets',
	'img',
	'images',
	'media',
	'docs',
	'help',
	'support',
	'admin',
	'portal',
	'login',
	'sso',
	'auth',
	'app',
	'dashboard',
	'status',
	'blog',
	'shop',
	'store',
	'dev',
	'staging',
	'test',
	'beta',
]);

/** Threshold for flagging many issuers. */
const MANY_ISSUERS_THRESHOLD = 3;

/** A single crt.sh JSON response entry. */
interface CrtShEntry {
	name_value: string;
	issuer_name: string;
	not_before: string;
	not_after: string;
}

/** A discovered subdomain with certificate metadata. */
export interface DiscoveredSubdomain {
	subdomain: string;
	firstSeen: string;
	lastSeen: string;
	issuer: string;
	certCount: number;
	isWildcard: boolean;
	isExpired: boolean;
}

/** An issue detected during subdomain discovery. */
export interface SubdomainIssue {
	type:
		| 'expired_subdomain'
		| 'wildcard_exposure'
		| 'many_issuers'
		| 'recent_issuance'
		| 'shadow_subdomain'
		| 'unconfirmed_zero'
		/**
		 * Always emitted on a non-empty result. Structured consumers that read
		 * ONLY `issues[]` — the same class the `unconfirmed_zero` issue was added
		 * for — would otherwise see a clean list of hosts with nothing telling
		 * them it is a floor, not an inventory.
		 */
		| 'ct_sample_not_inventory';
	severity: 'high' | 'medium' | 'low' | 'info';
	detail: string;
}

/** Full subdomain discovery result. */
export interface SubdomainDiscoveryResult {
	domain: string;
	totalSubdomains: number;
	totalCertificates: number;
	subdomains: DiscoveredSubdomain[];
	wildcardCerts: number;
	expiredCerts: number;
	uniqueIssuers: string[];
	issues: SubdomainIssue[];
	/**
	 * True when the Certificate Transparency source could not be queried (e.g.
	 * crt.sh returned a non-OK status or the request failed). Distinguishes a
	 * lookup failure from a successful query that genuinely found no subdomains.
	 */
	sourceUnavailable?: boolean;
	/**
	 * True when the synchronous budget tripped mid-pipeline and one or more
	 * downstream stages were skipped. Earlier stages that succeeded are kept.
	 */
	partial?: boolean;
	/**
	 * True when this result was served from the last-known-good cache because
	 * every live CT source was unreachable. The data is a prior successful
	 * enumeration, NOT a fresh answer — pair with {@link cacheAgeMinutes} to
	 * judge freshness. `sourceUnavailable` stays false here (we DO have data).
	 */
	stale?: boolean;
	/** Age of a `stale` result in whole minutes since it was cached. */
	cacheAgeMinutes?: number;
	/**
	 * True when this result is NOT the whole story — either the returned
	 * {@link subdomains} array is a strict subset of what was enumerated
	 * (`returned < totalSubdomains`, the {@link MAX_SUBDOMAINS} cap), or the
	 * source's own index was not read to the end ({@link sourceIndexExhausted}
	 * false). A security caller that sweeps only `subdomains` MUST branch on
	 * this: before #573 the cap was silent and the tool read as authoritative.
	 *
	 * NOTE the asymmetry, and it is deliberate: `truncated: false` does NOT mean
	 * "you have the estate". It means nothing was dropped BETWEEN the source and
	 * you. What the source itself could never see is {@link coverage}'s job.
	 */
	truncated?: boolean;
	/** How many entries the {@link subdomains} array actually carries. */
	returned?: number;
	/** Which CT source(s) contributed names, e.g. `['crtsh']`, `['certspotter']`. */
	sources?: string[];
	/**
	 * True when we read the contributing source's index to the end: every page
	 * followed, no upstream truncation flag, no entry-cap applied. False means
	 * `totalSubdomains` is a FLOOR even relative to that ONE source.
	 *
	 * REPLACES the former `enumerationComplete`. Same narrow truth, a name that
	 * cannot be misread: exhausting one source's index is not enumerating an
	 * estate. Measured 2026-07-27, bnz.co.nz returned `enumerationComplete: true`
	 * on 165 names while crt.sh's unfiltered history held 420, four of the
	 * missing ones resolving to live production IPs. See {@link coverage} and
	 * `src/lib/ct-coverage.ts` for the full rationale.
	 */
	sourceIndexExhausted?: boolean;
	/**
	 * What was actually looked at, and what that could possibly have seen. Always
	 * populated by every production path in this module; optional only so that
	 * hand-built fixtures in unrelated suites still typecheck.
	 *
	 * Its `basis` is the literal `'ct-sample'` — a one-member union, so there is
	 * no value a consumer can read as "complete inventory".
	 */
	coverage?: CtCoverage;
}

/** Provenance/completeness metadata threaded from a source into the result builders. */
interface EnumerationMeta {
	sources?: string[];
	sourceIndexExhausted?: boolean;
	/** Per-source attempt log; folded into {@link SubdomainDiscoveryResult.coverage}. */
	attempts?: CtSourceAttempt[];
}

/**
 * Optional caller-supplied deadline / cancellation controls.
 *
 * `deadlineMs` is an absolute `Date.now()` epoch — stages compare against it
 * synchronously between fetches and short-circuit if exceeded.
 *
 * `signal` is composed (via `AbortSignal.any` when available) with each
 * stage's inner timeout so that an outer cancellation aborts in-flight fetches.
 */
export interface DiscoverSubdomainsOptions {
	signal?: AbortSignal;
	deadlineMs?: number;
	/**
	 * When true, ask the certstream worker to bypass its cache (`force_refresh=true`) so a
	 * stale cached result — e.g. an empty snapshot captured during a prior CT-source outage —
	 * is not re-served. The direct-source path is uncached upstream, so this only affects the
	 * fast path. It does NOT suppress the last-known-good stale fallback on a total outage:
	 * a stale list beats an empty result.
	 */
	forceRefresh?: boolean;
	/**
	 * Optional KV namespace backing the last-known-good resilience cache. A
	 * clean successful enumeration is written here (best-effort); on a total
	 * live-source outage it is read back and returned marked `stale`. Absent →
	 * no resilience cache (behaviour reverts to the pre-cache path). Never read
	 * on the happy path — the live sources stay authoritative.
	 */
	cacheKv?: KVNamespace;
	/**
	 * Defers the best-effort LKG cache write off the response path when provided
	 * (`ctx.waitUntil`). Absent → the write is awaited inline (still best-effort).
	 */
	waitUntil?: (promise: Promise<unknown>) => void;
}

/** Extract CN= value from an issuer_name string (e.g. "C=US, O=Let's Encrypt, CN=R3" -> "R3"). */
function extractIssuerCN(issuerName: string): string {
	const match = issuerName.match(/CN=([^,]+)/i);
	return match ? match[1].trim() : issuerName.trim();
}

/** Internal tracking state for a subdomain across multiple certificates. */
interface SubdomainTracker {
	subdomain: string;
	firstSeen: string;
	lastSeen: string;
	latestNotAfter: string;
	latestIssuer: string;
	certCount: number;
	isWildcard: boolean;
	allExpired: boolean;
}

/** Response shape from bv-certstream-worker /enumerate endpoint. */
interface CertstreamEnumerateResponse {
	domain: string;
	subdomains: string[];
	certificateCount: number;
	timedOut: boolean;
	cached: boolean;
	cacheAgeMinutes?: number;
	error?: string;
}

/** Response shape from bv-certstream-worker /sans endpoint. */
interface CertstreamSansResponse {
	domain: string;
	names: string[];
	certificateCount: number;
	timedOut: boolean;
	truncated: boolean;
	cached: boolean;
	cacheAgeMinutes?: number;
	error?: string;
}

/**
 * Discover subdomains for a domain by querying Certificate Transparency logs.
 * Uses bv-certstream-worker service binding (fast, cached) when available,
 * falls back to direct crt.sh query otherwise.
 *
 * @param domain - Validated, sanitized domain
 * @param certstream - Optional bv-certstream-worker service binding
 * @returns Subdomain discovery result with metadata and issues
 */
export async function discoverSubdomains(
	domain: string,
	certstream?: { fetch: typeof fetch },
	certstreamAuthToken?: string,
	options?: DiscoverSubdomainsOptions,
): Promise<SubdomainDiscoveryResult> {
	// Fast path: certstream service binding (bv-certstream-worker; itself
	// multi-source + short-cached). On a clean result, prime the LKG cache.
	if (certstream) {
		const result = await queryCertstream(domain, certstream, certstreamAuthToken, options);
		if (result) {
			await cacheSuccess(domain, result, options);
			return result;
		}
		// Fall through to the direct public sources if the binding failed.
	}

	// Deadline gate before the (slowest) direct-source stage. A budget trip after
	// the fast path already failed is still "no live source answered" from the
	// caller's side, so consult last-known-good before giving up — a KV read costs
	// milliseconds, unlike the 10s fetch we no longer have budget for.
	if (deadlineExceeded(options)) {
		const staleOnDeadline = await readLastKnownGood(domain, options);
		return staleOnDeadline ? { ...staleOnDeadline, partial: true } : emptyResult(domain, true, true);
	}

	// Direct public CT sources, tried in order with per-source health logging
	// and a bounded retry: crt.sh (rich metadata) → Certspotter (names + dates).
	const direct = await queryDirectSources(domain, options);
	if (direct.available) {
		const meta: EnumerationMeta = {
			sources: direct.sources,
			sourceIndexExhausted: direct.sourceIndexExhausted,
			attempts: direct.attempts,
		};
		const result =
			direct.entries.length > 0 ? buildResultFromEntries(domain, direct.entries, meta) : emptyResult(domain, false, false, meta);
		await cacheSuccess(domain, result, options);
		return result;
	}

	// Total live-source outage. Serve last-known-good (stale) if we have it — a
	// stale list with an age beats an empty "source unavailable". force_refresh
	// intentionally does NOT suppress this; it only bypasses the live-fetch cache.
	const stale = await readLastKnownGood(domain, options);
	if (stale) return stale;

	return emptyResult(domain, true, false, { attempts: direct.attempts });
}

/**
 * Aggregate raw CT log entries (crt.sh / Certspotter, normalized to
 * {@link CrtShEntry}) into a full {@link SubdomainDiscoveryResult}: dedupe by
 * subdomain, track first/last-seen + issuer per name, and derive the wildcard /
 * expired / many-issuers / shadow-subdomain issues. Pure — no I/O.
 */
export function buildResultFromEntries(domain: string, rawEntries: CrtShEntry[], meta?: EnumerationMeta): SubdomainDiscoveryResult {
	const now = new Date();

	// Cap entries to prevent memory exhaustion on domains with huge CT histories.
	// Hitting this cap makes the enumeration incomplete regardless of what the
	// source reported — the discarded certs may carry names nothing else covers.
	const entryCapHit = rawEntries.length > 5000;
	const entries = entryCapHit ? rawEntries.slice(0, 5000) : rawEntries;

	// Parse and aggregate subdomain data
	const trackers = new Map<string, SubdomainTracker>();
	const domainSuffix = `.${domain.toLowerCase()}`;
	let totalCertificates = 0;

	for (const entry of entries) {
		if (!entry.name_value) continue;

		// Split name_value on newlines — one cert can cover multiple names
		const names = entry.name_value
			.split('\n')
			.map((n) => n.trim().toLowerCase())
			.filter(Boolean);
		const issuer = extractIssuerCN(entry.issuer_name ?? '');
		const notBefore = entry.not_before ?? '';
		const notAfter = entry.not_after ?? '';
		const isExpired = notAfter ? new Date(notAfter) < now : false;

		totalCertificates++;

		for (const name of names) {
			// Filter: must be a subdomain of the target domain, not the bare domain itself
			if (name === domain.toLowerCase()) continue;
			if (!name.endsWith(domainSuffix)) continue;

			const isWildcard = name.startsWith('*.');

			const existing = trackers.get(name);
			if (existing) {
				existing.certCount++;
				if (notBefore && notBefore < existing.firstSeen) {
					existing.firstSeen = notBefore;
				}
				if (notBefore && notBefore > existing.lastSeen) {
					existing.lastSeen = notBefore;
					existing.latestNotAfter = notAfter;
					existing.latestIssuer = issuer;
				}
				if (!isExpired) {
					existing.allExpired = false;
				}
			} else {
				trackers.set(name, {
					subdomain: name,
					firstSeen: notBefore,
					lastSeen: notBefore,
					latestNotAfter: notAfter,
					latestIssuer: issuer,
					certCount: 1,
					isWildcard,
					allExpired: isExpired,
				});
			}
		}
	}

	// Build subdomain list from trackers
	const allSubdomains: DiscoveredSubdomain[] = [];
	for (const tracker of trackers.values()) {
		allSubdomains.push({
			subdomain: tracker.subdomain,
			firstSeen: tracker.firstSeen,
			lastSeen: tracker.lastSeen,
			issuer: tracker.latestIssuer,
			certCount: tracker.certCount,
			isWildcard: tracker.isWildcard,
			isExpired: tracker.allExpired,
		});
	}

	// Sort by lastSeen descending (most recent first)
	allSubdomains.sort((a, b) => (b.lastSeen > a.lastSeen ? 1 : b.lastSeen < a.lastSeen ? -1 : 0));

	// Limit to MAX_SUBDOMAINS. NOTE: every derived statistic below is computed
	// over `allSubdomains`, NOT this slice — the counts describe the ESTATE, and
	// a count taken after the display cut is a silently wrong security answer
	// (issue #573 defect C: 3 wildcards on the wire were reported as 2).
	const subdomains = allSubdomains.slice(0, MAX_SUBDOMAINS);

	// Collect unique issuers
	const issuerSet = new Set<string>();
	for (const sd of allSubdomains) {
		if (sd.issuer) issuerSet.add(sd.issuer);
	}
	const uniqueIssuers = Array.from(issuerSet);

	// Count wildcards and expired — whole set, never the returned slice.
	const wildcardCerts = allSubdomains.filter((s) => s.isWildcard).length;
	const expiredCerts = allSubdomains.filter((s) => s.isExpired).length;

	// Detect issues
	const issues: SubdomainIssue[] = [];

	// Expired subdomains — only certs expired. Rows are bounded (a 500-name
	// estate must not emit 500 rows) but the roll-up keeps the total honest.
	let expiredRows = 0;
	for (const sd of allSubdomains) {
		if (!sd.isExpired) continue;
		if (expiredRows >= MAX_PER_NAME_ISSUES) break;
		expiredRows++;
		issues.push({
			type: 'expired_subdomain',
			severity: 'medium',
			detail: `${sd.subdomain} has only expired certificates — may be abandoned`,
		});
	}
	if (expiredCerts > expiredRows) {
		issues.push({
			type: 'expired_subdomain',
			severity: 'medium',
			detail: `…and ${expiredCerts - expiredRows} further subdomains have only expired certificates (rows capped at ${MAX_PER_NAME_ISSUES} for readability; see the full list in the structured result)`,
		});
	}

	// Wildcard exposure
	if (wildcardCerts > 0) {
		issues.push({
			type: 'wildcard_exposure',
			severity: 'info',
			detail: `${wildcardCerts} wildcard certificate${wildcardCerts > 1 ? 's' : ''} found — covers all subdomains under the wildcard pattern`,
		});
	}

	// Many issuers
	if (uniqueIssuers.length > MANY_ISSUERS_THRESHOLD) {
		issues.push({
			type: 'many_issuers',
			severity: 'low',
			detail: `${uniqueIssuers.length} unique certificate authorities detected (${uniqueIssuers.join(', ')}). Multiple CAs may indicate decentralized certificate management or shadow IT.`,
		});
	}

	// Shadow subdomains — not matching common patterns, with recent certs.
	// Swept over the whole set (a shadow host that fell past the return cap is
	// exactly the one worth naming), with the same bounded-rows discipline.
	const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
	let shadowRows = 0;
	let shadowTotal = 0;
	for (const sd of allSubdomains) {
		if (sd.isWildcard || sd.isExpired) continue;
		const label = sd.subdomain.replace(domainSuffix, '').replace(/\.$/, '');
		// Only consider single-label subdomains for shadow detection
		if (label.includes('.')) continue;
		if (!COMMON_SUBDOMAINS.has(label) && sd.lastSeen >= thirtyDaysAgo) {
			shadowTotal++;
			if (shadowRows >= MAX_PER_NAME_ISSUES) continue;
			shadowRows++;
			issues.push({
				type: 'shadow_subdomain',
				severity: 'info',
				detail: `${sd.subdomain} has recent certificate activity but is not a common service name — verify it is authorized`,
			});
		}
	}
	if (shadowTotal > shadowRows) {
		issues.push({
			type: 'shadow_subdomain',
			severity: 'info',
			detail: `…and ${shadowTotal - shadowRows} further subdomains with recent certificate activity are not common service names (rows capped at ${MAX_PER_NAME_ISSUES} for readability; see the full list in the structured result)`,
		});
	}

	const sourceIndexExhausted = (meta?.sourceIndexExhausted ?? true) && !entryCapHit;
	const flags = enumerationFlags(allSubdomains.length, subdomains.length, meta?.sources, sourceIndexExhausted, meta?.attempts);
	// Prepended, not appended: a caller that truncates the issue list for display
	// must not lose the one line saying the list itself is a floor.
	if (flags.coverage) issues.unshift(sampleCaveatIssue(flags.coverage, allSubdomains.length));

	return {
		domain,
		totalSubdomains: allSubdomains.length,
		totalCertificates,
		subdomains,
		wildcardCerts,
		expiredCerts,
		uniqueIssuers,
		issues,
		...flags,
	};
}

/**
 * Build the {@link SubdomainDiscoveryResult} completeness contract from a
 * (total, returned) pair plus the per-source attempt log.
 *
 * `truncated` stays the UNION of the two ways data can be lost BETWEEN the
 * source and the caller — the return cap, or the source's index not being read
 * to the end. `coverage` answers the different and larger question the old
 * `enumerationComplete` flag pretended to: what was consulted, and what could
 * that possibly have seen. Both are always emitted; neither can be `true` in a
 * way that means "this is the estate".
 */
function enumerationFlags(
	total: number,
	returned: number,
	sources: string[] | undefined,
	sourceIndexExhausted: boolean,
	attempts: CtSourceAttempt[] | undefined,
): Pick<SubdomainDiscoveryResult, 'truncated' | 'returned' | 'sources' | 'sourceIndexExhausted' | 'coverage'> {
	return {
		returned,
		truncated: returned < total || !sourceIndexExhausted,
		sourceIndexExhausted,
		coverage: buildCtCoverage(attempts ?? attemptsFromSources(sources, sourceIndexExhausted)),
		...(sources && sources.length > 0 ? { sources } : {}),
	};
}

/**
 * Fallback attempt log for paths that know WHICH source answered but kept no
 * per-source failure record (the certstream fast path, and cached results
 * rebuilt from an older payload). Everything not named is reported as
 * `notConsulted` rather than silently assumed healthy.
 */
function attemptsFromSources(sources: string[] | undefined, sourceIndexExhausted: boolean): CtSourceAttempt[] {
	if (!sources || sources.length === 0) return [];
	return sources.map((source) => ({ source, outcome: 'ok' as CtSourceOutcome, contributed: true, indexExhausted: sourceIndexExhausted }));
}

/**
 * The always-present sample caveat on `issues[]`.
 *
 * `unconfirmed_zero` already covers the empty case, so this one rides on
 * non-empty results — the shape that looked healthy and therefore did the
 * damage. Severity `info`: it is a standing property of CT-derived evidence,
 * not a finding about the domain.
 */
function sampleCaveatIssue(coverage: CtCoverage, total: number): SubdomainIssue {
	// Kept SHORT deliberately, and BOUNDED: `formatCompact`/`formatFull` push issue
	// details through `sanitizeOutputText(…, 200|300)`, so a detail that carried the
	// full `coverage.caveat` prose was truncated mid-sentence — losing the clause
	// that matters. The long form still rides on the banner and `coverage.caveat`.
	//
	// The lead sentence is the non-negotiable part and is built first; the source
	// summary is appended only while it still fits under the tightest cap, so a
	// long source list can never push the meaning off the end.
	const lead = `${total} subdomains is a LOWER BOUND from a CT sample, not an inventory — hosts with no logged certificate never appear.`;
	const answered = coverage.contributing.length > 0 ? coverage.contributing.join(', ') : 'no source';
	const missing = [...coverage.unavailable, ...coverage.notConsulted];
	const suffix = ` Answered: ${answered}${missing.length > 0 ? `; no data from ${missing.join(', ')}` : ''}.`;
	return {
		type: 'ct_sample_not_inventory',
		severity: 'info',
		detail: lead.length + suffix.length <= COMPACT_ISSUE_DETAIL_CAP ? `${lead}${suffix}` : lead,
	};
}

/**
 * The tightest cap any renderer applies to `SubdomainIssue.detail`
 * (`formatCompact` → `sanitizeOutputText(detail, 200)`). Kept next to the caveat
 * builder so the two cannot drift apart silently.
 */
const COMPACT_ISSUE_DETAIL_CAP = 200;

// `CtSourceOutcome` (the per-source health outcome emitted to the `ct_source`
// log) now lives in `../lib/ct-coverage` — the coverage record reports the same
// values, so one definition serves both.

/** Normalized result of one direct-source attempt. */
interface SourceResult {
	outcome: CtSourceOutcome;
	entries: CrtShEntry[];
	/**
	 * False when the source's index was NOT read exhaustively (pagination cut
	 * short by {@link MAX_CT_PAGES}, the budget, or a mid-pagination failure).
	 * Defaults to true for single-shot sources.
	 */
	enumerationComplete?: boolean;
}

/**
 * A single Certspotter issuance (with `expand=dns_names&expand=issuer`).
 * `id` is the pagination cursor — `&after=<id>` fetches the next page.
 */
interface CertspotterIssuance {
	id?: string | number;
	dns_names?: string[];
	not_before?: string;
	not_after?: string;
	issuer?: { name?: string };
}

/** Persisted last-known-good cache envelope. */
interface SubdomainLkgEntry {
	cachedAt: number;
	result: SubdomainDiscoveryResult;
}

/** Classify a thrown fetch error as an inner-timeout abort vs a generic error. */
function classifyFetchError(err: unknown): 'timeout' | 'error' {
	const name = (err as { name?: string } | null)?.name;
	return name === 'AbortError' || name === 'TimeoutError' ? 'timeout' : 'error';
}

/**
 * Emit a per-source CT health line so upstream outages are observable/alertable
 * rather than silently degrading the tool. Fail-open — logging never throws.
 */
function logCtSource(domain: string, source: string, outcome: CtSourceOutcome): void {
	try {
		logEvent({
			timestamp: new Date().toISOString(),
			tool: 'discover_subdomains',
			domain,
			category: 'ct_source',
			severity: outcome === 'ok' || outcome === 'empty' ? 'info' : 'warn',
			result: outcome,
			details: { source },
		});
	} catch {
		/* logging must never break discovery */
	}
}

/** Fetch + parse crt.sh into normalized entries. Bounded body, no throw. */
async function fetchCrtShEntries(domain: string, signal: AbortSignal): Promise<SourceResult> {
	try {
		const response = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json&exclude=expired`, {
			signal,
			redirect: 'manual',
		});
		if (!response.ok) {
			await disposeUnreadResponseBody(response);
			return { outcome: 'http_error', entries: [] };
		}
		const declaredLength = Number(response.headers.get('content-length'));
		if (Number.isFinite(declaredLength) && declaredLength > CT_SOURCE_MAX_BODY_BYTES) {
			await disposeUnreadResponseBody(response);
			return { outcome: 'http_error', entries: [] };
		}
		const rawBody = await readBoundedOrNull(response.body, CT_SOURCE_MAX_BODY_BYTES);
		if (rawBody === null) return { outcome: 'http_error', entries: [] };
		const parsed = JSON.parse(rawBody) as unknown;
		if (!Array.isArray(parsed)) return { outcome: 'error', entries: [] };
		const entries = parsed as CrtShEntry[];
		// crt.sh answers the whole query in one response — no pagination to miss.
		return { outcome: entries.length === 0 ? 'empty' : 'ok', entries, enumerationComplete: true };
	} catch (err) {
		return { outcome: classifyFetchError(err), entries: [] };
	}
}

/** True when a Certspotter response advertises another page (`Link: …; rel="next"`). */
function hasNextCertspotterPage(response: Response): boolean {
	const link = response.headers.get('link');
	return typeof link === 'string' && /rel\s*=\s*"?next"?/i.test(link);
}

/**
 * Fetch + parse Certspotter issuances into normalized {@link CrtShEntry}s so the
 * shared aggregation applies unchanged. Unauthenticated (rate-limited but
 * functional for occasional failover); `not_before`/`not_after` are best-effort.
 *
 * PAGINATION (issue #573): Certspotter serves 100 issuances per page and
 * **silently ignores `&limit=` without an API key**, so a single request is
 * page 1 of N — for bnz.co.nz that was 140 names reported out of 165 the index
 * actually holds. We follow `Link: <…>; rel="next"` by re-requesting with
 * `&after=<last issuance id>` until a short page, a missing next link,
 * {@link MAX_CT_PAGES}, or the caller's budget stops us.
 *
 * Failure posture is asymmetric on purpose: a failure on page 1 is a SOURCE
 * failure (failover to the next source), while a failure mid-pagination keeps
 * the pages already read and marks the enumeration incomplete — partial real
 * data beats discarding it and reporting an outage.
 */
async function fetchCertspotterEntries(domain: string, signal: AbortSignal, options?: DiscoverSubdomainsOptions): Promise<SourceResult> {
	const base = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`;
	const entries: CrtShEntry[] = [];
	let after: string | undefined;
	let pagesRead = 0;
	let enumerationComplete = true;

	/** A mid-pagination stop: keep what we have, flag the gap. */
	const stopIncomplete = (): boolean => {
		enumerationComplete = false;
		return true;
	};

	try {
		while (pagesRead < MAX_CT_PAGES) {
			// The caller's synchronous budget stays authoritative over the page
			// loop — an extra page is never worth tripping the 28s guillotine.
			if (pagesRead > 0 && (deadlineExceeded(options) || !hasBudgetFor(options, CERTSPOTTER_PAGE_BUDGET_MS))) {
				stopIncomplete();
				break;
			}

			const url = after ? `${base}&after=${encodeURIComponent(after)}` : base;
			const response = await fetch(url, { signal, redirect: 'manual' });

			if (!response.ok) {
				await disposeUnreadResponseBody(response);
				if (pagesRead === 0) return { outcome: 'http_error', entries: [] };
				stopIncomplete();
				break;
			}
			const declaredLength = Number(response.headers.get('content-length'));
			if (Number.isFinite(declaredLength) && declaredLength > CT_SOURCE_MAX_BODY_BYTES) {
				await disposeUnreadResponseBody(response);
				if (pagesRead === 0) return { outcome: 'http_error', entries: [] };
				stopIncomplete();
				break;
			}
			const rawBody = await readBoundedOrNull(response.body, CT_SOURCE_MAX_BODY_BYTES);
			if (rawBody === null) {
				if (pagesRead === 0) return { outcome: 'http_error', entries: [] };
				stopIncomplete();
				break;
			}
			const parsed = JSON.parse(rawBody) as unknown;
			if (!Array.isArray(parsed)) {
				if (pagesRead === 0) return { outcome: 'error', entries: [] };
				stopIncomplete();
				break;
			}

			const page = parsed as CertspotterIssuance[];
			pagesRead++;
			let lastId: string | undefined;
			for (const item of page) {
				if (item && (typeof item.id === 'string' || typeof item.id === 'number')) lastId = String(item.id);
				if (!item || !Array.isArray(item.dns_names) || item.dns_names.length === 0) continue;
				entries.push({
					name_value: item.dns_names.join('\n'),
					issuer_name: item.issuer?.name ?? '',
					not_before: item.not_before ?? '',
					not_after: item.not_after ?? '',
				});
			}

			// Index exhausted, or the server says this is the last page.
			if (page.length === 0 || !hasNextCertspotterPage(response)) break;
			// A next page exists but we cannot address it (no usable cursor) or we
			// have spent the page budget — either way the enumeration is partial.
			if (!lastId || pagesRead >= MAX_CT_PAGES) {
				stopIncomplete();
				break;
			}
			after = lastId;
		}

		return { outcome: entries.length === 0 ? 'empty' : 'ok', entries, enumerationComplete };
	} catch (err) {
		// An abort/network error AFTER a successful page is still usable data.
		if (entries.length > 0) return { outcome: 'ok', entries, enumerationComplete: false };
		return { outcome: classifyFetchError(err), entries: [] };
	}
}

/** True when the remaining deadline budget can fit another `ms` attempt. */
function hasBudgetFor(options: DiscoverSubdomainsOptions | undefined, ms: number): boolean {
	if (typeof options?.deadlineMs !== 'number') return true;
	return options.deadlineMs - Date.now() >= ms;
}

/** Signal-aware delay used for same-source retry backoff. Resolves on abort. */
function delayWithSignal(ms: number, signal?: AbortSignal): Promise<void> {
	return new Promise((resolve) => {
		if (signal?.aborted) {
			resolve();
			return;
		}
		const id = setTimeout(resolve, ms);
		signal?.addEventListener(
			'abort',
			() => {
				clearTimeout(id);
				resolve();
			},
			{ once: true },
		);
	});
}

/**
 * Query the direct public CT sources with per-source health logging and deadline
 * gating.
 *
 *   - `ok`    → real data; return it immediately (a later empty answer never
 *               overrides real data already in hand).
 *   - `empty` → NOT authoritative on its own. crt.sh (or Certspotter) can be
 *               behind on indexing a domain even when it is up, so a single
 *               source's "nothing here" is corroborated by trying the next
 *               source before it is trusted — an uncorroborated single-source
 *               empty is exactly the success-shaped-zero this tool must not
 *               produce. Only once a full pass over every source completes
 *               without any `ok` do we report `available:true` with an empty
 *               set (the caller routes this through `emptyResult()`, which
 *               always carries the `unconfirmed_zero` issue regardless of how
 *               many sources agreed — CT-log absence is never positive proof).
 *
 * Ordering is **failover-first, retry-second**: pass 1 tries every source once
 * (crt.sh → Certspotter) before any source is retried. Re-asking a source that
 * just timed out is the worst use of a tight budget — it costs another full
 * timeout and delays the source that would actually rescue the caller. A pass
 * that ends with at least one authoritative `empty` and no `ok` stops there
 * (that is real information, not a gap to paper over with a retry pass); a
 * pass that ends with ONLY failures (http_error / timeout / error — no source
 * answered at all) spends a retry pass chasing what is presumed transient.
 *
 * `available:false` means no source ever answered authoritatively — the
 * caller then decides between last-known-good and an explicit outage error.
 *
 * NOTE: sequential first-authoritative-wins on `ok`, not a fan-out+merge.
 * Under the ~24s synchronous budget, querying every source to merge results
 * on every call would blow the deadline; failing over to the first
 * `ok` responder is what the budget allows. `empty` is the one outcome that
 * deliberately keeps trying rather than winning immediately.
 */
async function queryDirectSources(
	domain: string,
	options?: DiscoverSubdomainsOptions,
): Promise<{ available: boolean; entries: CrtShEntry[]; sources?: string[]; sourceIndexExhausted?: boolean; attempts: CtSourceAttempt[] }> {
	// Per-source timeouts differ by backend: crt.sh is Postgres-backed and often
	// slow on a cold query, while Certspotter is a fast JSON API — giving the
	// fallback a tighter bound keeps both inside one budget.
	const sources: Array<{
		name: string;
		timeoutMs: number;
		fetch: (d: string, signal: AbortSignal, options?: DiscoverSubdomainsOptions) => Promise<SourceResult>;
	}> = [
		{ name: 'crtsh', timeoutMs: CT_SOURCE_TIMEOUT_MS, fetch: fetchCrtShEntries },
		{ name: 'certspotter', timeoutMs: CERTSPOTTER_TIMEOUT_MS, fetch: fetchCertspotterEntries },
	];

	// True once ANY source has returned an authoritative "no subdomains"
	// answer. Tracked across sources (and, if reached, retry passes) so a
	// first-source empty is never reported until at least one other source
	// has had a chance to corroborate it or supersede it with real data.
	let sawEmpty = false;

	// Per-source attempt log for the coverage record. Last outcome per source
	// wins across retry passes; a source never reached stays out entirely so
	// `buildCtCoverage` reports it as `notConsulted` rather than as healthy.
	const attemptLog = new Map<string, CtSourceAttempt>();
	const recordAttempt = (source: string, outcome: CtSourceOutcome, contributed: boolean, indexExhausted?: boolean): void => {
		attemptLog.set(source, { source, outcome, contributed, ...(indexExhausted === undefined ? {} : { indexExhausted }) });
	};
	const attempts = (): CtSourceAttempt[] =>
		sources.filter((s) => attemptLog.has(s.name)).map((s) => attemptLog.get(s.name) as CtSourceAttempt);

	for (let pass = 0; pass <= CT_SOURCE_MAX_RETRIES; pass++) {
		// Backoff applies BETWEEN passes, not between sources — failover should be
		// immediate, only a repeat attempt at the same source needs to back off.
		if (pass > 0) await delayWithSignal(CT_SOURCE_RETRY_BACKOFF_MS, options?.signal);

		for (const source of sources) {
			// Never start an attempt we can't finish inside the budget. An empty
			// answer already gathered from an earlier source in this loop is real
			// information — surface it rather than downgrading to a bare outage
			// just because we ran out of budget to corroborate further.
			if (deadlineExceeded(options) || !hasBudgetFor(options, source.timeoutMs)) {
				return sawEmpty ? { available: true, entries: [], attempts: attempts() } : { available: false, entries: [], attempts: attempts() };
			}
			const composed = composeAbortSignal(source.timeoutMs, options?.signal);
			let res: SourceResult;
			try {
				res = await source.fetch(domain, composed.signal, options);
			} finally {
				composed.cleanup();
			}
			logCtSource(domain, source.name, res.outcome);
			// Every attempt is recorded — including the failures. The pre-fix payload
			// reported only the winner (`sources: ["certspotter"]`), so a caller could
			// not tell that crt.sh had been asked and had failed, i.e. that recall on
			// that call was degraded. That omission is now impossible.
			recordAttempt(source.name, res.outcome, res.outcome === 'ok', res.enumerationComplete);
			// #573 metadata (which source answered, was its index read to the end) rides
			// on the ok path only. #575's `sawEmpty` fall-through is preserved: an
			// `empty` outcome must NOT short-circuit, because a source that answers
			// "nothing" is not authoritative until every source has been tried.
			if (res.outcome === 'ok') {
				return {
					available: true,
					entries: res.entries,
					sources: [source.name],
					sourceIndexExhausted: res.enumerationComplete ?? true,
					attempts: attempts(),
				};
			}
			if (res.outcome === 'empty') sawEmpty = true;
			// empty / http_error / timeout / error all fall through to try the
			// next source instead of short-circuiting.
		}

		// A full pass completed without any source returning real data. An
		// authoritative empty from at least one source is a real (if
		// unconfirmed) answer — report it rather than burning a retry pass
		// chasing a source that merely failed to respond.
		if (sawEmpty) return { available: true, entries: [], attempts: attempts() };
	}
	return { available: false, entries: [], attempts: attempts() };
}

/** LKG cache key for a domain. */
function subdomainLkgKey(domain: string): string {
	return `${SUBDOMAIN_LKG_KEY_PREFIX}${domain.toLowerCase()}`;
}

/** Strip transient/served-state flags so the cached copy is a clean answer. */
function stripTransientFlags(result: SubdomainDiscoveryResult): SubdomainDiscoveryResult {
	const { stale: _stale, cacheAgeMinutes: _age, sourceUnavailable: _unavail, partial: _partial, ...clean } = result;
	return clean;
}

/**
 * Persist a clean enumeration as last-known-good (best-effort). Never stores a
 * non-answer (source-unavailable / partial / already-stale) so the fallback net
 * can't be poisoned by an outage. Deferred via `waitUntil` when available.
 */
async function cacheSuccess(domain: string, result: SubdomainDiscoveryResult, options?: DiscoverSubdomainsOptions): Promise<void> {
	if (!options?.cacheKv) return;
	if (result.sourceUnavailable || result.partial || result.stale) return;
	// An empty enumeration is a worthless fallback: re-serving "0 subdomains
	// (stale)" during an outage tells the caller nothing the explicit outage
	// error doesn't, and invites reading it as a confirmed empty.
	if (result.totalSubdomains === 0) return;
	const entry: SubdomainLkgEntry = { cachedAt: Date.now(), result: stripTransientFlags(result) };
	const write = cacheSet(subdomainLkgKey(domain), entry, options.cacheKv, SUBDOMAIN_LKG_TTL_SECONDS).catch(() => {
		/* best-effort; KV is not a lock */
	});
	if (options.waitUntil) options.waitUntil(write);
	else await write;
}

/**
 * Read the last-known-good enumeration for a total-outage fallback. Returns the
 * cached result marked `stale:true` with its age in minutes, or null when there
 * is no cache / KV is absent / the read fails.
 */
async function readLastKnownGood(domain: string, options?: DiscoverSubdomainsOptions): Promise<SubdomainDiscoveryResult | null> {
	if (!options?.cacheKv) return null;
	let entry: SubdomainLkgEntry | undefined;
	try {
		entry = await cacheGet<SubdomainLkgEntry>(subdomainLkgKey(domain), options.cacheKv);
	} catch {
		return null;
	}
	if (!entry || !entry.result) return null;
	const cachedAt = typeof entry.cachedAt === 'number' ? entry.cachedAt : Date.now();
	const ageMs = Math.max(0, Date.now() - cachedAt);
	return {
		...stripTransientFlags(entry.result),
		stale: true,
		cacheAgeMinutes: Math.floor(ageMs / 60_000),
	};
}

/**
 * Query bv-certstream-worker via service binding. Returns null on failure.
 *
 * Pipeline: `/enumerate` (fast path) → `/sans` (fallback). Between stages we
 * check the optional deadline; if tripped, we either return the enumerate
 * result tagged `partial:true` (when it had data) or signal the orchestrator
 * to skip remaining stages by returning a partial empty result.
 *
 * `timedOut` handling (mirrors `attemptCertstreamSans` in
 * `src/tenants/discovery/san-correlator.ts`): the worker itself hit ITS
 * upstream timeout mid-query. A `timedOut:true` response with data is a real,
 * if incomplete, measurement — returned marked `partial:true` rather than
 * discarded. A `timedOut:true` response with NO data carries no signal at
 * all (we don't know whether there truly are zero subdomains, or whether the
 * timeout hit before anything could be found) — that is treated like a
 * failure so the caller falls through to the next stage instead of accepting
 * an incomplete measurement as a confident zero.
 */
async function queryCertstream(
	domain: string,
	certstream: { fetch: typeof fetch },
	certstreamAuthToken?: string,
	options?: DiscoverSubdomainsOptions,
): Promise<SubdomainDiscoveryResult | null> {
	if (deadlineExceeded(options)) {
		return emptyResult(domain, true, true);
	}

	const enumerate = await queryCertstreamEndpoint<CertstreamEnumerateResponse>(
		'enumerate',
		domain,
		certstream,
		certstreamAuthToken,
		options,
	);
	const enumerateOk = Boolean(enumerate) && !enumerate?.error && Array.isArray(enumerate?.subdomains);
	if (enumerateOk && enumerate) {
		if (!enumerate.timedOut) {
			return buildCertstreamResult(domain, enumerate.subdomains, enumerate.certificateCount);
		}
		// #575's partial semantics, now also carrying #573's upstream metadata so the
		// timed-out enumeration is reported incomplete rather than merely `partial`.
		if (enumerate.subdomains.length > 0) {
			return {
				...buildCertstreamResult(domain, enumerate.subdomains, enumerate.certificateCount, { timedOut: true }),
				partial: true,
			};
		}
		// timedOut:true with an empty list — fall through to /sans below rather
		// than accepting an incomplete measurement as a confident zero.
	}

	// Deadline gate: if we already burned the budget on /enumerate, skip /sans
	// and let the orchestrator decide whether to fall through to crt.sh.
	if (deadlineExceeded(options)) {
		return emptyResult(domain, true, true);
	}

	const sans = await queryCertstreamEndpoint<CertstreamSansResponse>('sans', domain, certstream, certstreamAuthToken, options);
	// `/sans` reports its own upstream truncation — read it (declared and silently
	// discarded before #573) so an incomplete SAN sweep is never served as a
	// complete enumeration. Layered over #575's timed-out control flow.
	const sansOk = Boolean(sans) && !sans?.error && Array.isArray(sans?.names);
	if (!sansOk || !sans) return null;
	if (!sans.timedOut) {
		return buildCertstreamResult(domain, sans.names, sans.certificateCount, { truncated: sans.truncated });
	}
	if (sans.names.length > 0) {
		return {
			...buildCertstreamResult(domain, sans.names, sans.certificateCount, { truncated: sans.truncated, timedOut: true }),
			partial: true,
		};
	}
	// timedOut:true with an empty list — return null so the orchestrator falls
	// through to the direct public sources (crt.sh → Certspotter) instead of
	// treating this as a confident zero.
	return null;
}

async function queryCertstreamEndpoint<T>(
	path: 'enumerate' | 'sans',
	domain: string,
	certstream: { fetch: typeof fetch },
	certstreamAuthToken?: string,
	options?: DiscoverSubdomainsOptions,
): Promise<T | null> {
	const composed = composeAbortSignal(CT_SOURCE_TIMEOUT_MS, options?.signal);

	try {
		const forceRefreshParam = options?.forceRefresh ? '&force_refresh=true' : '';
		const response = await certstream.fetch(`https://certstream/${path}?domain=${encodeURIComponent(domain)}${forceRefreshParam}`, {
			...(certstreamAuthToken ? { headers: { Authorization: `Bearer ${certstreamAuthToken}` } } : {}),
			signal: composed.signal,
		});
		if (!response.ok) {
			await disposeUnreadResponseBody(response);
			return null;
		}
		return (await response.json()) as T;
	} catch {
		return null;
	} finally {
		composed.cleanup();
	}
}

/** True when an absolute deadline (epoch ms) has been crossed. */
function deadlineExceeded(options?: DiscoverSubdomainsOptions): boolean {
	return typeof options?.deadlineMs === 'number' && Date.now() >= options.deadlineMs;
}

interface ComposedSignal {
	signal: AbortSignal;
	cleanup: () => void;
}

/**
 * Compose an inner-timeout signal with the caller's optional cancellation signal.
 * Uses `AbortSignal.any` when present (workerd / modern Node); otherwise falls
 * back to plain inner-timeout (the orchestrator's `deadlineMs` pre-check is the
 * primary cancellation path in older runtimes).
 */
function composeAbortSignal(timeoutMs: number, outer?: AbortSignal): ComposedSignal {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

	if (outer) {
		const anyFn = (AbortSignal as unknown as { any?: (signals: AbortSignal[]) => AbortSignal }).any;
		if (typeof anyFn === 'function') {
			const merged = anyFn([controller.signal, outer]);
			return { signal: merged, cleanup: () => clearTimeout(timeoutId) };
		}
		// Fallback: if outer fires first, forward to our controller.
		const onAbort = () => controller.abort();
		if (outer.aborted) {
			controller.abort();
		} else {
			outer.addEventListener('abort', onAbort, { once: true });
		}
		return {
			signal: controller.signal,
			cleanup: () => {
				clearTimeout(timeoutId);
				outer.removeEventListener('abort', onAbort);
			},
		};
	}

	return { signal: controller.signal, cleanup: () => clearTimeout(timeoutId) };
}

/**
 * Aggregate a certstream name list into a result.
 *
 * Issue #573 defect D: this path used to `.slice(0, MAX_SUBDOMAINS)` BEFORE
 * counting, so `totalSubdomains` could never exceed the cap and the overflow
 * line could never render — strictly worse than the crt.sh path. Totals are now
 * taken over the full deduped set and the slice is applied afterwards.
 */
function buildCertstreamResult(
	domain: string,
	names: string[],
	certificateCount: number | undefined,
	upstream?: { truncated?: boolean; timedOut?: boolean },
): SubdomainDiscoveryResult {
	const domainLower = domain.toLowerCase();
	const domainSuffix = `.${domainLower}`;
	const subdomains: DiscoveredSubdomain[] = [];

	for (const name of names) {
		const lower = name.trim().toLowerCase().replace(/\.$/, '');
		if (!lower) continue;

		const isWildcard = lower.startsWith('*.');
		const comparable = isWildcard ? lower.slice(2) : lower;
		if (!isWildcard && comparable === domainLower) continue;
		if (comparable !== domainLower && !comparable.endsWith(domainSuffix)) continue;

		subdomains.push({
			subdomain: lower,
			firstSeen: '',
			lastSeen: '',
			issuer: '',
			certCount: 1,
			isWildcard,
			isExpired: false,
		});
	}

	// Deduplicate
	const seen = new Map<string, DiscoveredSubdomain>();
	for (const sd of subdomains) {
		const existing = seen.get(sd.subdomain);
		if (existing) {
			existing.certCount++;
		} else {
			seen.set(sd.subdomain, sd);
		}
	}

	// Count over the WHOLE deduped set; slice only what we return.
	const dedupedAll = Array.from(seen.values());
	const deduped = dedupedAll.slice(0, MAX_SUBDOMAINS);
	const wildcardCerts = dedupedAll.filter((s) => s.isWildcard).length;

	const issues: SubdomainIssue[] = [];
	if (wildcardCerts > 0) {
		issues.push({
			type: 'wildcard_exposure',
			severity: 'info',
			detail: `${wildcardCerts} wildcard subdomain${wildcardCerts > 1 ? 's' : ''} found`,
		});
	}

	// Shadow subdomain detection — whole set, bounded rows (see MAX_PER_NAME_ISSUES).
	let shadowRows = 0;
	let shadowTotal = 0;
	for (const sd of dedupedAll) {
		if (sd.isWildcard) continue;
		const label = sd.subdomain.replace(domainSuffix, '').replace(/\.$/, '');
		if (label.includes('.')) continue;
		if (!COMMON_SUBDOMAINS.has(label)) {
			shadowTotal++;
			if (shadowRows >= MAX_PER_NAME_ISSUES) continue;
			shadowRows++;
			issues.push({
				type: 'shadow_subdomain',
				severity: 'info',
				detail: `${sd.subdomain} is not a common service name — verify it is authorized`,
			});
		}
	}
	if (shadowTotal > shadowRows) {
		issues.push({
			type: 'shadow_subdomain',
			severity: 'info',
			detail: `…and ${shadowTotal - shadowRows} further subdomains are not common service names (rows capped at ${MAX_PER_NAME_ISSUES} for readability; see the full list in the structured result)`,
		});
	}

	const sourceIndexExhausted = !upstream?.truncated && !upstream?.timedOut;
	// The fast path answers from ONE aggregator and never asks crt.sh or
	// Certspotter — `buildCtCoverage` turns that into an explicit `notConsulted`
	// list rather than letting a single opinion read as consensus.
	const flags = enumerationFlags(dedupedAll.length, deduped.length, ['certstream'], sourceIndexExhausted, [
		{ source: 'certstream', outcome: dedupedAll.length === 0 ? 'empty' : 'ok', contributed: true, indexExhausted: sourceIndexExhausted },
	]);
	if (flags.coverage && dedupedAll.length > 0) issues.unshift(sampleCaveatIssue(flags.coverage, dedupedAll.length));

	return {
		domain,
		totalSubdomains: dedupedAll.length,
		totalCertificates: certificateCount ?? dedupedAll.length,
		subdomains: deduped,
		wildcardCerts,
		expiredCerts: 0,
		uniqueIssuers: [],
		issues,
		...flags,
	};
}

/**
 * Build an empty result. `sourceUnavailable` distinguishes a CT lookup failure
 * (crt.sh non-OK / network error) from a successful query that found nothing.
 * `partial` indicates the deadline tripped before a stage could run.
 *
 * Every call carries a `high`-severity `unconfirmed_zero` issue: `isError`
 * (set by the handler for `sourceUnavailable`) is dropped by structured
 * consumers that read `issues[]` directly, so a bare `totalSubdomains: 0` +
 * `issues: []` reads as a confidently-verified absence of subdomains — the
 * success-shaped-zero this tool must never produce. CT logs are indirect
 * evidence at best (a subdomain with no certificate never appears in them),
 * so even a query that ran to completion cannot *positively* confirm zero
 * subdomains — it can only report that no certificate-issuance evidence was
 * found.
 */
function emptyResult(domain: string, sourceUnavailable = false, partial = false, meta?: EnumerationMeta): SubdomainDiscoveryResult {
	// A source outage or a budget trip is by definition not an exhaustive read —
	// never let an empty error read as a confident "none found".
	const sourceIndexExhausted = sourceUnavailable || partial ? false : (meta?.sourceIndexExhausted ?? true);
	return {
		domain,
		totalSubdomains: 0,
		totalCertificates: 0,
		subdomains: [],
		wildcardCerts: 0,
		expiredCerts: 0,
		uniqueIssuers: [],
		issues: [
			{
				type: 'unconfirmed_zero',
				severity: 'high',
				detail: sourceUnavailable
					? `Certificate Transparency enumeration for ${domain} did not complete — this zero-subdomain result reflects a lookup failure, not a confirmed absence of subdomains.`
					: `No Certificate Transparency source has positively confirmed ${domain} has zero subdomains — CT logs only capture certificate issuance, so this is an unconfirmed measurement, not a verified absence.`,
			},
		],
		sourceUnavailable,
		...(partial ? { partial: true } : {}),
		...enumerationFlags(0, 0, meta?.sources, sourceIndexExhausted, meta?.attempts),
	};
}

/**
 * Remediation prose for a total CT failure, split by WHY each source failed.
 *
 * The banner used to end "retry shortly" unconditionally. That is correct for an
 * upstream outage and actively misleading for a timeout: Certspotter returns
 * HTTP 504 `{"code":"timeout"}` for domains with a large certificate population
 * ("domains with a huge number of sub-domains or certificates" — its own words)
 * while answering smaller domains in the same window. Measured 2026-08-21:
 * `meta.com` timed out repeatedly; `anthropic.com` returned 200 / 43 KB. So the
 * timeout is a deterministic property of the DOMAIN under an unpaginated query,
 * not a transient property of the SOURCE — telling the caller to retry sends
 * them into a loop that cannot terminate, on precisely the largest estates.
 *
 * `notConsulted` is reported separately because it is not a failure at all: the
 * source was never asked (typically unbound in this deployment). Folding it into
 * "unavailable" implies three sources were tried when only two were (#735).
 */
function ctFailureGuidance(coverage: CtCoverage | undefined): string {
	const perSource = coverage?.perSource ?? [];
	const timedOut = perSource.filter((s) => s.outcome === 'timeout').map((s) => s.source);
	const errored = perSource.filter((s) => s.outcome === 'http_error' || s.outcome === 'error').map((s) => s.source);
	const never = coverage?.notConsulted ?? [];

	const parts: string[] = [];
	if (timedOut.length > 0) {
		parts.push(
			`${timedOut.join(', ')} timed out — for a domain with a large certificate population this is deterministic, not transient, so an identical retry will time out again; narrow the query or page the source.`,
		);
	}
	if (errored.length > 0) {
		parts.push(`${errored.join(', ')} returned an upstream error, which may be transient — a retry is worthwhile.`);
	}
	if (never.length > 0) {
		parts.push(`${never.join(', ')} was never consulted (not configured in this deployment), so no fallback source remained.`);
	}
	// Only reachable if a source failed with an outcome outside the known set.
	if (parts.length === 0) return 'Retry shortly.';
	return parts.join(' ');
}

/** Format subdomain discovery result as human-readable text. */
export function formatSubdomainDiscovery(result: SubdomainDiscoveryResult, format: OutputFormat = 'full'): string {
	// Both zero-ish branches carry the per-source coverage line: "which source
	// failed" is the first thing a caller needs in order to judge a zero.
	const coverageLine = result.coverage ? `\n${formatCoverageLine(result.coverage)}` : '';

	if (result.sourceUnavailable) {
		return `Subdomain Discovery: ${result.domain} — Certificate Transparency source unavailable; could not enumerate subdomains. This does not mean the domain has no subdomains. ${ctFailureGuidance(result.coverage)}${coverageLine}`;
	}
	if (result.totalSubdomains === 0) {
		// A STALE empty set is not a confident "none found" — say so, or the
		// original failure mode (an unreliable answer read as authoritative)
		// comes back through the zero branch.
		return result.stale
			? `${staleBanner(result)}\n\nSubdomain Discovery: ${result.domain} — the cached enumeration contains no subdomains; this is NOT a confirmed empty result.${coverageLine}`
			: `Subdomain Discovery: ${result.domain} — no subdomains found in Certificate Transparency logs (unconfirmed: CT logs only capture certificate issuance, so this is not a verified absence)${coverageLine}`;
	}

	const body = format === 'compact' ? formatCompact(result) : formatFull(result);
	const banners: string[] = [];
	// The sample caveat leads, UNCONDITIONALLY. The dangerous production shape was
	// a clean, exhausted, single-source answer — no banner fired, and the reader
	// took 165 names for a bank's estate. A caveat that only appears when
	// something visibly went wrong is the same false confidence in a new place.
	banners.push(sampleBanner(result));
	if (result.stale) banners.push(staleBanner(result));
	// Distinct from `stale` (served from the last-known-good cache): `partial`
	// here means a live source answered but timed out mid-query, so the data
	// shown is real but the enumeration may be incomplete. Skip when `stale`
	// already fired for this result — the stale banner already says the data
	// may not be current, and the two flags are not expected to co-occur from
	// the paths that set `partial:true` with real subdomain data.
	if (result.partial && !result.stale) banners.push(partialBanner());
	return banners.length > 0 ? `${banners.join('\n\n')}\n\n${body}` : body;
}

/**
 * The standing sample caveat + per-source coverage line, prepended to EVERY
 * rendered result.
 *
 * Falls back to fixed prose when `coverage` is absent (a hand-built fixture, or
 * a payload cached before this contract existed) — the caveat is never the thing
 * that goes missing.
 */
function sampleBanner(result: SubdomainDiscoveryResult): string {
	if (!result.coverage) {
		return `ℹ️ CT SAMPLE — NOT AN INVENTORY: ${result.totalSubdomains} is a LOWER BOUND. A host that has never had a publicly-logged certificate does not appear in Certificate Transparency at all.`;
	}
	return `ℹ️ CT SAMPLE — NOT AN INVENTORY: ${result.coverage.caveat}\n${formatCoverageLine(result.coverage)}`;
}

/** Staleness notice prepended when a result came from the last-known-good cache. */
function staleBanner(result: SubdomainDiscoveryResult): string {
	const age = result.cacheAgeMinutes ?? 0;
	const ageText =
		age < 60 ? `${age} minute${age === 1 ? '' : 's'}` : `${Math.floor(age / 60)} hour${Math.floor(age / 60) === 1 ? '' : 's'}`;
	return `⚠️ STALE RESULT (cached ${ageText} ago): every live Certificate Transparency source is currently unreachable, so this is the last known good enumeration — not a fresh one. Newly-issued certificates may be missing.`;
}

/**
 * Honest overflow/completeness lines for a rendered subdomain list.
 *
 * Two distinct truths, reported separately (issue #573 defect A): how many
 * enumerated names the TEXT is not showing, and whether the ENUMERATION itself
 * was complete. The old wording collapsed both into "…and N more", which under
 * a capped upstream fetch under-states the remainder and reads as reassurance —
 * bnz.co.nz rendered "and 40 more" when ~320 more existed.
 */
function overflowLines(result: SubdomainDiscoveryResult, shownCount: number, style: 'compact' | 'full'): string[] {
	const lines: string[] = [];
	const hidden = Math.max(0, result.totalSubdomains - shownCount);
	const incomplete = result.sourceIndexExhausted === false;

	if (hidden > 0) {
		// "at least N" — never a bare N — once the enumeration is known partial.
		const count = incomplete ? `at least ${hidden}` : `${hidden}`;
		lines.push(style === 'compact' ? ` ...and ${count} more` : `_...and ${count} more subdomains not shown_`);
	}

	if (incomplete) {
		const source = result.sources && result.sources.length > 0 ? result.sources.join(', ') : 'the Certificate Transparency source';
		// Escalation ON TOP of the standing sample caveat: not merely "CT can't see
		// everything", but "we did not even finish reading the source we used".
		const note = `⚠️ SOURCE INDEX NOT EXHAUSTED (${source}): we stopped reading this source before its index ended, so ${result.totalSubdomains} is short even of what THIS source holds.`;
		lines.push(style === 'compact' ? ` ${note}` : `_${note}_`);
	}

	return lines;
}

/** Partial notice prepended when a live source answered but timed out mid-query. */
function partialBanner(): string {
	return `⚠️ PARTIAL RESULT: the Certificate Transparency source timed out before finishing this enumeration — the subdomains below are real, but there may be more that were not found in time.`;
}

/** Compact format: concise one-line-per-subdomain output. */
function formatCompact(result: SubdomainDiscoveryResult): string {
	const lines: string[] = [];
	lines.push(`Subdomain Discovery: ${result.domain} — ${result.totalSubdomains} subdomains (${result.totalCertificates} certificates)`);
	if (result.uniqueIssuers.length > 0) {
		lines.push(`Issuers: ${result.uniqueIssuers.map((i) => sanitizeOutputText(i, 60)).join(', ')}`);
	}

	// Text rendering is capped well below the structural cap — the full list
	// stays in `structuredContent`.
	const shown = result.subdomains.slice(0, MAX_RENDERED_SUBDOMAINS);
	for (const sd of shown) {
		const tags: string[] = [];
		if (sd.isWildcard) tags.push('[WILDCARD]');
		if (sd.isExpired) tags.push('[EXPIRED]');
		const tagStr = tags.length > 0 ? ` ${tags.join(' ')}` : '';
		const lastDate = sd.lastSeen.slice(0, 10);
		lines.push(
			` ${sanitizeOutputText(sd.subdomain, 80)} (${sd.certCount} cert${sd.certCount !== 1 ? 's' : ''}, last: ${lastDate}, ${sanitizeOutputText(sd.issuer, 40)})${tagStr}`,
		);
	}

	lines.push(...overflowLines(result, shown.length, 'compact'));

	if (result.issues.length > 0) {
		lines.push('');
		lines.push('Issues:');
		for (const issue of result.issues) {
			const icon = issue.severity === 'high' ? '!!' : issue.severity === 'medium' ? '!' : '-';
			lines.push(` ${icon} [${issue.severity.toUpperCase()}] ${sanitizeOutputText(issue.detail, 200)}`);
		}
	}

	return lines.join('\n');
}

/** Full format: detailed output with headers and all metadata. */
function formatFull(result: SubdomainDiscoveryResult): string {
	const lines: string[] = [];
	lines.push(`# Subdomain Discovery: ${result.domain}`);
	lines.push(`Total: ${result.totalSubdomains} subdomains across ${result.totalCertificates} certificates`);
	lines.push(`Issuers: ${result.uniqueIssuers.map((i) => sanitizeOutputText(i, 60)).join(', ')}`);
	lines.push(`Wildcards: ${result.wildcardCerts} | Expired: ${result.expiredCerts}`);
	lines.push('');

	lines.push('## Subdomains');
	// ~4 lines per host, so the rendered list is capped far below the structural
	// cap; the complete list is in the structured payload.
	const shown = result.subdomains.slice(0, MAX_RENDERED_SUBDOMAINS);
	for (const sd of shown) {
		const tags: string[] = [];
		if (sd.isWildcard) tags.push('🔓 WILDCARD');
		if (sd.isExpired) tags.push('⏰ EXPIRED');
		const tagStr = tags.length > 0 ? ` [${tags.join(', ')}]` : '';
		lines.push(`**${sanitizeOutputText(sd.subdomain, 80)}**${tagStr}`);
		lines.push(`  Certs: ${sd.certCount} | First: ${sd.firstSeen.slice(0, 10)} | Last: ${sd.lastSeen.slice(0, 10)}`);
		lines.push(`  Issuer: ${sanitizeOutputText(sd.issuer, 80)}`);
		lines.push('');
	}

	const overflow = overflowLines(result, shown.length, 'full');
	if (overflow.length > 0) {
		lines.push(...overflow);
		lines.push('');
	}

	if (result.issues.length > 0) {
		lines.push('## Issues');
		for (const issue of result.issues) {
			const icon = issue.severity === 'high' ? '🔴' : issue.severity === 'medium' ? '🟠' : issue.severity === 'low' ? '🟡' : '🔵';
			lines.push(`${icon} [${issue.severity.toUpperCase()}] ${sanitizeOutputText(issue.detail, 300)}`);
		}
	}

	return lines.join('\n');
}
