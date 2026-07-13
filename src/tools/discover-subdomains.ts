// SPDX-License-Identifier: BUSL-1.1

/**
 * Subdomain Discovery tool.
 * Queries Certificate Transparency logs (crt.sh) to discover subdomains
 * that have had certificates issued. Reveals shadow IT, forgotten services,
 * and unauthorized certificate issuance.
 */

import type { OutputFormat } from '../handlers/tool-args';
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

/** Timeout for the crt.sh API request (ms). */
const CRT_SH_TIMEOUT_MS = 10_000;

/** Maximum bytes accepted from the public crt.sh fallback. */
const CRT_SH_MAX_BODY_BYTES = 5 * 1024 * 1024;

/** Maximum subdomains to return (CT logs can contain thousands). */
const MAX_SUBDOMAINS = 100;

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
	type: 'expired_subdomain' | 'wildcard_exposure' | 'many_issuers' | 'recent_issuance' | 'shadow_subdomain';
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
	// Fast path: use certstream service binding
	if (certstream) {
		const result = await queryCertstream(domain, certstream, certstreamAuthToken, options);
		if (result) return result;
		// Fall through to crt.sh if service binding fails
	}

	// Deadline gate before the crt.sh fallback (slowest stage).
	if (deadlineExceeded(options)) {
		return emptyResult(domain, true, true);
	}

	const now = new Date();
	let entries: CrtShEntry[];

	try {
		const composed = composeAbortSignal(CRT_SH_TIMEOUT_MS, options?.signal);

		const response = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json&exclude=expired`, {
			signal: composed.signal,
			redirect: 'manual',
		});

		composed.cleanup();

		if (!response.ok) {
			return emptyResult(domain, true);
		}

		const declaredLength = Number(response.headers.get('content-length'));
		if (Number.isFinite(declaredLength) && declaredLength > CRT_SH_MAX_BODY_BYTES) {
			await disposeUnreadResponseBody(response);
			return emptyResult(domain, true);
		}

		const rawBody = await readBoundedOrNull(response.body, CRT_SH_MAX_BODY_BYTES);
		if (rawBody === null) return emptyResult(domain, true);
		entries = JSON.parse(rawBody) as CrtShEntry[];
	} catch {
		return emptyResult(domain, true);
	}

	if (!Array.isArray(entries) || entries.length === 0) {
		return emptyResult(domain);
	}

	// Cap entries to prevent memory exhaustion on domains with huge CT histories
	if (entries.length > 5000) {
		entries = entries.slice(0, 5000);
	}

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

	// Limit to MAX_SUBDOMAINS
	const subdomains = allSubdomains.slice(0, MAX_SUBDOMAINS);

	// Collect unique issuers
	const issuerSet = new Set<string>();
	for (const sd of allSubdomains) {
		if (sd.issuer) issuerSet.add(sd.issuer);
	}
	const uniqueIssuers = Array.from(issuerSet);

	// Count wildcards and expired
	const wildcardCerts = subdomains.filter((s) => s.isWildcard).length;
	const expiredCerts = subdomains.filter((s) => s.isExpired).length;

	// Detect issues
	const issues: SubdomainIssue[] = [];

	// Expired subdomains — only certs expired
	for (const sd of subdomains) {
		if (sd.isExpired) {
			issues.push({
				type: 'expired_subdomain',
				severity: 'medium',
				detail: `${sd.subdomain} has only expired certificates — may be abandoned`,
			});
		}
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

	// Shadow subdomains — not matching common patterns, with recent certs
	const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
	for (const sd of subdomains) {
		if (sd.isWildcard || sd.isExpired) continue;
		const label = sd.subdomain.replace(domainSuffix, '').replace(/\.$/, '');
		// Only consider single-label subdomains for shadow detection
		if (label.includes('.')) continue;
		if (!COMMON_SUBDOMAINS.has(label) && sd.lastSeen >= thirtyDaysAgo) {
			issues.push({
				type: 'shadow_subdomain',
				severity: 'info',
				detail: `${sd.subdomain} has recent certificate activity but is not a common service name — verify it is authorized`,
			});
		}
	}

	return {
		domain,
		totalSubdomains: allSubdomains.length,
		totalCertificates,
		subdomains,
		wildcardCerts,
		expiredCerts,
		uniqueIssuers,
		issues,
	};
}

/**
 * Query bv-certstream-worker via service binding. Returns null on failure.
 *
 * Pipeline: `/enumerate` (fast path) → `/sans` (fallback). Between stages we
 * check the optional deadline; if tripped, we either return the enumerate
 * result tagged `partial:true` (when it had data) or signal the orchestrator
 * to skip remaining stages by returning a partial empty result.
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

	const enumerate = await queryCertstreamEndpoint<CertstreamEnumerateResponse>('enumerate', domain, certstream, certstreamAuthToken, options);
	const enumerateResult =
		enumerate && !enumerate.error && Array.isArray(enumerate.subdomains)
			? buildCertstreamResult(domain, enumerate.subdomains, enumerate.certificateCount)
			: null;
	if (enumerateResult) return enumerateResult;

	// Deadline gate: if we already burned the budget on /enumerate, skip /sans
	// and let the orchestrator decide whether to fall through to crt.sh.
	if (deadlineExceeded(options)) {
		return emptyResult(domain, true, true);
	}

	const sans = await queryCertstreamEndpoint<CertstreamSansResponse>('sans', domain, certstream, certstreamAuthToken, options);
	return sans && !sans.error && Array.isArray(sans.names) ? buildCertstreamResult(domain, sans.names, sans.certificateCount) : null;
}

async function queryCertstreamEndpoint<T>(
	path: 'enumerate' | 'sans',
	domain: string,
	certstream: { fetch: typeof fetch },
	certstreamAuthToken?: string,
	options?: DiscoverSubdomainsOptions,
): Promise<T | null> {
	const composed = composeAbortSignal(CRT_SH_TIMEOUT_MS, options?.signal);

	try {
		const response = await certstream.fetch(`https://certstream/${path}?domain=${encodeURIComponent(domain)}`, {
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

function buildCertstreamResult(domain: string, names: string[], certificateCount: number | undefined): SubdomainDiscoveryResult {
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

	const deduped = Array.from(seen.values()).slice(0, MAX_SUBDOMAINS);
	const wildcardCerts = deduped.filter((s) => s.isWildcard).length;

	const issues: SubdomainIssue[] = [];
	if (wildcardCerts > 0) {
		issues.push({
			type: 'wildcard_exposure',
			severity: 'info',
			detail: `${wildcardCerts} wildcard subdomain${wildcardCerts > 1 ? 's' : ''} found`,
		});
	}

	// Shadow subdomain detection
	for (const sd of deduped) {
		if (sd.isWildcard) continue;
		const label = sd.subdomain.replace(domainSuffix, '').replace(/\.$/, '');
		if (label.includes('.')) continue;
		if (!COMMON_SUBDOMAINS.has(label)) {
			issues.push({
				type: 'shadow_subdomain',
				severity: 'info',
				detail: `${sd.subdomain} is not a common service name — verify it is authorized`,
			});
		}
	}

	return {
		domain,
		totalSubdomains: deduped.length,
		totalCertificates: certificateCount ?? deduped.length,
		subdomains: deduped,
		wildcardCerts,
		expiredCerts: 0,
		uniqueIssuers: [],
		issues,
	};
}

/**
 * Build an empty result. `sourceUnavailable` distinguishes a CT lookup failure
 * (crt.sh non-OK / network error) from a successful query that found nothing.
 * `partial` indicates the deadline tripped before a stage could run.
 */
function emptyResult(domain: string, sourceUnavailable = false, partial = false): SubdomainDiscoveryResult {
	return {
		domain,
		totalSubdomains: 0,
		totalCertificates: 0,
		subdomains: [],
		wildcardCerts: 0,
		expiredCerts: 0,
		uniqueIssuers: [],
		issues: [],
		sourceUnavailable,
		...(partial ? { partial: true } : {}),
	};
}

/** Format subdomain discovery result as human-readable text. */
export function formatSubdomainDiscovery(result: SubdomainDiscoveryResult, format: OutputFormat = 'full'): string {
	if (result.sourceUnavailable) {
		return `Subdomain Discovery: ${result.domain} — Certificate Transparency source unavailable (the CT log endpoint returned an error or was unreachable); could not enumerate subdomains. This does not mean the domain has no subdomains — retry shortly.`;
	}
	if (result.totalSubdomains === 0) {
		return `Subdomain Discovery: ${result.domain} — no subdomains found in Certificate Transparency logs`;
	}

	if (format === 'compact') {
		return formatCompact(result);
	}

	return formatFull(result);
}

/** Compact format: concise one-line-per-subdomain output. */
function formatCompact(result: SubdomainDiscoveryResult): string {
	const lines: string[] = [];
	lines.push(`Subdomain Discovery: ${result.domain} — ${result.totalSubdomains} subdomains (${result.totalCertificates} certificates)`);
	if (result.uniqueIssuers.length > 0) {
		lines.push(`Issuers: ${result.uniqueIssuers.map((i) => sanitizeOutputText(i, 60)).join(', ')}`);
	}

	for (const sd of result.subdomains) {
		const tags: string[] = [];
		if (sd.isWildcard) tags.push('[WILDCARD]');
		if (sd.isExpired) tags.push('[EXPIRED]');
		const tagStr = tags.length > 0 ? ` ${tags.join(' ')}` : '';
		const lastDate = sd.lastSeen.slice(0, 10);
		lines.push(
			` ${sanitizeOutputText(sd.subdomain, 80)} (${sd.certCount} cert${sd.certCount !== 1 ? 's' : ''}, last: ${lastDate}, ${sanitizeOutputText(sd.issuer, 40)})${tagStr}`,
		);
	}

	if (result.totalSubdomains > result.subdomains.length) {
		lines.push(` ...and ${result.totalSubdomains - result.subdomains.length} more`);
	}

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
	for (const sd of result.subdomains) {
		const tags: string[] = [];
		if (sd.isWildcard) tags.push('🔓 WILDCARD');
		if (sd.isExpired) tags.push('⏰ EXPIRED');
		const tagStr = tags.length > 0 ? ` [${tags.join(', ')}]` : '';
		lines.push(`**${sanitizeOutputText(sd.subdomain, 80)}**${tagStr}`);
		lines.push(`  Certs: ${sd.certCount} | First: ${sd.firstSeen.slice(0, 10)} | Last: ${sd.lastSeen.slice(0, 10)}`);
		lines.push(`  Issuer: ${sanitizeOutputText(sd.issuer, 80)}`);
		lines.push('');
	}

	if (result.totalSubdomains > result.subdomains.length) {
		lines.push(`_...and ${result.totalSubdomains - result.subdomains.length} more subdomains not shown_`);
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
