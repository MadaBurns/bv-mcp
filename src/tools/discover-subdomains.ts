// SPDX-License-Identifier: BUSL-1.1

/**
 * Subdomain Discovery tool.
 * Queries Certificate Transparency logs (crt.sh) to discover subdomains
 * that have had certificates issued. Reveals shadow IT, forgotten services,
 * and unauthorized certificate issuance.
 */

import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';

/** Timeout for the crt.sh API request (ms). */
const CRT_SH_TIMEOUT_MS = 10_000;

/** Maximum subdomains to return (CT logs can contain thousands). */
const MAX_SUBDOMAINS = 100;

/** Common subdomain prefixes that are expected infrastructure. */
const COMMON_SUBDOMAINS = new Set([
	'www', 'api', 'mail', 'smtp', 'imap', 'pop', 'pop3', 'ftp', 'ns', 'ns1', 'ns2', 'ns3', 'ns4',
	'dns', 'mx', 'mx1', 'mx2', 'webmail', 'vpn', 'remote', 'cdn', 'static', 'assets', 'img',
	'images', 'media', 'docs', 'help', 'support', 'admin', 'portal', 'login', 'sso', 'auth',
	'app', 'dashboard', 'status', 'blog', 'shop', 'store', 'dev', 'staging', 'test', 'beta',
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
): Promise<SubdomainDiscoveryResult> {
	// Fast path: use certstream service binding
	if (certstream) {
		const result = await queryCertstream(domain, certstream);
		if (result) return result;
		// Fall through to crt.sh if service binding fails
	}

	const now = new Date();
	let entries: CrtShEntry[];

	try {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), CRT_SH_TIMEOUT_MS);

		const response = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
			signal: controller.signal,
			redirect: 'manual',
		});

		clearTimeout(timeoutId);

		if (!response.ok) {
			return emptyResult(domain);
		}

		entries = (await response.json()) as CrtShEntry[];
	} catch {
		return emptyResult(domain);
	}

	if (!Array.isArray(entries) || entries.length === 0) {
		return emptyResult(domain);
	}

	// Parse and aggregate subdomain data
	const trackers = new Map<string, SubdomainTracker>();
	const domainSuffix = `.${domain.toLowerCase()}`;
	let totalCertificates = 0;

	for (const entry of entries) {
		if (!entry.name_value) continue;

		// Split name_value on newlines — one cert can cover multiple names
		const names = entry.name_value.split('\n').map((n) => n.trim().toLowerCase()).filter(Boolean);
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

/** Query bv-certstream-worker via service binding. Returns null on failure. */
async function queryCertstream(
	domain: string,
	certstream: { fetch: typeof fetch },
): Promise<SubdomainDiscoveryResult | null> {
	try {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), CRT_SH_TIMEOUT_MS);

		const response = await certstream.fetch(
			`https://certstream/enumerate?domain=${encodeURIComponent(domain)}`,
			{ signal: controller.signal },
		);

		clearTimeout(timeoutId);

		if (!response.ok) return null;

		const data = (await response.json()) as CertstreamEnumerateResponse;
		if (data.error || !data.subdomains) return null;

		const now = new Date();
		const domainSuffix = `.${domain.toLowerCase()}`;
		const subdomains: DiscoveredSubdomain[] = [];

		for (const name of data.subdomains) {
			const lower = name.toLowerCase();
			if (lower === domain.toLowerCase()) continue;
			if (!lower.endsWith(domainSuffix) && !lower.startsWith('*.')) continue;

			subdomains.push({
				subdomain: lower,
				firstSeen: '',
				lastSeen: '',
				issuer: '',
				certCount: 1,
				isWildcard: lower.startsWith('*.'),
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
			totalCertificates: data.certificateCount ?? deduped.length,
			subdomains: deduped,
			wildcardCerts,
			expiredCerts: 0,
			uniqueIssuers: [],
			issues,
		};
	} catch {
		return null;
	}
}

/** Build an empty result for when crt.sh is unavailable or returns no data. */
function emptyResult(domain: string): SubdomainDiscoveryResult {
	return {
		domain,
		totalSubdomains: 0,
		totalCertificates: 0,
		subdomains: [],
		wildcardCerts: 0,
		expiredCerts: 0,
		uniqueIssuers: [],
		issues: [],
	};
}

/** Format subdomain discovery result as human-readable text. */
export function formatSubdomainDiscovery(result: SubdomainDiscoveryResult, format: OutputFormat = 'full'): string {
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
	lines.push(
		`Subdomain Discovery: ${result.domain} — ${result.totalSubdomains} subdomains (${result.totalCertificates} certificates)`,
	);
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
	lines.push(
		`Total: ${result.totalSubdomains} subdomains across ${result.totalCertificates} certificates`,
	);
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
			const icon =
				issue.severity === 'high' ? '🔴' : issue.severity === 'medium' ? '🟠' : issue.severity === 'low' ? '🟡' : '🔵';
			lines.push(`${icon} [${issue.severity.toUpperCase()}] ${sanitizeOutputText(issue.detail, 300)}`);
		}
	}

	return lines.join('\n');
}
