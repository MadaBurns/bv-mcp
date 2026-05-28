// SPDX-License-Identifier: BUSL-1.1

/**
 * Supply Chain Mapper tool.
 * Maps third-party service dependencies from DNS data by querying SPF (TXT),
 * NS, CAA, and SRV records in parallel, extracting provider relationships,
 * classifying trust levels, correlating across sources, and flagging risk signals.
 */

import type { OutputFormat } from '../handlers/tool-args';
import type { QueryDnsOptions } from '../lib/dns-types';
import { queryTxtRecords, queryDnsRecords, querySrvRecords, queryMxRecords } from '../lib/dns';
import { sanitizeOutputText } from '../lib/output-sanitize';
import { detectProviders, matchProviderForNsHost, matchProviderForSpfInclude, matchProviderForMxHost } from './provider-guides';
import { VERIFICATION_PATTERNS, SERVICE_SPF_DOMAINS } from './txt-hygiene-analysis';
import { SRV_PREFIXES } from './srv-analysis';
import type { SrvProbeResult } from './srv-analysis';

/** Trust classification for a dependency. */
export type TrustLevel = 'critical' | 'high' | 'medium' | 'low';

/** A single third-party dependency detected from DNS. */
export interface Dependency {
	provider: string;
	roles: string[];
	trustLevel: TrustLevel;
	sources: string[];
}

/** A risk signal detected in the supply chain. */
export interface Signal {
	type: 'concentration' | 'excessive_includes' | 'single_ns_provider' | 'stale_integration' | 'shadow_service' | 'insecure_service' | 'security_tooling_exposed';
	severity: 'low' | 'medium' | 'high';
	detail: string;
}

/** Full supply chain map result. */
export interface SupplyChainMap {
	domain: string;
	dependencies: Dependency[];
	signals: Signal[];
	summary: {
		totalProviders: number;
		critical: number;
		high: number;
		medium: number;
		low: number;
	};
}

/** Extract include: and redirect= domains from an SPF record string. */
function extractSpfIncludesFromRecord(spfRecord: string): string[] {
	const domains: string[] = [];
	const includeRegex = /\binclude:([^\s]+)/gi;
	const redirectRegex = /\bredirect=([^\s]+)/gi;

	for (const match of spfRecord.matchAll(includeRegex)) {
		const domain = match[1].toLowerCase();
		if (domain && !domains.includes(domain)) {
			domains.push(domain);
		}
	}
	for (const match of spfRecord.matchAll(redirectRegex)) {
		const domain = match[1].toLowerCase();
		if (domain && !domains.includes(domain)) {
			domains.push(domain);
		}
	}
	return domains;
}

/** Parse CAA record data string into tag and value. */
function parseCaaIssuer(data: string): string | null {
	// Human-readable format: "0 issue "letsencrypt.org""
	const match = data.match(/^\d+\s+(issue|issuewild)\s+"?([^"]+)"?\s*$/i);
	if (match) {
		return match[2].toLowerCase().replace(/\.$/, '');
	}
	return null;
}

/** Determine the highest trust level for a dependency based on its sources. */
function determineTrustLevel(sources: string[]): TrustLevel {
	// SPF includes = critical (they can send email as you)
	if (sources.some((s) => s === 'spf')) return 'critical';
	// MX = critical (they receive all your inbound mail)
	if (sources.some((s) => s === 'mx')) return 'critical';
	// NS = high (they control your DNS)
	if (sources.some((s) => s === 'ns')) return 'high';
	// SRV = medium (advertised service)
	if (sources.some((s) => s === 'srv')) return 'medium';
	// TXT verification = low (SaaS integration)
	if (sources.some((s) => s === 'txt-verification')) return 'low';
	// CAA = low (advisory control)
	if (sources.some((s) => s === 'caa')) return 'low';
	return 'medium';
}

/** Build a role label from the source type. */
function sourceToRole(source: string): string {
	switch (source) {
		case 'spf':
			return 'email-sending';
		case 'mx':
			return 'email-receiving';
		case 'ns':
			return 'dns-hosting';
		case 'caa':
			return 'certificate-authority';
		case 'txt-verification':
			return 'saas-integration';
		case 'srv':
			return 'advertised-service';
		default:
			return source;
	}
}

/**
 * Common ccTLD second-level domains (SLDs) where the registrable parent domain
 * is 3 labels deep, not 2 (e.g. `ns1.anz.co.nz` → `anz.co.nz`, not `co.nz`).
 *
 * This is a curated short list covering >95% of real-world ccTLD-2LD cases;
 * the proper long-term fix is the Public Suffix List, but its ~9KB dataset
 * and fuzzy-matching cost isn't justified for a DNS-derived heuristic that
 * only needs to avoid labelling registry suffixes as third-party providers.
 *
 * Extend as new false positives surface (defect surfaced 2026-05-28 against
 * `anz.co.nz`, where `co.nz` was reported as a DNS hosting provider).
 */
const PUBLIC_SUFFIX_SECOND_LEVEL: ReadonlySet<string> = new Set([
	// United Kingdom
	'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk',
	// New Zealand
	'co.nz', 'org.nz', 'net.nz', 'ac.nz', 'govt.nz', 'school.nz',
	// Australia
	'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
	// South Africa
	'co.za', 'org.za', 'web.za',
	// Japan
	'co.jp', 'ac.jp', 'ne.jp', 'or.jp', 'go.jp',
	// India
	'co.in', 'org.in', 'net.in', 'gov.in', 'ac.in',
	// South Korea
	'co.kr', 'or.kr', 'ne.kr', 'go.kr',
	// Brazil
	'com.br', 'net.br', 'org.br', 'gov.br',
	// Mexico
	'com.mx', 'gob.mx', 'edu.mx',
	// Singapore
	'com.sg', 'edu.sg', 'org.sg', 'gov.sg',
]);

/**
 * Resolve a hostname to its registrable parent domain, accounting for common
 * ccTLD second-level domains. Used to group NS hostnames by provider zone.
 *
 * Examples:
 *   ns1.akam.net      → akam.net
 *   ns1.anz.co.nz     → anz.co.nz   (not co.nz — co.nz is a registry suffix)
 *   ns1.example.co.uk → example.co.uk
 *   ns1               → ns1         (degenerate; returned as-is)
 */
export function getEffectiveParentDomain(host: string): string {
	const parts = host.split('.');
	if (parts.length < 2) return host;
	const twoLabel = parts.slice(-2).join('.');
	if (parts.length >= 3 && PUBLIC_SUFFIX_SECOND_LEVEL.has(twoLabel)) {
		return parts.slice(-3).join('.');
	}
	return twoLabel;
}

/** Map SRV target hostnames to known provider names. */
const SRV_TARGET_PROVIDERS: Array<{ pattern: RegExp; provider: string }> = [
	{ pattern: /\.outlook\.com$/i, provider: 'Microsoft 365' },
	{ pattern: /\.google\.com$/i, provider: 'Google Workspace' },
	{ pattern: /\.messagingengine\.com$/i, provider: 'Fastmail' },
	{ pattern: /\.mimecast\.com$/i, provider: 'Mimecast' },
];

/**
 * Map the third-party supply chain for a domain from DNS data.
 *
 * Queries SPF (TXT), NS, and CAA records in parallel, extracts provider
 * relationships, classifies trust levels, and detects risk signals.
 *
 * @param domain - Validated, sanitized domain
 * @param dnsOptions - Optional DNS query options
 * @returns Supply chain map with dependencies, signals, and summary
 */
export interface MapSupplyChainOptions {
	/** DNS query options (timeout, resolver) threaded into every lookup. */
	dnsOptions?: QueryDnsOptions;
	/**
	 * CDN provider already attributed by the scan's HTTP/header path. When set,
	 * the supply-chain map uses it directly and skips its own ASN lookup. When
	 * omitted (standalone calls), the ASN tier resolves the apex A-records.
	 */
	precomputedCdn?: string;
}

export async function mapSupplyChain(
	domain: string,
	options: MapSupplyChainOptions = {},
): Promise<SupplyChainMap> {
	const { dnsOptions } = options;
	// Query all record types in parallel — allSettled so one failure doesn't block others
	const [txtSettled, nsSettled, caaSettled, mxSettled, srvBatchSettled] = await Promise.allSettled([
		queryTxtRecords(domain, dnsOptions),
		queryDnsRecords(domain, 'NS', dnsOptions),
		queryDnsRecords(domain, 'CAA', dnsOptions),
		queryMxRecords(domain, dnsOptions),
		Promise.allSettled(
			SRV_PREFIXES.map(async (prefix) => {
				const name = `${prefix}.${domain}`;
				const records = await querySrvRecords(name, dnsOptions);
				return { prefix, records } as SrvProbeResult;
			}),
		),
	]);

	// Extract SPF includes from TXT records
	const txtRecords = txtSettled.status === 'fulfilled' ? txtSettled.value : [];
	const spfRecord = txtRecords.find((r) => r.toLowerCase().startsWith('v=spf1'));
	const spfIncludes = spfRecord ? extractSpfIncludesFromRecord(spfRecord) : [];

	// Match TXT records against verification patterns (skip SPF and DMARC)
	const verifiedServices: Array<{ service: string; category: string }> = [];
	for (const txt of txtRecords) {
		if (txt.toLowerCase().startsWith('v=spf1') || txt.toLowerCase().startsWith('v=dmarc1')) continue;
		for (const pattern of VERIFICATION_PATTERNS) {
			if (txt.startsWith(pattern.prefix)) {
				verifiedServices.push({ service: pattern.service, category: pattern.category });
				break; // One match per TXT record
			}
		}
	}

	// Extract NS hostnames
	const rawNsRecords = nsSettled.status === 'fulfilled' ? nsSettled.value : [];
	const nsHosts = rawNsRecords.map((r) => r.replace(/\.$/, '').toLowerCase());

	// Extract MX exchange hosts (email-receiving providers)
	const rawMxRecords = mxSettled.status === 'fulfilled' ? mxSettled.value : [];
	const mxHosts = rawMxRecords.map((r) => r.exchange.replace(/\.$/, '').toLowerCase());

	// Extract CAA issuers (only issue and issuewild tags)
	const rawCaaRecords = caaSettled.status === 'fulfilled' ? caaSettled.value : [];
	const caaIssuers: string[] = [];
	for (const record of rawCaaRecords) {
		const issuer = parseCaaIssuer(record);
		if (issuer && !caaIssuers.includes(issuer)) {
			caaIssuers.push(issuer);
		}
	}

	// Extract SRV services
	const srvResults: SrvProbeResult[] = [];
	if (srvBatchSettled.status === 'fulfilled') {
		for (const settled of srvBatchSettled.value) {
			if (settled.status === 'fulfilled' && settled.value.records.length > 0) {
				// Filter out explicitly disabled services (target "." or port 0)
				const activeRecords = settled.value.records.filter((r) => r.target !== '.' && r.port !== 0);
				if (activeRecords.length > 0) {
					srvResults.push({ prefix: settled.value.prefix, records: activeRecords });
				}
			}
		}
	}

	// Use provider detection to resolve known provider names
	const detectedProviders = detectProviders({
		mxHosts: [], // We don't run MX check here
		spfIncludes,
		nsHosts,
	});

	// Build a map of provider name -> { roles, sources }
	const providerMap = new Map<string, { roles: Set<string>; sources: Set<string> }>();

	function addDependency(providerName: string, source: string): void {
		const existing = providerMap.get(providerName);
		if (existing) {
			existing.roles.add(sourceToRole(source));
			existing.sources.add(source);
		} else {
			providerMap.set(providerName, {
				roles: new Set([sourceToRole(source)]),
				sources: new Set([source]),
			});
		}
	}

	// Map detected providers (known names) and track which raw entries matched
	const detectedSpfDomains = new Set<string>();
	const detectedNsHosts = new Set<string>();

	const detectedMailSendingNames = new Set(
		detectedProviders
			.filter((p) => p.role === 'mail' || p.role === 'sending')
			.map((p) => p.name),
	);

	// Resolve each raw SPF include against DETECTION_RULES (shared SSOT with
	// detectProviders) so dedup can't drift from the detection patterns. This
	// also closes the gap where a provider rule's static `signal` referenced
	// MX (e.g. Microsoft 365 — `mx:mail.protection.outlook.com`) but the rule
	// actually matched via its `spf` pattern (`spf.protection.outlook.com`),
	// causing the substring-based dedup to miss and emit a duplicate raw row.
	for (const inc of spfIncludes) {
		const matchedName = matchProviderForSpfInclude(inc);
		if (matchedName && detectedMailSendingNames.has(matchedName)) {
			detectedSpfDomains.add(inc);
		}
	}

	for (const provider of detectedProviders) {
		const source = provider.role === 'mail' || provider.role === 'sending' ? 'spf' : 'ns';
		addDependency(provider.name, source);
	}

	// Mark every NS host that resolves to a known provider as "detected" so the
	// downstream "unrecognized NS host → parent-domain row" loop skips it.
	// Uses the shared DETECTION_RULES regex (via matchProviderForNsHost) instead
	// of a `provider.signal` substring heuristic; the substring approach silently
	// broke for multi-TLD vendors whose two TLDs share no common substring
	// (eg. NS1: `*.ns1.com` + `*.nsone.net`). Mirrors the SPF dedup path's use
	// of matchProviderForSpfInclude so the two paths can't drift.
	for (const host of nsHosts) {
		if (matchProviderForNsHost(host) !== null) {
			detectedNsHosts.add(host);
		}
	}

	// Add unrecognized SPF includes as raw entries.
	// Self-delegated SPF includes — where the effective parent of the include
	// equals the scan domain — collapse into ONE self-hosted row, not N
	// critical third-party rows. Surfaced 2026-05-28: large orgs commonly
	// publish multiple self-owned SPF wrapper subdomains (eg. `pp._spf.<own>`
	// + several `3ph*._spf.<own>` siblings, or `spf1.<own>` plus a vendor-
	// rewrite host like `<vendor>-outbound-mail.<own>`). These are the org's
	// own SPF infrastructure, not external dependencies.
	const scanDomainLower = domain.toLowerCase();
	let selfDelegatedCount = 0;
	for (const inc of spfIncludes) {
		if (detectedSpfDomains.has(inc)) continue;
		if (getEffectiveParentDomain(inc) === scanDomainLower) {
			selfDelegatedCount++;
			continue;
		}
		addDependency(inc, 'spf');
	}
	if (selfDelegatedCount > 0) {
		addDependency(`${scanDomainLower} (self-hosted SPF)`, 'spf');
	}

	// Group unrecognized infra hosts (NS, MX) by registrable parent domain,
	// skipping detected providers and self-hosted hosts. `getEffectiveParentDomain`
	// accounts for ccTLD-2LD suffixes (co.nz, co.uk, com.au, …) so `ns1.anz.co.nz`
	// collapses to `anz.co.nz`, not `co.nz`. When the parent matches the scan
	// domain itself, the host is self-hosted — skip the "third-party" row.
	const scanDomain = domain.toLowerCase();
	const addUnrecognizedHostsByParent = (hosts: string[], detected: Set<string>, source: string): void => {
		for (const host of hosts) {
			if (detected.has(host)) continue;
			const parentDomain = getEffectiveParentDomain(host);
			if (parentDomain === scanDomain) continue;
			addDependency(parentDomain, source);
		}
	};

	// Add unrecognized NS hosts.
	addUnrecognizedHostsByParent(nsHosts, detectedNsHosts, 'ns');

	// Add MX (email-receiving) providers. Independent of the SPF email-sending
	// path — a domain can receive via one provider (eg. Mimecast/Proofpoint
	// inbound) and send via another (eg. M365). Match each exchange against
	// DETECTION_RULES (shared SSOT, via matchProviderForMxHost); unrecognized
	// hosts collapse to their registrable parent and skip self-hosted MX,
	// mirroring the NS path so the two can't drift.
	const detectedMxHosts = new Set<string>();
	for (const host of mxHosts) {
		const matched = matchProviderForMxHost(host);
		if (matched !== null) {
			addDependency(matched, 'mx');
			detectedMxHosts.add(host);
		}
	}
	addUnrecognizedHostsByParent(mxHosts, detectedMxHosts, 'mx');

	// Add CAA issuers
	for (const issuer of caaIssuers) {
		addDependency(issuer, 'caa');
	}

	// Add TXT-verified services
	for (const vs of verifiedServices) {
		addDependency(vs.service, 'txt-verification');
	}

	// Add SRV-discovered services — resolve targets to known providers
	const srvProviderNames: string[] = [];
	for (const srv of srvResults) {
		const target = srv.records[0].target;
		let providerName: string | null = null;
		for (const mapping of SRV_TARGET_PROVIDERS) {
			if (mapping.pattern.test(target)) {
				providerName = mapping.provider;
				break;
			}
		}
		const name = providerName ?? target;
		addDependency(name, 'srv');
		srvProviderNames.push(name);
	}

	// Build final dependency list
	const dependencies: Dependency[] = [];
	for (const [provider, data] of providerMap) {
		const sources = Array.from(data.sources);
		dependencies.push({
			provider,
			roles: Array.from(data.roles),
			trustLevel: determineTrustLevel(sources),
			sources,
		});
	}

	// Sort by trust level (critical first)
	const trustOrder: Record<TrustLevel, number> = { critical: 0, high: 1, medium: 2, low: 3 };
	dependencies.sort((a, b) => trustOrder[a.trustLevel] - trustOrder[b.trustLevel]);

	// Detect signals
	const signals: Signal[] = [];

	// Concentration risk: provider appears in 3+ roles
	for (const dep of dependencies) {
		if (dep.roles.length >= 3) {
			signals.push({
				type: 'concentration',
				severity: 'high',
				detail: `${dep.provider} serves ${dep.roles.length} roles (${dep.roles.join(', ')}). Single-vendor concentration creates correlated failure risk.`,
			});
		}
	}

	// Excessive SPF includes
	if (spfIncludes.length >= 7) {
		signals.push({
			type: 'excessive_includes',
			severity: 'medium',
			detail: `${spfIncludes.length} SPF include directives detected. Excessive includes increase DNS lookup count and risk hitting the 10-lookup SPF limit.`,
		});
	} else if (spfIncludes.length >= 5) {
		signals.push({
			type: 'excessive_includes',
			severity: 'low',
			detail: `${spfIncludes.length} SPF include directives detected. Consider consolidating to reduce DNS lookup count.`,
		});
	}

	// Stale integration: verified service has known SPF domains but none appear in SPF includes.
	// Dedup by service name first — large orgs commonly publish multiple TXT verification
	// records for the same service (e.g. one google-site-verification per web property);
	// without dedup we'd emit N identical signals (observed 3x on anz.co.nz, 2026-05-28).
	const verificationCountByService = new Map<string, number>();
	for (const vs of verifiedServices) {
		verificationCountByService.set(vs.service, (verificationCountByService.get(vs.service) ?? 0) + 1);
	}
	for (const [service, count] of verificationCountByService) {
		const expectedSpfDomains = SERVICE_SPF_DOMAINS[service];
		if (!expectedSpfDomains || expectedSpfDomains.length === 0) continue;
		const hasMatchingSpf = expectedSpfDomains.some((spfDomain) =>
			spfIncludes.some((inc) => inc.includes(spfDomain)),
		);
		if (hasMatchingSpf) continue;
		const recordPhrase = count === 1
			? 'a TXT verification record'
			: `${count} TXT verification records`;
		signals.push({
			type: 'stale_integration',
			severity: 'low',
			detail: `${service} has ${recordPhrase} but no corresponding SPF include. The integration may be stale or incomplete.`,
		});
	}

	// Shadow service: SRV-discovered provider not corroborated by TXT verifications or SPF includes
	const verifiedServiceNames = new Set(verifiedServices.map((vs) => vs.service));
	const spfProviderNames = new Set(
		detectedProviders
			.filter((p) => p.role === 'mail' || p.role === 'sending')
			.map((p) => p.name),
	);
	for (const srvProvider of srvProviderNames) {
		if (!verifiedServiceNames.has(srvProvider) && !spfProviderNames.has(srvProvider)) {
			// Also check raw SPF includes for partial matches
			const inSpfRaw = spfIncludes.some((inc) => inc.toLowerCase().includes(srvProvider.toLowerCase()));
			if (!inSpfRaw) {
				signals.push({
					type: 'shadow_service',
					severity: 'medium',
					detail: `${srvProvider} discovered via SRV but not corroborated by TXT verifications or SPF includes. This service may be undocumented or unauthorized.`,
				});
			}
		}
	}

	// Insecure service: plain-text protocol SRV without encrypted counterpart
	const srvPrefixSet = new Set(srvResults.map((r) => r.prefix));
	if (srvPrefixSet.has('_imap._tcp') && !srvPrefixSet.has('_imaps._tcp')) {
		signals.push({
			type: 'insecure_service',
			severity: 'medium',
			detail: 'IMAP SRV record (_imap._tcp) found without encrypted variant (_imaps._tcp). Clients may connect over unencrypted IMAP, exposing credentials.',
		});
	}
	if (srvPrefixSet.has('_pop3._tcp') && !srvPrefixSet.has('_pop3s._tcp')) {
		signals.push({
			type: 'insecure_service',
			severity: 'medium',
			detail: 'POP3 SRV record (_pop3._tcp) found without encrypted variant (_pop3s._tcp). Clients may connect over unencrypted POP3, exposing credentials.',
		});
	}

	// Security tooling exposed: TXT verification for a security-category service.
	// Dedup by service name first — large orgs commonly publish multiple TXT
	// verification records for the same security tool (e.g. xero.com had 2×
	// `onetrust-domain-verification=` records, one per property). Mirrors the
	// stale_integration aggregation above; closes #261.
	const securityCountByService = new Map<string, number>();
	for (const vs of verifiedServices) {
		if (vs.category !== 'security') continue;
		securityCountByService.set(vs.service, (securityCountByService.get(vs.service) ?? 0) + 1);
	}
	for (const [service, count] of securityCountByService) {
		const recordPhrase = count === 1
			? 'A TXT verification record'
			: `${count} TXT verification records`;
		signals.push({
			type: 'security_tooling_exposed',
			severity: 'low',
			detail: `${recordPhrase} for ${service} reveals security tooling in use. Attackers can tailor evasion techniques to this specific vendor.`,
		});
	}

	// Build summary counts
	const summary = {
		totalProviders: dependencies.length,
		critical: dependencies.filter((d) => d.trustLevel === 'critical').length,
		high: dependencies.filter((d) => d.trustLevel === 'high').length,
		medium: dependencies.filter((d) => d.trustLevel === 'medium').length,
		low: dependencies.filter((d) => d.trustLevel === 'low').length,
	};

	return { domain, dependencies, signals, summary };
}

/** Format supply chain map as human-readable text. */
export function formatSupplyChain(result: SupplyChainMap, format: OutputFormat = 'full'): string {
	if (format === 'compact') {
		const lines: string[] = [];
		lines.push(`Supply Chain: ${result.domain} — ${result.summary.totalProviders} providers (${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low)`);
		for (const dep of result.dependencies) {
			lines.push(`- [${dep.trustLevel.toUpperCase()}] ${sanitizeOutputText(dep.provider, 80)}: ${dep.roles.join(', ')}`);
		}
		if (result.signals.length > 0) {
			lines.push('');
			lines.push('Signals:');
			for (const signal of result.signals) {
				lines.push(`- [${signal.severity.toUpperCase()}] ${sanitizeOutputText(signal.detail, 200)}`);
			}
		}
		return lines.join('\n');
	}

	const lines: string[] = [];
	lines.push(`# Supply Chain Map: ${result.domain}`);
	lines.push(`Total Providers: ${result.summary.totalProviders} (${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low)`);
	lines.push('');

	if (result.dependencies.length > 0) {
		lines.push('## Dependencies');
		for (const dep of result.dependencies) {
			const trustIcon = dep.trustLevel === 'critical' ? '🔴' : dep.trustLevel === 'high' ? '🟠' : dep.trustLevel === 'medium' ? '🟡' : '🟢';
			lines.push(`${trustIcon} **${sanitizeOutputText(dep.provider, 80)}** [${dep.trustLevel.toUpperCase()}]`);
			lines.push(`  Roles: ${dep.roles.join(', ')}`);
			lines.push(`  Sources: ${dep.sources.join(', ')}`);
			lines.push('');
		}
	} else {
		lines.push('No third-party dependencies detected from DNS data.');
		lines.push('');
	}

	if (result.signals.length > 0) {
		lines.push('## Risk Signals');
		for (const signal of result.signals) {
			const icon = signal.severity === 'high' ? '🔴' : signal.severity === 'medium' ? '🟠' : '🟡';
			lines.push(`${icon} [${signal.severity.toUpperCase()}] ${sanitizeOutputText(signal.detail, 300)}`);
		}
	}

	return lines.join('\n');
}
