// SPDX-License-Identifier: BUSL-1.1

/**
 * Supply Chain Mapper tool.
 * Maps third-party service dependencies from DNS data by querying SPF (TXT),
 * NS, and CAA records in parallel, extracting provider relationships,
 * classifying trust levels, and flagging risk signals.
 */

import type { OutputFormat } from '../handlers/tool-args';
import type { QueryDnsOptions } from '../lib/dns-types';
import { queryTxtRecords, queryDnsRecords } from '../lib/dns';
import { sanitizeOutputText } from '../lib/output-sanitize';
import { detectProviders } from './provider-guides';

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
	type: 'concentration' | 'excessive_includes' | 'single_ns_provider';
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
	// NS = high (they control your DNS)
	if (sources.some((s) => s === 'ns')) return 'high';
	// CAA = low (advisory control)
	if (sources.some((s) => s === 'caa')) return 'low';
	return 'medium';
}

/** Build a role label from the source type. */
function sourceToRole(source: string): string {
	switch (source) {
		case 'spf':
			return 'email-sending';
		case 'ns':
			return 'dns-hosting';
		case 'caa':
			return 'certificate-authority';
		default:
			return source;
	}
}

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
export async function mapSupplyChain(
	domain: string,
	dnsOptions?: QueryDnsOptions,
): Promise<SupplyChainMap> {
	// Query all three record types in parallel — allSettled so one failure doesn't block others
	const [txtSettled, nsSettled, caaSettled] = await Promise.allSettled([
		queryTxtRecords(domain, dnsOptions),
		queryDnsRecords(domain, 'NS', dnsOptions),
		queryDnsRecords(domain, 'CAA', dnsOptions),
	]);

	// Extract SPF includes from TXT records
	const txtRecords = txtSettled.status === 'fulfilled' ? txtSettled.value : [];
	const spfRecord = txtRecords.find((r) => r.toLowerCase().startsWith('v=spf1'));
	const spfIncludes = spfRecord ? extractSpfIncludesFromRecord(spfRecord) : [];

	// Extract NS hostnames
	const rawNsRecords = nsSettled.status === 'fulfilled' ? nsSettled.value : [];
	const nsHosts = rawNsRecords.map((r) => r.replace(/\.$/, '').toLowerCase());

	// Extract CAA issuers (only issue and issuewild tags)
	const rawCaaRecords = caaSettled.status === 'fulfilled' ? caaSettled.value : [];
	const caaIssuers: string[] = [];
	for (const record of rawCaaRecords) {
		const issuer = parseCaaIssuer(record);
		if (issuer && !caaIssuers.includes(issuer)) {
			caaIssuers.push(issuer);
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

	for (const provider of detectedProviders) {
		const source = provider.role === 'mail' || provider.role === 'sending' ? 'spf' : 'ns';
		addDependency(provider.name, source);

		if (source === 'spf') {
			for (const inc of spfIncludes) {
				if (provider.signal.startsWith('spf:') || provider.signal.startsWith('mx:')) {
					const signalDomain = provider.signal.split(':').slice(1).join(':');
					if (inc.includes(signalDomain)) {
						detectedSpfDomains.add(inc);
					}
				}
			}
		} else {
			for (const host of nsHosts) {
				if (provider.signal.startsWith('ns:')) {
					const signalDomain = provider.signal.split(':').slice(1).join(':');
					if (host.includes(signalDomain)) {
						detectedNsHosts.add(host);
					}
				}
			}
		}
	}

	// Add unrecognized SPF includes as raw entries
	for (const inc of spfIncludes) {
		if (!detectedSpfDomains.has(inc)) {
			addDependency(inc, 'spf');
		}
	}

	// Add unrecognized NS hosts — group by parent domain
	for (const host of nsHosts) {
		if (!detectedNsHosts.has(host)) {
			const parts = host.split('.');
			const parentDomain = parts.length >= 2 ? parts.slice(-2).join('.') : host;
			addDependency(parentDomain, 'ns');
		}
	}

	// Add CAA issuers
	for (const issuer of caaIssuers) {
		addDependency(issuer, 'caa');
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
