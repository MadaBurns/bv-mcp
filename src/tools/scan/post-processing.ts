// SPDX-License-Identifier: BUSL-1.1

import { type CheckCategory, type CheckResult, type Finding, buildCheckResult, createFinding } from '../../lib/scoring';
import { queryTxtRecords } from '../../lib/dns';
import { detectProviderMatches, detectProviderMatchesBySelectors, loadProviderSignatures } from '../../lib/provider-signatures';
import { parseDmarcTags } from '../check-dmarc';

export interface ScanRuntimeOptions {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
	profile?: 'mail_enabled' | 'enterprise_mail' | 'non_mail' | 'web_only' | 'minimal' | 'auto';
	profileAccumulator?: DurableObjectNamespace;
	waitUntil?: (promise: Promise<unknown>) => void;
	scoringConfig?: import('../../lib/scoring-config').ScoringConfig;
	/** Override cache TTL in seconds (default: 300). Clamped to [60, 3600]. */
	cacheTtlSeconds?: number;
	/** Custom secondary DoH resolver config (bv-dns). Threaded to scanDns but only active when skipSecondaryConfirmation is false. */
	secondaryDoh?: import('../../lib/dns-types').SecondaryDohConfig;
	/** Bypass cache and run a fresh scan. Useful for troubleshooting after DNS changes. */
	forceRefresh?: boolean;
}

export async function applyScanPostProcessing(
	domain: string,
	checkResults: CheckResult[],
	runtimeOptions?: ScanRuntimeOptions,
): Promise<CheckResult[]> {
	let results = checkResults;
	const mxResult = results.find((result) => result.category === 'mx');
	const hasNoMx = mxResult ? mxResult.findings.some((finding: Finding) => finding.title === 'No MX records found') : false;

	if (hasNoMx) {
		const apexCovers = await checkApexDmarcPolicy(domain);
		results = adjustForNonMailDomain(results, apexCovers);
		results = adjustBimiForNonMailDomain(results);
	} else if (mxResult) {
		results = clarifyMtaStsForMailDomain(domain, results);
	}

	// Detect no-send SPF policy (v=spf1 -all with no authorizing mechanisms)
	const spfResult = results.find((result) => result.category === 'spf');
	const hasNoSendPolicy = spfResult?.findings.some((f: Finding) => f.metadata?.noSendPolicy === true) ?? false;
	if (hasNoSendPolicy && !hasNoMx) {
		results = adjustForNoSendDomain(results);
	}

	return addOutboundProviderInference(results, runtimeOptions);
}

function extractSpfSignalDomains(result: CheckResult | undefined): string[] {
	if (!result) return [];

	const domains = new Set<string>();
	for (const finding of result.findings) {
		const metadata = finding.metadata;
		if (!metadata || typeof metadata !== 'object') continue;

		const includeDomains = metadata.includeDomains;
		if (Array.isArray(includeDomains)) {
			for (const domain of includeDomains) {
				if (typeof domain === 'string' && domain.trim().length > 0) {
					domains.add(domain.trim().toLowerCase());
				}
			}
		}

		const redirectDomain = metadata.redirectDomain;
		if (typeof redirectDomain === 'string' && redirectDomain.trim().length > 0) {
			domains.add(redirectDomain.trim().toLowerCase());
		}
	}

	return Array.from(domains);
}

function extractDkimSignalSelectors(result: CheckResult | undefined): string[] {
	if (!result) return [];

	const selectors = new Set<string>();
	for (const finding of result.findings) {
		const metadata = finding.metadata;
		if (!metadata || typeof metadata !== 'object') continue;

		const selectorsFound = metadata.selectorsFound;
		if (!Array.isArray(selectorsFound)) continue;

		for (const selector of selectorsFound) {
			if (typeof selector === 'string' && selector.trim().length > 0) {
				selectors.add(selector.trim().toLowerCase());
			}
		}
	}

	return Array.from(selectors);
}

function upsertCheckResult(results: CheckResult[], updated: CheckResult): CheckResult[] {
	return results.map((result) => (result.category === updated.category ? updated : result));
}

async function addOutboundProviderInference(results: CheckResult[], runtimeOptions?: ScanRuntimeOptions): Promise<CheckResult[]> {
	const spfResult = results.find((result) => result.category === 'spf');
	const dkimResult = results.find((result) => result.category === 'dkim');

	const signalDomains = extractSpfSignalDomains(spfResult);
	const dkimSelectors = extractDkimSignalSelectors(dkimResult);
	if (signalDomains.length === 0 && dkimSelectors.length === 0) return results;

	const signatures = await loadProviderSignatures({
		sourceUrl: runtimeOptions?.providerSignaturesUrl,
		allowedHosts: runtimeOptions?.providerSignaturesAllowedHosts,
		expectedSha256: runtimeOptions?.providerSignaturesSha256,
	});
	const signatureSet = signatures.outbound.length > 0 ? signatures.outbound : signatures.inbound;
	const hostMatches = detectProviderMatches(signalDomains, signatureSet);
	const selectorMatches = detectProviderMatchesBySelectors(dkimSelectors, signatureSet);

	const mergedMatches = new Map<string, Set<string>>();
	for (const match of [...hostMatches, ...selectorMatches]) {
		if (!mergedMatches.has(match.provider)) {
			mergedMatches.set(match.provider, new Set<string>());
		}
		for (const evidence of match.matches) {
			mergedMatches.get(match.provider)?.add(evidence);
		}
	}

	const outboundMatches = Array.from(mergedMatches.entries()).map(([provider, matches]) => ({
		provider,
		matches: Array.from(matches),
	}));
	if (outboundMatches.length === 0) return results;

	const providerNames = outboundMatches.map((match) => match.provider).join(', ');
	const evidence = outboundMatches.map((match) => `${match.provider}: ${match.matches.join(', ')}`).join('; ');
	const signalBoost = signalDomains.length > 0 && dkimSelectors.length > 0 ? 0.05 : 0;
	const baseConfidence = signatures.source === 'runtime' ? 0.85 : signatures.source === 'stale' ? 0.7 : 0.65;
	const providerConfidence = Math.min(0.95, baseConfidence + signalBoost);

	const spfBaseline = spfResult ?? buildCheckResult('spf', []);
	const updatedSpf = buildCheckResult('spf', [
		...spfBaseline.findings,
		createFinding('spf', 'Outbound email provider inferred', 'info', `Outbound provider(s): ${providerNames}. Evidence: ${evidence}.`, {
			detectionType: 'outbound',
			providers: outboundMatches.map((match) => ({ name: match.provider, matches: match.matches })),
			signalsUsed: {
				spfDomains: signalDomains,
				dkimSelectors,
			},
			providerConfidence,
			signatureSource: signatures.source,
			signatureVersion: signatures.version,
			signatureFetchedAt: signatures.fetchedAt,
		}),
	]);

	return upsertCheckResult(results, updatedSpf);
}

function getParentDomain(domain: string): string | null {
	const parts = domain.split('.');
	if (parts.length <= 2) return null;
	return parts.slice(1).join('.');
}

async function checkApexDmarcPolicy(domain: string): Promise<boolean> {
	const parent = getParentDomain(domain);
	if (!parent) return false;

	try {
		const records = await queryTxtRecords(`_dmarc.${parent}`);
		const dmarcRecord = records.find((record) => record.toLowerCase().startsWith('v=dmarc1'));
		if (!dmarcRecord) return false;

		const tags = parseDmarcTags(dmarcRecord);
		const effectivePolicy = tags.get('sp') || tags.get('p') || '';
		return effectivePolicy === 'quarantine' || effectivePolicy === 'reject';
	} catch {
		return false;
	}
}

function isMissingRecordFinding(finding: { title: string; detail: string }): boolean {
	// Match against title only (controlled by check modules, not DNS data) to avoid ReDoS on attacker-controlled detail strings
	const title = finding.title.toLowerCase();
	return (
		title.includes('missing') ||
		title.includes('not found') ||
		title.includes('no mta-sts') ||
		title.includes('no dkim') ||
		/^no\s+\S+\s+record/.test(title)
	);
}

function clarifyMtaStsForMailDomain(domain: string, results: CheckResult[]): CheckResult[] {
	return results.map((result) => {
		if (result.category !== 'mta_sts') return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if (finding.title === 'No MTA-STS or TLS-RPT records found') {
				return {
					...finding,
					detail: `Neither MTA-STS nor TLS-RPT records are present for ${domain}. Since this domain has MX records and accepts email, adding MTA-STS and TLS-RPT is recommended to protect inbound email in transit.`,
				};
			}
			return finding;
		});
		return buildCheckResult(result.category, adjusted);
	});
}

function adjustForNonMailDomain(results: CheckResult[], apexDmarcCovers: boolean): CheckResult[] {
	const emailCategories: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'mta_sts'];
	return results.map((result) => {
		if (!emailCategories.includes(result.category)) return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if ((finding.severity === 'critical' || finding.severity === 'high') && isMissingRecordFinding(finding)) {
				const reason = apexDmarcCovers
					? 'expected — no MX records and parent domain DMARC policy covers subdomains'
					: 'expected — domain has no MX records';
				return { ...finding, severity: 'info' as const, detail: `${finding.detail} (${reason})` };
			}
			return finding;
		});
		return buildCheckResult(result.category, adjusted);
	});
}

function adjustBimiForNonMailDomain(results: CheckResult[]): CheckResult[] {
	return results.map((result) => {
		if (result.category !== 'bimi') return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if (finding.title === 'No BIMI record found' && finding.detail.includes('eligible for BIMI')) {
				const bimiDomain = finding.detail.match(/at (default\._bimi\.\S+)/)?.[1] ?? `default._bimi.unknown`;
				return {
					...finding,
					detail: `No BIMI record found at ${bimiDomain}. This domain does not appear to send email, so BIMI is not applicable.`,
				};
			}
			return finding;
		});
		return buildCheckResult(result.category, adjusted);
	});
}

function adjustForNoSendDomain(results: CheckResult[]): CheckResult[] {
	const noSendCategories: CheckCategory[] = ['dkim', 'mta_sts', 'bimi'];
	return results.map((result) => {
		if (!noSendCategories.includes(result.category)) return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if ((finding.severity === 'critical' || finding.severity === 'high') && isMissingRecordFinding(finding)) {
				return {
					...finding,
					severity: 'info' as const,
					detail: `${finding.detail} (expected — domain SPF policy rejects all outbound mail)`,
				};
			}
			return finding;
		});
		return buildCheckResult(result.category, adjusted);
	});
}