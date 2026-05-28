// SPDX-License-Identifier: BUSL-1.1

import { type CheckCategory, type CheckResult, type Finding, buildCheckResult, createFinding } from '../../lib/scoring';
import { queryTxtRecords } from '../../lib/dns';
import { queryDnsRecords } from '../../lib/dns-records';
import { detectProviderMatches, detectProviderMatchesBySelectors, loadProviderSignatures } from '../../lib/provider-signatures';
import { detectCloudflareFallback } from '../../lib/cdn-fallback-detection';
import { parseDmarcTags } from '../check-dmarc';

export interface ScanRuntimeOptions {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
	profile?: 'mail_enabled' | 'enterprise_mail' | 'non_mail' | 'web_only' | 'minimal' | 'auto' | 'authoritative_dns_infra';
	profileAccumulator?: DurableObjectNamespace;
	waitUntil?: (promise: Promise<unknown>) => void;
	scoringConfig?: import('@blackveil/dns-checks/scoring').ScoringConfig;
	/** Override cache TTL in seconds (default: 300). Clamped to [60, 3600]. */
	cacheTtlSeconds?: number;
	/** Scan-level wall-clock budget in milliseconds. Defaults to SCAN_TIMEOUT_MS. */
	scanTimeoutMs?: number;
	/** Per-check wall-clock budget in milliseconds. Defaults to PER_CHECK_TIMEOUT_MS. */
	perCheckTimeoutMs?: number;
	/** Custom secondary DoH resolver config (bv-dns). Threaded to scanDns but only active when skipSecondaryConfirmation is false. */
	secondaryDoh?: import('../../lib/dns-types').SecondaryDohConfig;
	/** Optional service binding for raw DNS, routing, and vantage-point probes. */
	infraProbe?: { fetch: typeof fetch };
	/**
	 * Optional service binding to bv-certstream-worker. When present, the
	 * Cloudflare-CDN attribution heuristic sources cert issuer from /cert-meta
	 * (activates the v3.3.17 2-of-3 third signal). Without it, the heuristic
	 * degrades to NS+IP-only.
	 */
	certstream?: { fetch: typeof fetch };
	/** Bearer token for the bv-certstream-worker admin auth gate. */
	certstreamAuthToken?: string;
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

	results = await addCloudflareCdnHeuristic(domain, results, {
		certstream: runtimeOptions?.certstream,
		certstreamAuthToken: runtimeOptions?.certstreamAuthToken,
	});

	return addOutboundProviderInference(results, runtimeOptions);
}

/**
 * Heuristic Cloudflare CDN attribution fallback.
 *
 * Header-based CDN detection (in `check-http-security`) cannot identify
 * Cloudflare from inside a Cloudflare Worker — see the rationale in
 * `src/lib/cdn-fallback-detection.ts`. This post-processing pass restores
 * attribution when:
 *
 *   1. No header-based CDN was identified for `http_security`, AND
 *   2. All NS records resolve under `*.ns.cloudflare.com`, AND
 *   3. At least one A record falls in a published Cloudflare edge range.
 *
 * When matched, emits a new info-level finding on the `http_security` check
 * with `metadata: { cdnProvider: 'Cloudflare', confidence: 'heuristic',
 * source: 'ns-and-ip-range' }`. Format-report already iterates findings
 * looking for `metadata.cdnProvider`, so it picks this up automatically.
 *
 * Conservative: any DNS error during the fresh NS/A lookups silently skips
 * the heuristic — never poisons a scan result.
 */
/**
 * Sync budget for the cert-meta lookup inside scan_domain post-processing.
 * Cert issuer is a best-effort upgrade signal — any failure (including
 * timeout) silently falls back to certIssuer:null, which degrades the
 * 2-of-3 rule to the v3.3.15 NS+IP-only gate. crt.sh typically returns in
 * <1s; certspotter fallback inside the worker can take up to 10s, but we
 * cap the caller side here at 5s so the heuristic doesn't drag scan latency.
 */
const CERT_META_LOOKUP_TIMEOUT_MS = 5_000;

async function fetchCertIssuerFromCertstream(
	domain: string,
	certstream: { fetch: typeof fetch },
	authToken?: string,
): Promise<string | null> {
	try {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), CERT_META_LOOKUP_TIMEOUT_MS);
		const response = await certstream.fetch(
			`https://certstream/cert-meta?domain=${encodeURIComponent(domain)}`,
			{
				...(authToken ? { headers: { Authorization: `Bearer ${authToken}` } } : {}),
				signal: controller.signal,
			},
		);
		clearTimeout(timer);
		if (!response.ok) return null;
		const data = (await response.json()) as { issuer?: string | null; error?: string };
		if (data.error || !data.issuer) return null;
		return data.issuer;
	} catch {
		return null;
	}
}

async function addCloudflareCdnHeuristic(
	domain: string,
	results: CheckResult[],
	options?: { certstream?: { fetch: typeof fetch }; certstreamAuthToken?: string },
): Promise<CheckResult[]> {
	const httpResult = results.find((result) => result.category === 'http_security');
	if (!httpResult) return results;

	// Don't compete with a header-based CDN hit — those are stronger signal.
	const alreadyHasCdn = httpResult.findings.some((f) => typeof f.metadata?.cdnProvider === 'string');
	if (alreadyHasCdn) return results;

	let nsHosts: string[];
	let aRecords: string[];
	try {
		[nsHosts, aRecords] = await Promise.all([
			queryDnsRecords(domain, 'NS'),
			queryDnsRecords(domain, 'A'),
		]);
	} catch {
		return results;
	}

	// Strip trailing dots for consistency with the helper's expected input.
	const normalisedNs = nsHosts.map((h) => h.replace(/\.$/, '').toLowerCase());

	// TLS cert issuer — sourced via the bv-certstream-worker /cert-meta
	// endpoint when the service binding is available. Without the binding,
	// or on lookup failure/timeout, fall back to null and let the 2-of-3 rule
	// degrade to the v3.3.15 NS+IP-only gate. This activates v3.3.17's
	// dormant third signal: Cloudflare customers using external DNS providers
	// (eg. shopify.com on Foundation DNS for NS, Cloudflare for CDN) now
	// flip from cdnProvider:null to cdnProvider:'Cloudflare' via IP+cert.
	let certIssuer: string | null = null;
	if (options?.certstream) {
		certIssuer = await fetchCertIssuerFromCertstream(
			domain,
			options.certstream,
			options.certstreamAuthToken,
		);
	}

	const heuristic = detectCloudflareFallback({ nsHosts: normalisedNs, aRecords, certIssuer });
	if (!heuristic) return results;

	// Build a detail string that honestly reflects which signals matched, so
	// users understand whether attribution came from (NS+IP) or (IP+cert) or
	// (NS+cert) — the three valid 2-of-3 combinations.
	const detailParts: string[] = [];
	const nsMatchedCf = normalisedNs.some((h) => h.endsWith('.ns.cloudflare.com'));
	const certMatchedCf = certIssuer !== null && /cloudflare/i.test(certIssuer);
	if (nsMatchedCf) detailParts.push('NS records on *.ns.cloudflare.com');
	if (aRecords.length > 0) detailParts.push("A records in Cloudflare's published edge ranges");
	if (certMatchedCf) detailParts.push(`TLS cert issuer matches Cloudflare (${certIssuer})`);

	const cdnFinding = createFinding(
		'http_security',
		'HTTP origin attributed to Cloudflare CDN (heuristic)',
		'info',
		`Cloudflare CDN inferred from 2-of-3 signals: ${detailParts.join('; ')}. Header-based CDN detection was inconclusive (the scanner runs inside a Cloudflare Worker, which rewrites server: cloudflare on every outbound response).`,
		{
			cdnProvider: 'Cloudflare',
			confidence: 'heuristic',
			source: certMatchedCf ? 'ns-ip-and-cert' : 'ns-and-ip-range',
			...(certIssuer ? { certIssuer } : {}),
		},
	);

	const updated = buildCheckResult('http_security', [...httpResult.findings, cdnFinding]);
	// buildCheckResult creates a fresh CheckResult — preserve scoring fields we care about.
	const merged: CheckResult = {
		...updated,
		score: httpResult.score,
		passed: httpResult.passed,
		checkStatus: httpResult.checkStatus,
		metadata: httpResult.metadata,
	};
	return upsertCheckResult(results, merged);
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
	// If the MX provider detection failed, skip provider-informed DKIM/SPF adjustments
	// to avoid false inferences based on incomplete or degraded provider data.
	const mxResult = results.find((result) => result.category === 'mx');
	const providerDetectionFailed = Boolean(
		(mxResult?.metadata as { providerDetectionFailed?: boolean } | undefined)?.providerDetectionFailed,
	);
	if (providerDetectionFailed) return results;

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
	const emailCategories: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'mta_sts', 'subdomailing'];
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
