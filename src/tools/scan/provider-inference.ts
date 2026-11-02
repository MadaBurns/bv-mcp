// SPDX-License-Identifier: BUSL-1.1

/** scan_domain post-processing: infer the outbound email provider from SPF includes and DKIM selectors. */

import { type CheckResult, buildCheckResult, createFinding } from '../../lib/scoring';
import { detectProviderMatches, detectProviderMatchesBySelectors, loadProviderSignatures } from '../../lib/provider-signatures';
import { upsertCheckResult, rebuildPreservingSignals } from './result-rebuild';

import type { ScanRuntimeOptions } from './post-processing';

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

export async function addOutboundProviderInference(results: CheckResult[], runtimeOptions?: ScanRuntimeOptions): Promise<CheckResult[]> {
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

	// `buildCheckResult('spf', [])` is a synthetic EMPTY baseline — no probe ran, so
	// there are no signals to carry and `rebuildPreservingSignals` would have nothing
	// to preserve. It is also unreachable as OUTPUT: `upsertCheckResult` only replaces
	// an existing `spf` entry, so with no `spfResult` the rebuild is discarded. Kept
	// as-is rather than deleted, but it is the one deliberate bare call in this file.
	// bv-signals-checked: synthetic empty baseline, no source result to carry from
	const spfBaseline = spfResult ?? buildCheckResult('spf', []);
	const updatedSpf = rebuildPreservingSignals(spfBaseline, [
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
