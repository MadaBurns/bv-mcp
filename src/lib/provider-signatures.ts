import {
	BUILT_IN_SIGNATURES,
	buildResult,
	DEFAULT_RETRIES,
	DEFAULT_TIMEOUT_MS,
	fetchProviderPayload,
	type LoadProviderSignaturesOptions,
	normalizeAllowedHosts,
	type ProviderSignature,
	type ProviderSourceResult,
	RUNTIME_SIGNATURE_CACHE_TTL_MS,
	validateRuntimeSourceUrl,
} from './provider-signature-source';

interface ProviderMatchEvidence {
	provider: string;
	matches: string[];
}

let lastKnownGood: ProviderSourceResult | null = null;
let runtimeSignatureCache: {
	sourceUrl: string;
	result: ProviderSourceResult;
	expiresAt: number;
} | null = null;

function normalizeDomain(value: string): string {
	return value.trim().toLowerCase().replace(/\.$/, '');
}

function boundarySuffixMatch(hostname: string, suffix: string): boolean {
	const host = normalizeDomain(hostname);
	const normalizedSuffix = normalizeDomain(suffix);
	if (!host || !normalizedSuffix) return false;
	return host === normalizedSuffix || host.endsWith(`.${normalizedSuffix}`);
}


export async function loadProviderSignatures(options?: LoadProviderSignaturesOptions): Promise<ProviderSourceResult> {
	const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const retries = options?.retries ?? DEFAULT_RETRIES;
	const sourceUrl = options?.sourceUrl?.trim();
	const allowedHosts = normalizeAllowedHosts(options?.allowedHosts);
	const expectedSha256 = options?.expectedSha256?.trim();

	if (!sourceUrl) {
		return buildResult(BUILT_IN_SIGNATURES, 'built-in', false);
	}

	const now = Date.now();
	if (runtimeSignatureCache && runtimeSignatureCache.sourceUrl === sourceUrl && runtimeSignatureCache.expiresAt > now) {
		return runtimeSignatureCache.result;
	}

	try {
		const validatedUrl = validateRuntimeSourceUrl(sourceUrl, allowedHosts);
		const payload = await fetchProviderPayload(validatedUrl.toString(), timeoutMs, retries, expectedSha256);
		const result = buildResult(payload, 'runtime', false);
		lastKnownGood = result;
		runtimeSignatureCache = {
			sourceUrl,
			result,
			expiresAt: now + RUNTIME_SIGNATURE_CACHE_TTL_MS,
		};
		return result;
	} catch {
		if (lastKnownGood) {
			const staleResult = { ...lastKnownGood, source: 'stale' as const, degraded: true, fetchedAt: new Date().toISOString() };
			runtimeSignatureCache = {
				sourceUrl,
				result: staleResult,
				expiresAt: now + RUNTIME_SIGNATURE_CACHE_TTL_MS,
			};
			return staleResult;
		}
		const fallbackResult = buildResult(BUILT_IN_SIGNATURES, 'built-in', true);
		runtimeSignatureCache = {
			sourceUrl,
			result: fallbackResult,
			expiresAt: now + RUNTIME_SIGNATURE_CACHE_TTL_MS,
		};
		return fallbackResult;
	}
}

/**
 * Test helper to reset provider signature loader state between cases.
 * @internal Exported for test use only.
 */
export function resetProviderSignatureState(): void {
	lastKnownGood = null;
	runtimeSignatureCache = null;
}

export function detectProviderMatches(hosts: string[], signatures: ProviderSignature[]): ProviderMatchEvidence[] {
	const normalizedHosts = hosts.map((host) => normalizeDomain(host)).filter((host) => host.length > 0);
	const matches: ProviderMatchEvidence[] = [];

	for (const provider of signatures) {
		const providerMatches = new Set<string>();
		for (const host of normalizedHosts) {
			if (provider.domains.some((domain) => boundarySuffixMatch(host, domain))) {
				providerMatches.add(host);
			}
		}
		if (providerMatches.size > 0) {
			matches.push({ provider: provider.name, matches: Array.from(providerMatches) });
		}
	}

	return matches;
}

export function detectProviderMatchesBySelectors(selectors: string[], signatures: ProviderSignature[]): ProviderMatchEvidence[] {
	const normalizedSelectors = selectors.map((selector) => selector.trim().toLowerCase()).filter((selector) => selector.length > 0);
	const matches: ProviderMatchEvidence[] = [];

	for (const provider of signatures) {
		const hints = provider.selectorHints ?? [];
		if (hints.length === 0) continue;

		const providerMatches = normalizedSelectors.filter((selector) => hints.includes(selector));
		if (providerMatches.length > 0) {
			matches.push({ provider: provider.name, matches: Array.from(new Set(providerMatches)) });
		}
	}

	return matches;
}
