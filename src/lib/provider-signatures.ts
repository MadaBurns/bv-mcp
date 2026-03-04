interface ProviderSignature {
	name: string;
	domains: string[];
	selectorHints?: string[];
}

interface ProviderSignaturePayload {
	version?: string;
	inbound?: ProviderSignature[];
	outbound?: ProviderSignature[];
}

interface ProviderSourceResult {
	version: string;
	source: 'runtime' | 'stale' | 'built-in';
	fetchedAt: string;
	degraded: boolean;
	inbound: ProviderSignature[];
	outbound: ProviderSignature[];
}

interface LoadProviderSignaturesOptions {
	sourceUrl?: string;
	timeoutMs?: number;
	retries?: number;
}

interface ProviderMatchEvidence {
	provider: string;
	matches: string[];
}

const DEFAULT_TIMEOUT_MS = 2500;
const DEFAULT_RETRIES = 1;

const BUILT_IN_SIGNATURES: ProviderSignaturePayload = {
	version: 'built-in-2026-03-04',
	inbound: [
		{ name: 'Google Workspace', domains: ['google.com', 'googlemail.com'], selectorHints: ['google'] },
		{ name: 'Microsoft 365', domains: ['outlook.com', 'protection.outlook.com'], selectorHints: ['selector1', 'selector2'] },
		{ name: 'Proofpoint', domains: ['pphosted.com'] },
		{ name: 'Mimecast', domains: ['mimecast.com'], selectorHints: ['mimecast'] },
		{ name: 'Mailgun', domains: ['mailgun.org'] },
		{ name: 'SendGrid', domains: ['sendgrid.net'] },
		{ name: 'Amazon SES', domains: ['amazonses.com'] },
	],
	outbound: [],
};

let lastKnownGood: ProviderSourceResult | null = null;

function normalizeDomain(value: string): string {
	return value.trim().toLowerCase().replace(/\.$/, '');
}

function boundarySuffixMatch(hostname: string, suffix: string): boolean {
	const host = normalizeDomain(hostname);
	const normalizedSuffix = normalizeDomain(suffix);
	if (!host || !normalizedSuffix) return false;
	return host === normalizedSuffix || host.endsWith(`.${normalizedSuffix}`);
}

function normalizeProviderSignatures(input: ProviderSignature[] | undefined): ProviderSignature[] {
	if (!Array.isArray(input)) return [];

	return input
		.map((provider) => {
			const name = typeof provider?.name === 'string' ? provider.name.trim() : '';
			const domains = Array.isArray(provider?.domains)
				? provider.domains.map((d) => normalizeDomain(String(d))).filter((d) => d.length > 0)
				: [];
			const selectorHints = Array.isArray(provider?.selectorHints)
				? provider.selectorHints.map((s) => String(s).trim().toLowerCase()).filter((s) => s.length > 0)
				: [];
			return { name, domains, ...(selectorHints.length > 0 ? { selectorHints } : {}) };
		})
		.filter((provider) => provider.name.length > 0 && provider.domains.length > 0);
}

function buildResult(payload: ProviderSignaturePayload, source: ProviderSourceResult['source'], degraded: boolean): ProviderSourceResult {
	const inbound = normalizeProviderSignatures(payload.inbound);
	const outbound = normalizeProviderSignatures(payload.outbound);

	return {
		version: payload.version?.trim() || BUILT_IN_SIGNATURES.version || 'unknown',
		source,
		fetchedAt: new Date().toISOString(),
		degraded,
		inbound,
		outbound,
	};
}

function isValidSignaturePayload(payload: unknown): payload is ProviderSignaturePayload {
	if (!payload || typeof payload !== 'object') return false;
	const record = payload as Record<string, unknown>;
	if (record.version !== undefined && typeof record.version !== 'string') return false;
	if (record.inbound !== undefined && !Array.isArray(record.inbound)) return false;
	if (record.outbound !== undefined && !Array.isArray(record.outbound)) return false;
	return true;
}

async function fetchProviderPayload(url: string, timeoutMs: number, retries: number): Promise<ProviderSignaturePayload> {
	for (let attempt = 0; attempt <= retries; attempt++) {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), timeoutMs);
		try {
			const response = await fetch(url, {
				method: 'GET',
				headers: { Accept: 'application/json' },
				signal: controller.signal,
			});
			if (!response.ok) {
				if (attempt < retries && response.status >= 500) continue;
				throw new Error(`Provider signature source returned HTTP ${response.status}`);
			}
			const payload = await response.json();
			if (!isValidSignaturePayload(payload)) {
				throw new Error('Provider signature source returned an invalid payload shape');
			}
			return payload;
		} catch (err) {
			if (attempt < retries) continue;
			if (err instanceof DOMException && err.name === 'AbortError') {
				throw new Error(`Provider signature source timed out after ${timeoutMs}ms`);
			}
			throw err;
		} finally {
			clearTimeout(timeout);
		}
	}

	throw new Error('Failed to load provider signatures');
}

export async function loadProviderSignatures(options?: LoadProviderSignaturesOptions): Promise<ProviderSourceResult> {
	const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const retries = options?.retries ?? DEFAULT_RETRIES;
	const sourceUrl = options?.sourceUrl?.trim();

	if (!sourceUrl) {
		return buildResult(BUILT_IN_SIGNATURES, 'built-in', false);
	}

	try {
		const payload = await fetchProviderPayload(sourceUrl, timeoutMs, retries);
		const result = buildResult(payload, 'runtime', false);
		lastKnownGood = result;
		return result;
	} catch {
		if (lastKnownGood) {
			return { ...lastKnownGood, source: 'stale', degraded: true, fetchedAt: new Date().toISOString() };
		}
		return buildResult(BUILT_IN_SIGNATURES, 'built-in', true);
	}
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
