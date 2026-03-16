// SPDX-License-Identifier: BUSL-1.1

export interface ProviderSignature {
	name: string;
	domains: string[];
	selectorHints?: string[];
}

export interface ProviderSignaturePayload {
	version?: string;
	inbound?: ProviderSignature[];
	outbound?: ProviderSignature[];
}

export interface ProviderSourceResult {
	version: string;
	source: 'runtime' | 'stale' | 'built-in';
	fetchedAt: string;
	degraded: boolean;
	inbound: ProviderSignature[];
	outbound: ProviderSignature[];
}

export interface LoadProviderSignaturesOptions {
	sourceUrl?: string;
	allowedHosts?: string[];
	expectedSha256?: string;
	timeoutMs?: number;
	retries?: number;
}

export const DEFAULT_TIMEOUT_MS = 2500;
export const DEFAULT_RETRIES = 1;
export const RUNTIME_SIGNATURE_CACHE_TTL_MS = 5 * 60 * 1000;

export const BUILT_IN_SIGNATURES: ProviderSignaturePayload = {
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

export function normalizeSha256(value: string): string {
	return value.trim().toLowerCase().replace(/^sha256:/, '');
}

export function normalizeAllowedHosts(input: string[] | undefined): string[] {
	if (!Array.isArray(input)) return [];
	return input.map((host) => host.trim().toLowerCase()).filter((host) => host.length > 0);
}

export function validateRuntimeSourceUrl(sourceUrl: string, allowedHosts: string[]): URL {
	let url: URL;
	try {
		url = new URL(sourceUrl);
	} catch {
		throw new Error('Invalid provider signature source URL');
	}

	if (url.protocol !== 'https:') {
		throw new Error('Invalid provider signature source URL: HTTPS is required');
	}

	if (allowedHosts.length > 0 && !allowedHosts.includes(url.hostname.toLowerCase())) {
		throw new Error('Invalid provider signature source URL: host is not allowlisted');
	}

	return url;
}

async function sha256Hex(input: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function normalizeDomain(value: string): string {
	return value.trim().toLowerCase().replace(/\.$/, '');
}

function normalizeProviderSignatures(input: ProviderSignature[] | undefined): ProviderSignature[] {
	if (!Array.isArray(input)) return [];

	return input
		.map((provider) => {
			const name = typeof provider?.name === 'string' ? provider.name.trim() : '';
			const domains = Array.isArray(provider?.domains)
				? provider.domains.map((domain) => normalizeDomain(String(domain))).filter((domain) => domain.length > 0)
				: [];
			const selectorHints = Array.isArray(provider?.selectorHints)
				? provider.selectorHints.map((selector) => String(selector).trim().toLowerCase()).filter((selector) => selector.length > 0)
				: [];
			return { name, domains, ...(selectorHints.length > 0 ? { selectorHints } : {}) };
		})
		.filter((provider) => provider.name.length > 0 && provider.domains.length > 0);
}

export function buildResult(
	payload: ProviderSignaturePayload,
	source: ProviderSourceResult['source'],
	degraded: boolean,
): ProviderSourceResult {
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

export function isValidSignaturePayload(payload: unknown): payload is ProviderSignaturePayload {
	if (!payload || typeof payload !== 'object') return false;
	const record = payload as Record<string, unknown>; // typeof payload === 'object' is checked above
	if (record.version !== undefined && typeof record.version !== 'string') return false;
	if (record.inbound !== undefined && !Array.isArray(record.inbound)) return false;
	if (record.outbound !== undefined && !Array.isArray(record.outbound)) return false;
	return true;
}

export async function fetchProviderPayload(
	url: string,
	timeoutMs: number,
	retries: number,
	expectedSha256?: string,
): Promise<ProviderSignaturePayload | null> {
	for (let attempt = 0; attempt <= retries; attempt++) {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), timeoutMs);
		try {
			const response = await fetch(url, {
				method: 'GET',
				headers: { Accept: 'application/json' },
				signal: controller.signal,
				redirect: 'manual',
			});
			if (response.status >= 300 && response.status < 400) {
				return null;
			}
			if (!response.ok) {
				if (attempt < retries && response.status >= 500) continue;
				throw new Error(`Provider signature source returned HTTP ${response.status}`);
			}

			const rawPayload = await response.text();
			if (!expectedSha256) {
				throw new Error('Provider signature source requires a pinned SHA-256 digest');
			}

			const digest = await sha256Hex(rawPayload);
			if (digest !== normalizeSha256(expectedSha256)) {
				throw new Error('Provider signature source failed SHA-256 verification');
			}

			const payload = JSON.parse(rawPayload) as unknown;
			if (!isValidSignaturePayload(payload)) {
				throw new Error('Provider signature source returned an invalid payload shape');
			}

			return payload;
		} catch (error) {
			if (attempt < retries) continue;
			if (error instanceof DOMException && error.name === 'AbortError') {
				throw new Error(`Provider signature source timed out after ${timeoutMs}ms`);
			}
			throw error;
		} finally {
			clearTimeout(timeout);
		}
	}

	throw new Error('Failed to load provider signatures');
}