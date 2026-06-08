// SPDX-License-Identifier: BUSL-1.1

/**
 * Client-IP resolution helpers.
 *
 * Trust model (per CLAUDE.md): only `cf-connecting-ip` is trustworthy for
 * security decisions (owner-tier gating, rate limits, per-IP quotas, audit
 * `ipHash`). Cloudflare sets this header on every request that reaches a
 * Worker route and overrides any client-provided value. Headers like
 * `x-forwarded-for`, `x-real-ip`, and `true-client-ip` are attacker-controlled
 * — they MUST NOT be used as a trust source.
 *
 * If `cf-connecting-ip` is absent (rare: workers.dev direct hits without CF in
 * front, or a service binding that constructed a fresh Request without copying
 * CF headers), the resolvers return `'unknown'`. Callers that gate on IP must
 * treat `'unknown'` as "no allowlist match" (i.e. fail closed).
 */

function firstHeaderValue(value: string | null | undefined): string | undefined {
	const first = value?.split(',')[0]?.trim();
	if (!first || first.toLowerCase() === 'unknown') return undefined;
	return first;
}

export function resolveClientIpFromHeaders(headersLc: Record<string, string>): string {
	return firstHeaderValue(headersLc['cf-connecting-ip']) ?? 'unknown';
}

export function resolveClientIpFromRequestHeaders(headers: Headers): string {
	return firstHeaderValue(headers.get('cf-connecting-ip')) ?? 'unknown';
}

export function resolveClientIpFromHeaderGetter(header: (name: string) => string | undefined): string {
	return firstHeaderValue(header('cf-connecting-ip')) ?? 'unknown';
}
