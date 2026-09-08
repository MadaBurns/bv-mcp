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
 * If `cf-connecting-ip` is absent, the resolvers return `'unknown'`. Callers
 * that gate on IP must treat `'unknown'` as "no allowlist match" (i.e. fail
 * closed).
 *
 * Absence is NOT rare and is NOT benign — it is a zone-config regression signal
 * (#896). A Workers Custom Domain bound directly to the Worker still delivers
 * `request.cf`, but a zone-level Managed Transform ("Remove visitor IP headers")
 * or transform rule strips the header before the Worker sees it, and nothing
 * errors: every public request silently collapses onto one `'unknown'` bucket
 * for rate limits, quotas and the owner-tier gate. Measured live on 2026-09-09:
 * ~80–94% of public-door traffic (168h / 24h) carried no header, and that stays
 * true until the zone is fixed (an operator dashboard action, not code). The
 * legitimate absent cases — a service binding that built a fresh Request without
 * copying CF headers, or an off-Cloudflare test harness — are the minority.
 *
 * Detection lives in `src/lib/client-ip-audit.ts` (SSOT for the SQL and
 * thresholds): `npm run audit:client-ip-headers` on demand, and the 15-min cron
 * lane `handleClientIpHeaderAudit` (`src/scheduled.ts`) pages
 * `client_ip_header_missing` when > 5% of >= 20 public-door rows in the last
 * 24h lack the header (24h, not 1h: at ~2.3 public rows/hour a 1h window never
 * reaches the sample floor and the lane would sit at `unknown` forever). The
 * daily digest carries the same verdict as a positive control.
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
