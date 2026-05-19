// SPDX-License-Identifier: BUSL-1.1

/**
 * Tier 0 brand-discovery source: tenant-declared portfolio lookup.
 *
 * Calls the `bv-enterprise` Worker via the `BV_ENTERPRISE` Cloudflare service
 * binding to ask "is this seed in any tenant's declared portfolio, and is it
 * opted out?" Tenant-declared ownership is gold-standard ground truth —
 * confidence 1.0, Tier 0.
 *
 * Source of truth:
 *   docs/superpowers/plans/2026-05-20-brand-discovery-cross-worker-contract.md §1.3
 *   docs/superpowers/plans/2026-05-20-brand-discovery-first-principles-tdd.md Task 2
 *
 * Design constraints (do not relax without ADR):
 *
 *   - **Fail-soft.** Every error path returns
 *     `{ observations: [], status: 'degraded' }`. Discovery is best-effort; a
 *     flaky Tier 0 source must never throw to the discovery pipeline.
 *   - **No PII / domain values in logs.** This module emits no logs. The
 *     orchestrator emits structured telemetry on the way out.
 *   - **`isOptedOut` is required.** Schema-level boundary: if the producer
 *     omits the flag, Zod fails closed and we return `degraded` (never
 *     default-false). See `cross-worker-tenant-domains.ts`.
 *   - **Shared internal-key bearer auth.** Header is
 *     `Authorization: Bearer ${env.BV_WEB_INTERNAL_KEY}`. We never compare the
 *     key here; the producer side does the constant-time XOR (per
 *     `bv-intel-gateway/CLAUDE.md` auth gotchas, mirrored across all three
 *     cross-Worker surfaces).
 *
 * This module is intentionally pure: imports only Zod and the shared schema.
 * It does NOT depend on `src/handlers/`, `src/tools/`, `brand-evidence.ts`, or
 * `brand-classification.ts`. The wiring into `discoverBrandDomains()` happens
 * separately in Task 7.
 */

import {
	TenantDomainsLookupResponseSchema,
	type TenantDomainsLookupResponse,
} from '../schemas/cross-worker-tenant-domains';

/**
 * Status of the Tier 0 lookup attempt, mirroring the per-tier status convention
 * across the discovery pipeline.
 *
 *   - `ok`       — call completed and the response parsed cleanly.
 *   - `degraded` — call failed, response was non-2xx, response failed Zod
 *                  validation, or required env was missing. Caller should
 *                  proceed without Tier 0 data; do NOT abort discovery.
 *   - `partial`  — reserved for multi-record fan-out modes; not used by the
 *                  single-seed lookup, kept on the union for future symmetry.
 *   - `timeout`  — reserved (no explicit timeout is wired here; the binding
 *                  inherits the caller's request budget).
 *   - `skipped`  — reserved (caller decided to skip Tier 0 entirely).
 */
export type Tier0LookupStatus = 'ok' | 'degraded' | 'partial' | 'timeout' | 'skipped';

/**
 * Observation surfaced when a seed is found in a tenant's declared portfolio.
 *
 * Shape matches the Tier-classifier contract: every observation carries
 * `source`, `tier`, and `confidence` so the classifier can dedupe across
 * sources without re-interpreting per-source quirks.
 */
export interface Tier0Observation {
	candidate: string;
	source: 'tenant_domains';
	tier: 0;
	confidence: 1.0;
	tenantId?: string;
	registeredAt?: number;
}

export interface Tier0Result {
	observations: Tier0Observation[];
	status: Tier0LookupStatus;
	optedOut: boolean;
}

export interface Tier0EnterpriseEnv {
	BV_WEB_INTERNAL_KEY?: string;
}

/**
 * Internal hostname used for service-binding `fetch()` calls. Cloudflare
 * service bindings ignore the hostname (routing is by binding identity), but a
 * syntactically-valid absolute URL is still required by the `Request` constructor.
 * Using a non-resolving `.invalid` TLD documents intent and prevents any chance
 * of accidental egress if the binding were ever replaced with a real Fetcher.
 */
const BV_ENTERPRISE_HOST = 'https://bv-enterprise.internal.invalid';

const DEGRADED_EMPTY: Tier0Result = Object.freeze({
	observations: [],
	status: 'degraded',
	optedOut: false,
});

/**
 * Tier 0 lookup against the bv-enterprise registry.
 *
 * Returns a Tier 0 observation when the seed is `isRegistered && !isOptedOut`.
 * Returns no observations (but `optedOut: true`) when the seed is opted out —
 * callers downstream of Tier 0 enforcement should not surface this domain at
 * any tier, but the `optedOut` flag lets the orchestrator emit the opt-out
 * telemetry counter.
 *
 * Never throws.
 */
export async function tier0EnterpriseLookup(
	domain: string,
	binding: Fetcher,
	env: Tier0EnterpriseEnv,
): Promise<Tier0Result> {
	if (!env.BV_WEB_INTERNAL_KEY) {
		return { ...DEGRADED_EMPTY };
	}

	let parsed: TenantDomainsLookupResponse;
	try {
		const url = `${BV_ENTERPRISE_HOST}/internal/tenant-domains/${encodeURIComponent(domain)}`;
		const response = await binding.fetch(url, {
			headers: {
				'Authorization': `Bearer ${env.BV_WEB_INTERNAL_KEY}`,
			},
		});

		if (response.status < 200 || response.status >= 300) {
			return { ...DEGRADED_EMPTY };
		}

		const body: unknown = await response.json();
		const result = TenantDomainsLookupResponseSchema.safeParse(body);
		if (!result.success) {
			return { ...DEGRADED_EMPTY };
		}
		parsed = result.data;
	} catch {
		// Binding threw, JSON parse failed, network error, etc.
		// Fail-soft: discovery must never abort on a Tier 0 hiccup.
		return { ...DEGRADED_EMPTY };
	}

	// Opt-out: privacy boundary. Surface the flag, drop any observations.
	if (parsed.isOptedOut) {
		return { observations: [], status: 'ok', optedOut: true };
	}

	// Not registered: clean negative.
	if (!parsed.isRegistered) {
		return { observations: [], status: 'ok', optedOut: false };
	}

	// Registered and not opted out: Tier 0 observation.
	const observation: Tier0Observation = {
		candidate: domain,
		source: 'tenant_domains',
		tier: 0,
		confidence: 1.0,
		...(parsed.tenantId !== undefined ? { tenantId: parsed.tenantId } : {}),
		...(parsed.registeredAt !== undefined ? { registeredAt: parsed.registeredAt } : {}),
	};

	return {
		observations: [observation],
		status: 'ok',
		optedOut: false,
	};
}
