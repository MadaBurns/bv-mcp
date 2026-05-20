// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared constructor for the Tier 0/1/2 lookup closures used by
 * `discoverBrandDomains` and `brand_audit_single`.
 *
 * Three entry points need these closures: the public `/mcp` request path
 * (`src/index.ts`), the internal `/internal/tools/{call,batch}` paths
 * (`src/internal.ts`), and the brand-audit queue consumer (`src/index.ts`'s
 * queue handler). All three rely on the same private service bindings:
 *
 *   - `BV_ENTERPRISE`       — Tier 0 (tenant-declared portfolio, HTTP binding)
 *   - `BV_INFRA_GRAPH`      — Tier 1 (infrastructure-graph signals, HTTP binding)
 *   - `BV_INTEL_GATEWAY`    — Tier 2 (declared-evidence, Workers RPC binding)
 *   - `BV_WEB_INTERNAL_KEY` — shared bearer for Tier 0/1 producer auth
 *
 * Each closure is built only when its binding (+ `BV_WEB_INTERNAL_KEY` for
 * Tier 0/1) is provisioned. BSL self-hosts that lack any of these get
 * `undefined` for the corresponding closure — the discoverer then falls back
 * to classic-mode behaviour without ever calling the proprietary surfaces.
 *
 * Tier 2 is RPC-typed; auth is enforced at the binding level (no Authorization
 * header to plumb). See `src/lib/brand-tier2-evidence.ts` for the contract.
 *
 * The closures dynamically import their tier modules so BSL self-hosts that
 * never call into tiered mode don't bundle the closure bodies into the
 * request hot path.
 */

import type { Tier0Result } from './brand-tier0-enterprise';
import type { Tier1Result } from './brand-tier1-graph';
import type { Tier2Result, IntelGatewayBinding } from './brand-tier2-evidence';

/**
 * Minimal env shape consumed by the closure factory. Each entry point's
 * `Env` type narrows to this via duck-typing — neither `BvMcpEnv` nor
 * `InternalEnv` need to import or extend a shared interface, which keeps the
 * BSL boundary clean (the bindings remain operator-deploy-only).
 */
export interface BrandTierLookupEnv {
	BV_ENTERPRISE?: Fetcher;
	BV_INFRA_GRAPH?: Fetcher;
	BV_INTEL_GATEWAY?: IntelGatewayBinding;
	BV_WEB_INTERNAL_KEY?: string;
}

export interface BrandTierLookups {
	tier0Lookup?: (domain: string) => Promise<Tier0Result>;
	tier1Lookup?: (domain: string) => Promise<Tier1Result>;
	tier2Lookup?: (domain: string) => Promise<Tier2Result>;
}

/**
 * Build Tier 0/1/2 lookup closures from the available env bindings.
 *
 * Pure construction — no I/O, no logging, no throws. Each closure returns
 * `undefined` when its prerequisites aren't met, so callers can spread the
 * result into a wider options bag without conditional branches per tier.
 */
export function buildBrandTierLookups(env: BrandTierLookupEnv): BrandTierLookups {
	const enterpriseBinding = env.BV_ENTERPRISE;
	const infraGraphBinding = env.BV_INFRA_GRAPH;
	const intelGatewayBinding = env.BV_INTEL_GATEWAY;
	const internalKey = env.BV_WEB_INTERNAL_KEY;
	return {
		...(enterpriseBinding && internalKey
			? {
					tier0Lookup: async (domain: string) => {
						const { tier0EnterpriseLookup } = await import('./brand-tier0-enterprise');
						return tier0EnterpriseLookup(domain, enterpriseBinding, { BV_WEB_INTERNAL_KEY: internalKey });
					},
				}
			: {}),
		...(infraGraphBinding && internalKey
			? {
					tier1Lookup: async (domain: string) => {
						const { tier1GraphLookup } = await import('./brand-tier1-graph');
						return tier1GraphLookup(domain, infraGraphBinding, { BV_WEB_INTERNAL_KEY: internalKey });
					},
				}
			: {}),
		...(intelGatewayBinding
			? {
					tier2Lookup: async (domain: string) => {
						const { tier2EvidenceLookup } = await import('./brand-tier2-evidence');
						return tier2EvidenceLookup(domain, intelGatewayBinding);
					},
				}
			: {}),
	};
}
