// SPDX-License-Identifier: BUSL-1.1

/**
 * Zod schemas for the internal Tenant orchestrator endpoints.
 *
 * Source of truth: tenant-Scalable-Architecture-Design.md §2.1, §3, §4.1.
 *
 * These schemas back the routes mounted under `/internal/tenants/*` (see
 * `src/tenants/routes/`). Conventions match the rest of `src/schemas/internal.ts`:
 *
 *   - `.passthrough()` (no property stripping) so future fields don't silently disappear
 *   - All Zod errors translate to "Invalid <field>: <message>" via the route layer,
 *     which lets them through SAFE_ERROR_PREFIXES in `lib/json-rpc.ts`
 *
 * The `TENANT_ID_REGEX` is the same regex applied by the per-tenant D1 adapter
 * (with hyphens explicitly allowed because sub-tenant IDs in the design doc
 * use hyphens, e.g. `tenant-1`). When the resolver constructs an actual
 * D1 binding name the hyphen is converted to underscore — see
 * `src/tenants/tenant-resolver.ts`.
 */

import { z } from 'zod';

/** Maximum number of domains accepted in a single portfolio upload or scan request. */
export const MAX_PORTFOLIO_DOMAINS = 10_000;

/**
 * Same shape as the per-tenant D1 prefix-stamping rule plus hyphens for
 * sub-tenant IDs. Lowercased to match Cloudflare conventions and to keep the
 * derived binding name deterministic.
 */
export const TENANT_ID_REGEX = /^[a-z][a-z0-9_-]{0,63}$/;

const DomainsArraySchema = z
	.array(z.string().min(1).max(253))
	.min(1)
	.max(MAX_PORTFOLIO_DOMAINS);

/** POST /internal/tenants/portfolio request body. */
export const PortfolioRequestSchema = z
	.object({
		domains: DomainsArraySchema,
	})
	.passthrough();

export type PortfolioRequest = z.infer<typeof PortfolioRequestSchema>;

/**
 * POST /internal/tenants/scan request body.
 *
 * All four fields are optional. Resolution priority inside the handler:
 *   1. `domain_ids` → look up rows from per-tenant `domains` table
 *   2. `domains` → use the explicit list (validated via `validateDomain`)
 *   3. neither → fan out across the full portfolio (everything in `domains`)
 */
export const ScanRequestSchema = z
	.object({
		cycle_id: z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/).optional(),
		domain_ids: z.array(z.string().min(1).max(253)).max(MAX_PORTFOLIO_DOMAINS).optional(),
		domains: z.array(z.string().min(1).max(253)).max(MAX_PORTFOLIO_DOMAINS).optional(),
		concurrency: z.number().int().min(1).max(50).optional(),
		/**
		 * If true, bypasses the Phase 6 fingerprint pre-flight and forces a cold scan.
		 */
		force_refresh: z.boolean().optional(),
		/**
		 * Phase 2 dispatch mode. Defaults to `sync` (the original inline scan path).
		 * `queue` enqueues one BV_SCANNER_QUEUE message per target domain and
		 * returns 202 immediately — the caller polls /report/:cycle_id later.
		 */
		mode: z.enum(['sync', 'queue']).optional(),
	})
	.passthrough();

export type ScanRequest = z.infer<typeof ScanRequestSchema>;

/** GET /internal/tenants/report/:cycle_id route param shape. */
export const ReportParamsSchema = z.object({
	cycle_id: z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/),
});

export type ReportParams = z.infer<typeof ReportParamsSchema>;

/** POST /internal/tenants/discover request body. */
export const DiscoveryRequestSchema = z
	.object({
		seed_domains: z.array(z.string().min(1).max(253)).min(1).max(500).optional(),
		signals: z
			.array(
				z
					.string()
					.transform((v) => v.toLowerCase().trim())
					.pipe(z.enum(['san', 'ns', 'dmarc_rua', 'dkim_key_reuse'])),
			)
			.min(1)
			.max(4)
			.optional(),
		min_confidence: z.number().min(0).max(1).optional(),
		/**
		 * If true, automatically adds discovered candidates with confidence >= 0.85
		 * to the tenant's domains table.
		 */
		auto_import: z.boolean().optional(),
	})
	.passthrough();

export type DiscoveryRequest = z.infer<typeof DiscoveryRequestSchema>;

/**
 * Scanner-queue message body (Phase 2).
 *
 * Producer: `POST /internal/tenants/scan` when `mode === 'queue'` — drops one
 * message per target domain onto `BV_SCANNER_QUEUE`.
 *
 * Consumer: `handleScanQueue` in `src/tenants/queue-consumer.ts` — validates each
 * message via this schema before invoking `handleToolsCall('scan_domain', …)`
 * and persisting the result to the per-tenant D1.
 *
 * Design notes:
 *   - Only JSON-serializable fields. Live runtime objects (analytics client,
 *     DO refs, `waitUntil`) are reconstructed by the consumer from `env`.
 *   - `runtime_options` is a deliberately narrow allow-list; new flags must be
 *     added here so downstream consumers can't have blind expectations.
 */
export const ScanQueueRuntimeOptionsSchema = z
	.object({
		cacheTtlSeconds: z.number().int().min(0).max(86_400).optional(),
	})
	.strict();

export type ScanQueueRuntimeOptions = z.infer<typeof ScanQueueRuntimeOptionsSchema>;

export const ScanQueueMessageSchema = z
	.object({
		cycle_id: z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/),
		sub_tenant_id: z.string().regex(TENANT_ID_REGEX),
		domain: z.string().min(1).max(253),
		force_refresh: z.boolean().optional(),
		runtime_options: ScanQueueRuntimeOptionsSchema.optional(),
	})
	.strict();

export type ScanQueueMessage = z.infer<typeof ScanQueueMessageSchema>;
