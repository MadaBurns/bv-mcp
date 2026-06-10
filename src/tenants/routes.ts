// SPDX-License-Identifier: BUSL-1.1

/**
 * Tenant orchestrator routes.
 *
 * Mounted by `src/internal.ts` under `/internal/tenants/*`. All three routes share:
 *   - the existing `/internal` network guard (public client-IP header absence)
 *   - the existing `internalLenientAuthGate` (REQUIRE_INTERNAL_AUTH=true → bearer)
 *   - the `X-Tenant` header → `resolveTenant()` lookup against the shared
 *     registry D1 (`TENANT_REGISTRY_DB` binding)
 *
 * The orchestrator accepts portfolio uploads, dispatches chunked batch scans,
 * and serves cycle reports. Heavy lifting (DoH, scoring) stays in
 * `handleToolsCall`.
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { ZodError } from 'zod';
import { handleToolsCall } from '../handlers/tools';
import { createAnalyticsClient, hashForAnalytics, hashIpForAnalytics } from '../lib/analytics';
import { resolveClientIpFromHeaderGetter } from '../lib/client-ip';
import { parseScoringConfigCached } from '../lib/scoring-config';
import { MAX_INTERNAL_BATCH_BODY_BYTES, MAX_TENANT_PORTFOLIO_BODY_BYTES, parseCacheTtl, parsePerCheckTimeout, parseScanTimeout } from '../lib/config';
import { validateDomain, sanitizeDomain } from '../lib/sanitize';
import {
	PortfolioRequestSchema,
	ScanRequestSchema,
	ReportParamsSchema,
	DiscoveryRequestSchema,
	TENANT_ID_REGEX,
	type ScanQueueMessage,
} from '../schemas/tenant-internal';
import { discoverBrandDomains } from '../tools/discover-brand-domains';
import { computeFingerprint, fingerprintsDiffer } from './dns-fingerprint';
import { resolveTenant, type ResolverEnv } from './tenant-resolver';
import { recordAuditEvent } from './audit';
import { checkAndRecord, PER_TENANT_QUOTAS, type RateLimitBucket } from './per-tenant-rate-limit';
import * as registrySchema from './db/schema/registry';
import type { AuditEvent } from '../schemas/audit';
import type { CheckResult } from '../lib/scoring';

/**
 * Minimal `Queue<T>` shape — Cloudflare's runtime types pin this to the
 * declared message body type. We type it locally so the producer compiles
 * without dragging in the full ambient definitions.
 */
type ScanQueueProducer = {
	send(message: ScanQueueMessage, options?: { contentType?: 'json' }): Promise<void>;
};

type TenantEnv = ResolverEnv & {
	SCAN_CACHE?: KVNamespace;
	/** Per-tenant rate limiter state — same KV as the public per-IP limiter. */
	RATE_LIMIT?: KVNamespace;
	PROFILE_ACCUMULATOR?: DurableObjectNamespace;
	MCP_ANALYTICS?: AnalyticsEngineDataset;
	PROVIDER_SIGNATURES_URL?: string;
	PROVIDER_SIGNATURES_ALLOWED_HOSTS?: string;
	PROVIDER_SIGNATURES_SHA256?: string;
	SCORING_CONFIG?: string;
	CACHE_TTL_SECONDS?: string;
	SCAN_TIMEOUT_MS?: string;
	PER_CHECK_TIMEOUT_MS?: string;
	BV_DOH_ENDPOINT?: string;
	BV_DOH_TOKEN?: string;
	BV_SCANNER_QUEUE?: ScanQueueProducer;
	/**
	 * FINDING #5 (BOLA): OPT-IN per-credential tenant-scope map. JSON object
	 * mapping `hex(SHA-256(bearer))` → array of sub-tenant ids that credential may
	 * target. When set, a bearer that appears as a key in the map is restricted to
	 * its listed tenants (403 otherwise). A bearer ABSENT from the map is
	 * unconstrained — this preserves the live single shared-key bv-web flow, which
	 * is expected NOT to appear in the map. Unset entirely → scoping disabled.
	 */
	TENANT_KEY_SCOPE?: string;
};

export const tenantRoutes = new Hono<{ Bindings: TenantEnv }>();

const DEFAULT_SCAN_CONCURRENCY = 10;
const PORTFOLIO_UPSERT_SQL =
	'INSERT INTO domains (domain, source, added_at) VALUES (?, ?, ?) ' +
	'ON CONFLICT(domain) DO UPDATE SET source = excluded.source';
const PORTFOLIO_PROBE_SQL = 'SELECT domain FROM domains WHERE domain = ? LIMIT 1';
const SCANS_INSERT_SQL =
	'INSERT INTO scans (id, domain, scan_at, score, grade, maturity_stage, finding_count, result_json, cycle_id) ' +
	'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
const FINDINGS_INSERT_SQL =
	'INSERT INTO findings (id, scan_id, domain, category, severity, title, detail, metadata) ' +
	'VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
const REPORT_SCANS_SQL = 'SELECT score, grade FROM scans WHERE cycle_id = ?';
const REPORT_FINDINGS_SQL =
	'SELECT category, severity, COUNT(*) as count FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE cycle_id = ?) GROUP BY category, severity';

/** Translate Zod errors to "Invalid <field>: <msg>" — matches SAFE_ERROR_PREFIXES. */
function zodToError(err: ZodError): string {
	const issue = err.issues[0];
	return `Invalid ${issue.path.join('.') || 'request'}: ${issue.message}`;
}

/** Pull X-Tenant from the Hono request and validate against the regex. */
function extractTenantHeader(c: { req: { header(name: string): string | undefined } }): string | { error: string } {
	const raw = c.req.header('x-tenant');
	if (!raw) return { error: 'Missing required header: X-Tenant' };
	if (!TENANT_ID_REGEX.test(raw)) return { error: 'Invalid tenant identifier' };
	return raw;
}

/**
 * TRUST INVARIANT (FINDING #5 / BOLA):
 *
 * `/internal/tenants/*` is authenticated by the single shared
 * `BV_WEB_INTERNAL_KEY`; the `X-Tenant` header selects the tenant. By itself
 * that lets ANY key holder target ANY active tenant, so the trust boundary is
 * "bv-web is the only caller and it forwards the correct tenant". `assertTenantScope`
 * lets an operator tighten that boundary WITHOUT breaking the live single-key
 * flow:
 *
 *   1. `X-Tenant-Scope` request header — a comma/space-separated allowlist of
 *      sub-tenant ids bv-web vouches the caller may touch (forwarded per request).
 *   2. `TENANT_KEY_SCOPE` env — a JSON map of `hex(SHA-256(bearer))` → allowed
 *      sub-tenant ids, binding a specific credential to specific tenants.
 *
 * Enforcement is OPT-IN and additive:
 *   - No `X-Tenant-Scope` header AND no `TENANT_KEY_SCOPE` entry for this bearer
 *     → no constraint (today's behaviour, prod single-key flow unchanged).
 *   - A signal present → the resolved tenant MUST be in the union of allowed ids,
 *     else the caller is denied (403). Enabling this requires bv-web to send the
 *     scope signal; per-tenant keys are NOT mandatory.
 */
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

/** hex(SHA-256(value)) — same credential-hash convention as `keyHash` elsewhere. */
async function sha256Hex(value: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

/** Parse an `X-Tenant-Scope` header into a set of allowed sub-tenant ids. */
function parseScopeHeader(raw: string | undefined): Set<string> | null {
	if (!raw) return null;
	const ids = raw
		.split(/[\s,]+/)
		.map((s) => s.trim())
		.filter(Boolean);
	return ids.length > 0 ? new Set(ids) : null;
}

/** Parse the `TENANT_KEY_SCOPE` env map and return the allowed ids for this bearer hash, if listed. */
function scopeForKeyHash(rawEnv: string | undefined, keyHash: string): Set<string> | null {
	if (!rawEnv) return null;
	let parsed: unknown;
	try {
		parsed = JSON.parse(rawEnv);
	} catch {
		// Malformed env config: fail-open to "no env constraint" rather than bricking
		// the route (the never-break-prod mandate). This is a deliberate trade-off —
		// a typo'd TENANT_KEY_SCOPE disables only the env-map cap, it does not grant
		// access beyond today's baseline (which has no scope cap at all). Any
		// `X-Tenant-Scope` header still applies.
		return null;
	}
	if (typeof parsed !== 'object' || parsed === null) return null;
	const entry = (parsed as Record<string, unknown>)[keyHash];
	if (!Array.isArray(entry)) return null; // bearer not listed → unconstrained by env
	const ids = entry.filter((v): v is string => typeof v === 'string');
	return new Set(ids);
}

/**
 * Assert the caller is entitled to the resolved sub-tenant. Returns `true` when
 * allowed (including when no scoping signal is configured — opt-in) and `false`
 * when a configured scope explicitly excludes the requested tenant.
 */
async function assertTenantScope(
	c: { req: { header(name: string): string | undefined }; env: { TENANT_KEY_SCOPE?: string } },
	subTenantId: string,
): Promise<boolean> {
	const headerScope = parseScopeHeader(c.req.header('x-tenant-scope'));

	let envScope: Set<string> | null = null;
	const rawEnv = c.env.TENANT_KEY_SCOPE;
	if (rawEnv) {
		const bearer = (c.req.header('authorization') ?? '').replace(/^Bearer\s+/i, '').trim();
		if (bearer) {
			const keyHash = await sha256Hex(bearer);
			if (SHA256_HEX_RE.test(keyHash)) {
				envScope = scopeForKeyHash(rawEnv, keyHash);
			}
		}
	}

	// No signal at all → opt-in disabled, preserve current behaviour.
	if (!headerScope && !envScope) return true;

	// INTERSECTION, not union: every signal that is present must independently
	// allow the tenant. The `TENANT_KEY_SCOPE` env map is bound to sha256(bearer)
	// and is the credential-anchored cap; the `X-Tenant-Scope` header is
	// caller-supplied and may only NARROW that cap, never widen it (otherwise an
	// attacker holding the shared key would send a permissive header to bypass the
	// env map). Each present scope is therefore a hard gate.
	if (envScope && !envScope.has(subTenantId)) return false;
	if (headerScope && !headerScope.has(subTenantId)) return false;
	return true;
}

/** UUIDv4 generation via Web Crypto. Workers runtime exposes randomUUID. */
function newCycleId(): string {
	return crypto.randomUUID();
}

/** Generate a per-row id (scans, findings). */
function newRowId(): string {
	return crypto.randomUUID();
}

/**
 * Dispatch an audit event for a Tenant orchestrator action via ctx.waitUntil so
 * the audit insert never blocks the response. Caller supplies the event body
 * minus the actor / network metadata, which we derive from the request.
 *
 * actorTier defaults to 'partner' (the bv-web service binding identity); when
 * paid OAuth tier propagation lands, this will become claim-driven.
 *
 * Phase 6 hardening: every 4xx/5xx return path now also dispatches an audit
 * event (outcome `'denied'` or `'error'`) so security posture analytics
 * reflect rejected traffic, not only successful upserts/scans/reads.
 */
type AuditPartial = Omit<AuditEvent, 'actorPrincipal' | 'actorTier' | 'ipHash' | 'cfRay'>;

type TenantRequestCtx = {
	req: { header(name: string): string | undefined };
	env: { TENANT_REGISTRY_DB?: D1Database };
	executionCtx: { waitUntil(promise: Promise<unknown>): void };
};

function dispatchAudit(c: TenantRequestCtx, partial: AuditPartial): void {
	const registryD1 = c.env.TENANT_REGISTRY_DB;
	if (!registryD1) return;
	const bearer = (c.req.header('authorization') ?? '').replace(/^Bearer\s+/i, '').trim();
	const ip = resolveClientIpFromHeaderGetter((name) => c.req.header(name));
	const event: AuditEvent = {
		...partial,
		actorPrincipal: bearer ? hashForAnalytics(bearer) : 'anonymous',
		actorTier: 'partner',
		ipHash: ip !== 'unknown' ? hashIpForAnalytics(ip) : undefined,
		cfRay: c.req.header('cf-ray') ?? undefined,
	};
	const db = drizzle(registryD1, { schema: registrySchema });
	// Cast to a structural ExecutionContext for Drizzle's API; the only method we
	// rely on at runtime is waitUntil, which both shapes provide.
	c.executionCtx.waitUntil(recordAuditEvent(db, event, c.executionCtx as ExecutionContext));
}

/**
 * Bound the resourceId we put in the audit row. Tenant headers, cycle ids,
 * and similar fields can be attacker-controlled before validation succeeds —
 * keeping them ≤64 chars matches the AuditEventSchema cap and prevents an
 * attacker from spamming megabyte rows into `audit_events` via header abuse.
 */
function safeResourceId(raw: string | undefined): string {
	if (!raw) return '<unknown>';
	const s = String(raw).slice(0, 64);
	return s.length > 0 ? s : '<unknown>';
}

/**
 * Run the per-tenant rate limiter if `RATE_LIMIT` KV is bound. Returns
 * `allowed: true` with full quota when KV is unavailable so a misconfigured
 * deployment doesn't 429 every legitimate call.
 *
 * Tier resolution follows `ResolvedTenant.tier` (additive on the resolver) —
 * defaults to `'default'` until bv-web wires up the override path.
 */
async function maybeRateLimit(
	c: { env: { RATE_LIMIT?: KVNamespace } },
	subTenantId: string,
	bucket: RateLimitBucket,
	tier: string,
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
	const kv = c.env.RATE_LIMIT;
	if (!kv) {
		// Limiter is opt-in via the binding — keep behavior identical to pre-Phase-6
		// when unbound (e.g. local `wrangler dev`).
		const safeTier = (tier as keyof typeof PER_TENANT_QUOTAS) in PER_TENANT_QUOTAS ? (tier as keyof typeof PER_TENANT_QUOTAS) : 'default';
		const q = PER_TENANT_QUOTAS[safeTier];
		const fakeReset = Date.now() + 60_000;
		// Pull a representative quota for the bucket so callers can still
		// surface a meaningful Retry-After if they ever hit a synthetic deny.
		const remaining = bucket === 'scans:day' ? q.scansPerDay : bucket === 'portfolio:min' ? q.portfolioPerMin : q.reportsPerMin;
		return { allowed: true, remaining, resetAt: fakeReset };
	}
	const safeTier = (tier as keyof typeof PER_TENANT_QUOTAS) in PER_TENANT_QUOTAS ? (tier as keyof typeof PER_TENANT_QUOTAS) : 'default';
	return checkAndRecord(kv, subTenantId, bucket, safeTier);
}

/** Build the 429 response with `Retry-After` set to seconds-until-reset. */
function rateLimited(
	c: {
		json(body: unknown, status: number, headers?: Record<string, string>): Response;
	},
	resetAt: number,
): Response {
	const retryAfterSeconds = Math.max(1, Math.ceil((resetAt - Date.now()) / 1000));
	return c.json(
		{ error: 'Rate limit exceeded', retry_after: retryAfterSeconds },
		429,
		{ 'Retry-After': String(retryAfterSeconds) },
	);
}

// ─── POST /internal/tenants/portfolio ──────────────────────────────────────────

tenantRoutes.post('/portfolio', async (c) => {
	try {
		const raw = await c.req.text();
		if (raw.length > MAX_TENANT_PORTFOLIO_BODY_BYTES) {
			// Tenant header has not been read yet — resourceId is `<unknown>`.
			dispatchAudit(c, {
				action: 'portfolio.upsert',
				resourceType: 'sub_tenant',
				resourceId: '<unknown>',
				outcome: 'denied',
				blob: { reason: 'body_too_large', byteLength: raw.length, maxBytes: MAX_TENANT_PORTFOLIO_BODY_BYTES },
			});
			return c.json({ error: `Request body exceeds maximum of ${MAX_TENANT_PORTFOLIO_BODY_BYTES} bytes` }, 413);
		}

		const tenantOrErr = extractTenantHeader(c);
		if (typeof tenantOrErr !== 'string') {
			const headerRaw = c.req.header('x-tenant');
			dispatchAudit(c, {
				action: 'portfolio.upsert',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(headerRaw),
				outcome: 'denied',
				blob: { reason: 'invalid_tenant_header', error: tenantOrErr.error },
			});
			return c.json({ error: tenantOrErr.error }, 400);
		}

		let body: { domains: string[] };
		try {
			body = PortfolioRequestSchema.parse(JSON.parse(raw)) as { domains: string[] };
		} catch (err) {
			const errMsg = err instanceof ZodError ? zodToError(err) : 'Invalid request body';
			dispatchAudit(c, {
				action: 'portfolio.upsert',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'invalid_body', error: errMsg },
			});
			return c.json({ error: errMsg }, 400);
		}

		// Domain shape validated by Zod; semantic validation (SSRF / blocklist) here.
		const sanitized: string[] = [];
		for (const d of body.domains) {
			const v = validateDomain(d);
			if (!v.valid) {
				dispatchAudit(c, {
					action: 'portfolio.upsert',
					resourceType: 'sub_tenant',
					resourceId: safeResourceId(tenantOrErr),
					outcome: 'denied',
					blob: { reason: 'invalid_domain', error: v.error ?? 'rejected' },
				});
				return c.json({ error: `Invalid domain: ${v.error ?? 'rejected'}` }, 400);
			}
			const s = sanitizeDomain(d);
			if (!s) {
				dispatchAudit(c, {
					action: 'portfolio.upsert',
					resourceType: 'sub_tenant',
					resourceId: safeResourceId(tenantOrErr),
					outcome: 'denied',
					blob: { reason: 'invalid_domain_after_sanitize' },
				});
				return c.json({ error: `Invalid domain: ${d}` }, 400);
			}
			sanitized.push(s);
		}

		let tenant;
		try {
			tenant = await resolveTenant(c.env, tenantOrErr);
		} catch (err) {
			const msg = err instanceof Error ? err.message : 'Tenant not found';
			const status = msg.startsWith('Tenant not found') ? 404 : 400;
			const errMsg = status === 404 ? msg : msg.startsWith('Invalid') ? msg : 'Invalid tenant identifier';
			dispatchAudit(c, {
				action: 'portfolio.upsert',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: status === 404 ? 'tenant_not_found' : 'tenant_lookup_failed', error: errMsg },
			});
			return c.json({ error: errMsg }, status);
		}

		// FINDING #5 (BOLA): opt-in per-credential tenant-scope assertion. No-op
		// (returns true) unless a scope signal is configured, so the live
		// single-key bv-web flow is unchanged.
		if (!(await assertTenantScope(c, tenant.subTenantId))) {
			dispatchAudit(c, {
				action: 'portfolio.upsert',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'tenant_scope_denied' },
			});
			return c.json({ error: 'Resource not found' }, 403);
		}

		const tenantDb = (c.env as Record<string, unknown>)[tenant.dbBinding] as D1Database | undefined;
		if (!tenantDb) {
			// Should be caught by resolveTenant, but defense-in-depth.
			dispatchAudit(c, {
				action: 'portfolio.upsert',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'tenant_db_binding_missing' },
			});
			return c.json({ error: `Tenant not found: ${tenantOrErr}` }, 404);
		}

		// Per-tenant rate limit. Audit on rejection, then 429 with Retry-After.
		const rl = await maybeRateLimit(c, tenant.subTenantId, 'portfolio:min', tenant.tier);
		if (!rl.allowed) {
			dispatchAudit(c, {
				action: 'portfolio.upsert',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'rate_limit_exceeded', bucket: 'portfolio:min', tier: tenant.tier },
			});
			return rateLimited(c, rl.resetAt);
		}

		let inserted = 0;
		let updated = 0;
		let skipped = 0;
		const now = Date.now();
		for (const domain of sanitized) {
			try {
				const existing = await tenantDb.prepare(PORTFOLIO_PROBE_SQL).bind(domain).first<{ domain: string }>();
				await tenantDb.prepare(PORTFOLIO_UPSERT_SQL).bind(domain, 'api', now).run();
				if (existing) updated += 1;
				else inserted += 1;
			} catch {
				skipped += 1;
			}
		}

		dispatchAudit(c, {
			action: 'portfolio.upsert',
			resourceType: 'sub_tenant',
			resourceId: tenantOrErr,
			outcome: 'success',
			blob: { inserted, updated, skipped, total: sanitized.length },
		});

		return c.json({ inserted, updated, skipped, total: sanitized.length });
	} catch (err) {
		const message = err instanceof Error ? err.message.slice(0, 256) : 'unknown';
		dispatchAudit(c, {
			action: 'portfolio.upsert',
			resourceType: 'sub_tenant',
			resourceId: safeResourceId(c.req.header('x-tenant')),
			outcome: 'error',
			blob: { reason: 'unhandled_exception', message },
		});
		return c.json({ error: 'Internal error' }, 500);
	}
});

// ─── POST /internal/tenants/scan ───────────────────────────────────────────────

tenantRoutes.post('/scan', async (c) => {
	try {
		const raw = await c.req.text();
		if (raw.length > MAX_INTERNAL_BATCH_BODY_BYTES) {
			dispatchAudit(c, {
				action: 'scan.start',
				resourceType: 'cycle',
				resourceId: '<unknown>',
				subTenantId: safeResourceId(c.req.header('x-tenant')),
				outcome: 'denied',
				blob: { reason: 'body_too_large', byteLength: raw.length, maxBytes: MAX_INTERNAL_BATCH_BODY_BYTES },
			});
			return c.json({ error: `Request body exceeds maximum of ${MAX_INTERNAL_BATCH_BODY_BYTES} bytes` }, 413);
		}

		const tenantOrErr = extractTenantHeader(c);
		if (typeof tenantOrErr !== 'string') {
			const headerRaw = c.req.header('x-tenant');
			dispatchAudit(c, {
				action: 'scan.start',
				resourceType: 'cycle',
				resourceId: '<unknown>',
				subTenantId: safeResourceId(headerRaw),
				outcome: 'denied',
				blob: { reason: 'invalid_tenant_header', error: tenantOrErr.error },
			});
			return c.json({ error: tenantOrErr.error }, 400);
		}

		let body: { cycle_id?: string; domain_ids?: string[]; domains?: string[]; concurrency?: number; force_refresh?: boolean; mode?: 'sync' | 'queue' };
		try {
			body = ScanRequestSchema.parse(JSON.parse(raw)) as typeof body;
		} catch (err) {
			const errMsg = err instanceof ZodError ? zodToError(err) : 'Invalid request body';
			dispatchAudit(c, {
				action: 'scan.start',
				resourceType: 'cycle',
				resourceId: '<unknown>',
				subTenantId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'invalid_body', error: errMsg },
			});
			return c.json({ error: errMsg }, 400);
		}

		let tenant;
		try {
			tenant = await resolveTenant(c.env, tenantOrErr);
		} catch (err) {
			const msg = err instanceof Error ? err.message : 'Tenant not found';
			const status = msg.startsWith('Tenant not found') ? 404 : 400;
			const errMsg = status === 404 ? msg : msg.startsWith('Invalid') ? msg : 'Invalid tenant identifier';
			dispatchAudit(c, {
				action: 'scan.start',
				resourceType: 'cycle',
				resourceId: '<unknown>',
				subTenantId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: status === 404 ? 'tenant_not_found' : 'tenant_lookup_failed', error: errMsg },
			});
			return c.json({ error: errMsg }, status);
		}

		// FINDING #5 (BOLA): opt-in per-credential tenant-scope assertion.
		if (!(await assertTenantScope(c, tenant.subTenantId))) {
			dispatchAudit(c, {
				action: 'scan.start',
				resourceType: 'cycle',
				resourceId: '<unknown>',
				subTenantId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'tenant_scope_denied' },
			});
			return c.json({ error: 'Resource not found' }, 403);
		}

		const tenantDb = (c.env as Record<string, unknown>)[tenant.dbBinding] as D1Database | undefined;
		if (!tenantDb) {
			dispatchAudit(c, {
				action: 'scan.start',
				resourceType: 'cycle',
				resourceId: '<unknown>',
				subTenantId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'tenant_db_binding_missing' },
			});
			return c.json({ error: `Tenant not found: ${tenantOrErr}` }, 404);
		}

		// Per-tenant rate limit. `scans:day` because /scan is the heavy workload.
		const rl = await maybeRateLimit(c, tenant.subTenantId, 'scans:day', tenant.tier);
		if (!rl.allowed) {
			dispatchAudit(c, {
				action: 'scan.start',
				resourceType: 'cycle',
				resourceId: '<unknown>',
				subTenantId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'rate_limit_exceeded', bucket: 'scans:day', tier: tenant.tier },
			});
			return rateLimited(c, rl.resetAt);
		}

		// Resolve target domains:
		//   1. domain_ids → portfolio-enrolled IDs only (DB-verified; rejects unenrolled)
		//   2. domains    → explicit ad-hoc scan list (validateDomain still runs; does
		//                   NOT require portfolio enrollment — by design)
		//   3. neither    → full active portfolio
		let targets: string[] = [];
		if (body.domain_ids && body.domain_ids.length > 0) {
			// Enforce portfolio enrollment so a tenant can't burn quota on arbitrary
			// strings dressed as IDs. validateDomain() runs below regardless.
			const placeholders = body.domain_ids.map(() => '?').join(',');
			const enrolledRows = await tenantDb
				.prepare(`SELECT domain FROM domains WHERE domain IN (${placeholders})`)
				.bind(...body.domain_ids)
				.all<{ domain: string }>();
			const enrolledSet = new Set((enrolledRows.results ?? []).map((r) => r.domain));
			targets = body.domain_ids.filter((d) => enrolledSet.has(d));
			if (targets.length === 0) {
				const requested = body.domain_ids.length;
				dispatchAudit(c, {
					action: 'scan.start',
					resourceType: 'cycle',
					resourceId: '<unknown>',
					subTenantId: safeResourceId(tenantOrErr),
					outcome: 'denied',
					blob: { reason: 'unenrolled_domain_ids', unenrolled_count: requested },
				});
				return c.json({ error: 'Invalid domain_ids: none enrolled in tenant portfolio' }, 400);
			}
		} else if (body.domains && body.domains.length > 0) {
			targets = body.domains;
		} else {
			const rows = await tenantDb.prepare('SELECT domain FROM domains WHERE watch = 1').all<{ domain: string }>();
			targets = (rows.results ?? []).map((r) => r.domain);
		}

	// Validate / sanitize.
	const validated: string[] = [];
	for (const d of targets) {
		const v = validateDomain(d);
		if (!v.valid) continue;
		const s = sanitizeDomain(d);
		if (s) validated.push(s);
	}

	const cycleId = body.cycle_id ?? newCycleId();
	const concurrency = body.concurrency ?? DEFAULT_SCAN_CONCURRENCY;
	const startedAt = Date.now();

	// Phase 2 fast-path: enqueue one message per domain and return 202.
	// Validation has already run above, so the producer never burns queue
	// space on bad input. The consumer (handleScanQueue) is responsible for
	// running the actual scan + persisting rows.
	if (body.mode === 'queue') {
		if (!c.env.BV_SCANNER_QUEUE) {
			dispatchAudit(c, {
				action: 'scan.start',
				resourceType: 'cycle',
				resourceId: cycleId,
				subTenantId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'queue_binding_missing' },
			});
			return c.json({ error: 'Invalid mode: queue dispatch is not configured on this deployment' }, 400);
		}
		let queued = 0;
		for (const domain of validated) {
			try {
				await c.env.BV_SCANNER_QUEUE.send(
					{
						cycle_id: cycleId,
						sub_tenant_id: tenant.subTenantId,
						domain,
						force_refresh: body.force_refresh,
					},
					{ contentType: 'json' },
				);
				queued += 1;
			} catch {
				// Per-message send failures are logged elsewhere; surface aggregate
				// shortfall in the response so the caller can decide to retry.
			}
		}
		return c.json(
			{
				cycle_id: cycleId,
				total: validated.length,
				queued,
				started_at: startedAt,
			},
			202,
		);
	}

	const cacheTtlSeconds = parseCacheTtl(c.env.CACHE_TTL_SECONDS);
	const runtimeBase = {
		providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
		providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS?.split(',')
			.map((h) => h.trim())
			.filter(Boolean),
		providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
		analytics: createAnalyticsClient(c.env.MCP_ANALYTICS),
		profileAccumulator: c.env.PROFILE_ACCUMULATOR,
		waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
		scoringConfig: parseScoringConfigCached(c.env.SCORING_CONFIG),
		cacheTtlSeconds,
		scanTimeoutMs: parseScanTimeout(c.env.SCAN_TIMEOUT_MS),
		perCheckTimeoutMs: parsePerCheckTimeout(c.env.PER_CHECK_TIMEOUT_MS),
		secondaryDoh: c.env.BV_DOH_ENDPOINT ? { endpoint: c.env.BV_DOH_ENDPOINT, token: c.env.BV_DOH_TOKEN } : undefined,
	};

	let completed = 0;
	let errored = 0;

	for (let i = 0; i < validated.length; i += concurrency) {
		const chunk = validated.slice(i, i + concurrency);
		const settled = await Promise.allSettled(
			chunk.map(async (domain) => {
				// Phase 6: Fingerprint pre-flight
				if (!body.force_refresh) {
					try {
						// Look up the last scan and fingerprint for this domain
						const lastScan = await tenantDb
							.prepare('SELECT result_json, scan_at FROM scans WHERE domain = ? ORDER BY scan_at DESC LIMIT 1')
							.bind(domain)
							.first<{ result_json: string; scan_at: number }>();

						if (lastScan && lastScan.result_json) {
							const domainRow = await tenantDb
								.prepare('SELECT fingerprint FROM domains WHERE domain = ?')
								.bind(domain)
								.first<{ fingerprint: string | null }>();

							const now = Date.now();
							const oneDayMs = 24 * 3600 * 1000;
							const isRecent = now - lastScan.scan_at < oneDayMs;

							if (isRecent) {
								const fp = await computeFingerprint(domain);
								if (fp.kind === 'ok' && !fingerprintsDiffer(fp.fingerprint, domainRow?.fingerprint ?? null)) {
									const captured = JSON.parse(lastScan.result_json) as CheckResult;
									// Return the cached result as if it were a fresh scan, but skip handleToolsCall
									return { domain, result: { isError: false }, captured, skippedByFingerprint: true };
								}
							}
						}
					} catch {
						// Fingerprint pre-flight is best-effort. Fall through to full scan on error.
					}
				}

				let captured: CheckResult | null = null;
				const result = await handleToolsCall(
					{ name: 'scan_domain', arguments: { domain } },
					c.env.SCAN_CACHE,
					{
						...runtimeBase,
						resultCapture: (r) => {
							captured = r;
						},
					},
				);
				return { domain, result, captured: captured as CheckResult | null, skippedByFingerprint: false };
			}),
		);

		for (const s of settled) {
			if (s.status === 'rejected') {
				errored += 1;
				continue;
			}
			const { domain, result, captured, skippedByFingerprint } = s.value as { domain: string; result: { isError: boolean }; captured: CheckResult | null; skippedByFingerprint: boolean };
			if (result.isError) {
				errored += 1;
				continue;
			}
			completed += 1;

			// Skip persistence if we reused an existing scan result for the same cycle
			if (skippedByFingerprint) continue;

			// Persist to per-tenant D1. Failures here count as scan-recording errors
			// but don't fail the whole cycle (consistent with §7.1 partial-result
			// design — D1 write failures get re-enqueued elsewhere).
			try {
				const scanId = newRowId();
				const score = captured?.score ?? null;
				const grade = (captured as unknown as { grade?: string } | null)?.grade ?? null;
				const findingCount = captured?.findings?.length ?? 0;
				await tenantDb
					.prepare(SCANS_INSERT_SQL)
					.bind(scanId, domain, Date.now(), score, grade, null, findingCount, captured ? JSON.stringify(captured) : null, cycleId)
					.run();

				if (captured?.findings) {
					for (const f of captured.findings) {
						await tenantDb
							.prepare(FINDINGS_INSERT_SQL)
							.bind(
								newRowId(),
								scanId,
								domain,
								f.category ?? 'unknown',
								f.severity ?? 'info',
								f.title ?? '',
								f.detail ?? null,
								f.metadata ? JSON.stringify(f.metadata) : null,
							)
							.run();
					}
				}
			} catch {
				// Persistence failure — logged via analytics elsewhere; don't fail
				// the cycle on a single row error.
			}
		}
	}

		dispatchAudit(c, {
			action: 'scan.start',
			resourceType: 'cycle',
			resourceId: cycleId,
			subTenantId: tenantOrErr,
			outcome: 'success',
			blob: { total: validated.length, completed, errored },
		});

		return c.json({
			cycle_id: cycleId,
			total: validated.length,
			completed,
			errored,
			started_at: startedAt,
			finished_at: Date.now(),
		});
	} catch (err) {
		const message = err instanceof Error ? err.message.slice(0, 256) : 'unknown';
		dispatchAudit(c, {
			action: 'scan.start',
			resourceType: 'cycle',
			resourceId: '<unknown>',
			subTenantId: safeResourceId(c.req.header('x-tenant')),
			outcome: 'error',
			blob: { reason: 'unhandled_exception', message },
		});
		return c.json({ error: 'Internal error' }, 500);
	}
});

// ─── POST /internal/tenants/discover ──────────────────────────────────────────

tenantRoutes.post('/discover', async (c) => {
	try {
		const raw = await c.req.text();
		if (raw.length > MAX_INTERNAL_BATCH_BODY_BYTES) {
			dispatchAudit(c, {
				action: 'discovery.start',
				resourceType: 'sub_tenant',
				resourceId: '<unknown>',
				outcome: 'denied',
				blob: { reason: 'body_too_large', byteLength: raw.length, maxBytes: MAX_INTERNAL_BATCH_BODY_BYTES },
			});
			return c.json({ error: `Request body exceeds maximum of ${MAX_INTERNAL_BATCH_BODY_BYTES} bytes` }, 413);
		}

		const tenantOrErr = extractTenantHeader(c);
		if (typeof tenantOrErr !== 'string') {
			const headerRaw = c.req.header('x-tenant');
			dispatchAudit(c, {
				action: 'discovery.start',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(headerRaw),
				outcome: 'denied',
				blob: { reason: 'invalid_tenant_header', error: tenantOrErr.error },
			});
			return c.json({ error: tenantOrErr.error }, 400);
		}

		let body: {
			seed_domains?: string[];
			signals?: Array<'san' | 'ns' | 'dmarc_rua' | 'dkim_key_reuse'>;
			min_confidence?: number;
			auto_import?: boolean;
		};
		try {
			body = DiscoveryRequestSchema.parse(JSON.parse(raw)) as typeof body;
		} catch (err) {
			const errMsg = err instanceof ZodError ? zodToError(err) : 'Invalid request body';
			dispatchAudit(c, {
				action: 'discovery.start',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'invalid_body', error: errMsg },
			});
			return c.json({ error: errMsg }, 400);
		}

		let tenant;
		try {
			tenant = await resolveTenant(c.env, tenantOrErr);
		} catch (err) {
			const msg = err instanceof Error ? err.message : 'Tenant not found';
			const status = msg.startsWith('Tenant not found') ? 404 : 400;
			const errMsg = status === 404 ? msg : msg.startsWith('Invalid') ? msg : 'Invalid tenant identifier';
			dispatchAudit(c, {
				action: 'discovery.start',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: status === 404 ? 'tenant_not_found' : 'tenant_lookup_failed', error: errMsg },
			});
			return c.json({ error: errMsg }, status);
		}

		// FINDING #5 (BOLA): opt-in per-credential tenant-scope assertion.
		if (!(await assertTenantScope(c, tenant.subTenantId))) {
			dispatchAudit(c, {
				action: 'discovery.start',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'tenant_scope_denied' },
			});
			return c.json({ error: 'Resource not found' }, 403);
		}

		const tenantDb = (c.env as Record<string, unknown>)[tenant.dbBinding] as D1Database | undefined;
		if (!tenantDb) {
			dispatchAudit(c, {
				action: 'discovery.start',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'tenant_db_binding_missing' },
			});
			return c.json({ error: `Tenant not found: ${tenantOrErr}` }, 404);
		}

		// Per-tenant rate limit. Discovery uses `reports:min` as it's a metadata-heavy
		// but typically less frequent operation than /scan.
		const rl = await maybeRateLimit(c, tenant.subTenantId, 'reports:min', tenant.tier);
		if (!rl.allowed) {
			dispatchAudit(c, {
				action: 'discovery.start',
				resourceType: 'sub_tenant',
				resourceId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'rate_limit_exceeded', bucket: 'reports:min', tier: tenant.tier },
			});
			return rateLimited(c, rl.resetAt);
		}

		// FINDING #8: caller-supplied seed_domains must clear the same SSRF /
		// blocklist gate as /portfolio and /scan before they drive discovery or an
		// auto_import upsert. Reject the whole request on the first invalid seed so
		// the behaviour matches /portfolio's fail-fast contract.
		let seeds: string[] = [];
		if (body.seed_domains && body.seed_domains.length > 0) {
			const sanitizedSeeds: string[] = [];
			for (const d of body.seed_domains) {
				const v = validateDomain(d);
				if (!v.valid) {
					dispatchAudit(c, {
						action: 'discovery.start',
						resourceType: 'sub_tenant',
						resourceId: safeResourceId(tenantOrErr),
						outcome: 'denied',
						blob: { reason: 'invalid_seed_domain', error: v.error ?? 'rejected' },
					});
					return c.json({ error: `Invalid domain: ${v.error ?? 'rejected'}` }, 400);
				}
				const s = sanitizeDomain(d);
				if (!s) {
					dispatchAudit(c, {
						action: 'discovery.start',
						resourceType: 'sub_tenant',
						resourceId: safeResourceId(tenantOrErr),
						outcome: 'denied',
						blob: { reason: 'invalid_seed_domain_after_sanitize' },
					});
					return c.json({ error: `Invalid domain: ${d}` }, 400);
				}
				sanitizedSeeds.push(s);
			}
			seeds = sanitizedSeeds;
		} else {
			const rows = await tenantDb
				.prepare('SELECT domain FROM domains WHERE watch = 1 LIMIT 10')
				.all<{ domain: string }>();
			seeds = (rows.results ?? []).map((r) => r.domain);
		}

		if (seeds.length === 0) {
			return c.json({ error: 'No seed domains provided or enrolled in portfolio' }, 400);
		}

		const signals = body.signals;
		const minConfidence = body.min_confidence ?? 0.5;
		const results: CheckResult[] = [];

		// For now, run discovery for each seed.
		// Future: optimize brand-discovery orchestrator to take a seed set.
		for (const domain of seeds) {
			try {
				const result = await discoverBrandDomains(domain, {
					signals,
					min_confidence: minConfidence,
				});
				results.push(result);
			} catch {
				// Single seed failure — skip.
			}
		}

		// Aggregate candidates across all seeds.
		const candidatesMap = new Map<string, { domain: string; confidence: number; signals: string[] }>();
		for (const res of results) {
			for (const f of res.findings) {
				const cand = f.metadata?.candidate as string | undefined;
				if (!cand) continue;
				const existing = candidatesMap.get(cand);
				const conf = (f.metadata?.combinedConfidence as number) ?? 0;
				const sigs = (f.metadata?.signals as string[]) ?? [];
				if (!existing || conf > existing.confidence) {
					candidatesMap.set(cand, { domain: cand, confidence: conf, signals: sigs });
				}
			}
		}

		const candidates = Array.from(candidatesMap.values()).sort((a, b) => b.confidence - a.confidence);

		let imported = 0;
		if (body.auto_import) {
			const now = Date.now();
			for (const cand of candidates) {
				if (cand.confidence >= 0.85) {
					// FINDING #8: discovery candidates are derived from external DNS / CT
					// data and are NOT trusted — run the same SSRF / blocklist gate as
					// /portfolio before persisting. An invalid candidate (IP literal,
					// reserved TLD, blocklisted host) is skipped, never upserted.
					const v = validateDomain(cand.domain);
					if (!v.valid) continue;
					const safeCandidate = sanitizeDomain(cand.domain);
					if (!safeCandidate) continue;
					try {
						const existing = await tenantDb.prepare(PORTFOLIO_PROBE_SQL).bind(safeCandidate).first<{ domain: string }>();
						if (!existing) {
							// Insert with a 'discovery' source tag so the UI can highlight them.
							await tenantDb.prepare(PORTFOLIO_UPSERT_SQL).bind(safeCandidate, 'discovery', now).run();
							imported += 1;
						}
					} catch {
						// Skip on DB error.
					}
				}
			}
		}

		dispatchAudit(c, {
			action: 'discovery.start',
			resourceType: 'sub_tenant',
			resourceId: tenantOrErr,
			outcome: 'success',
			blob: { seeds: seeds.length, candidates: candidates.length, imported },
		});

		return c.json({
			seeds: seeds.length,
			candidates,
			imported,
		});
	} catch (err) {
		const message = err instanceof Error ? err.message.slice(0, 256) : 'unknown';
		dispatchAudit(c, {
			action: 'discovery.start',
			resourceType: 'sub_tenant',
			resourceId: safeResourceId(c.req.header('x-tenant')),
			outcome: 'error',
			blob: { reason: 'unhandled_exception', message },
		});
		return c.json({ error: 'Internal error' }, 500);
	}
});

// ─── GET /internal/tenants/report/:cycle_id ────────────────────────────────────

tenantRoutes.get('/report/:cycle_id', async (c) => {
	try {
		const tenantOrErr = extractTenantHeader(c);
		if (typeof tenantOrErr !== 'string') {
			const headerRaw = c.req.header('x-tenant');
			dispatchAudit(c, {
				action: 'report.read',
				resourceType: 'cycle',
				resourceId: safeResourceId(c.req.param('cycle_id')),
				subTenantId: safeResourceId(headerRaw),
				outcome: 'denied',
				blob: { reason: 'invalid_tenant_header', error: tenantOrErr.error },
			});
			return c.json({ error: tenantOrErr.error }, 400);
		}

		let params: { cycle_id: string };
		try {
			params = ReportParamsSchema.parse({ cycle_id: c.req.param('cycle_id') });
		} catch (err) {
			const errMsg = err instanceof ZodError ? zodToError(err) : 'Invalid cycle_id';
			dispatchAudit(c, {
				action: 'report.read',
				resourceType: 'cycle',
				resourceId: safeResourceId(c.req.param('cycle_id')),
				subTenantId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'invalid_cycle_id', error: errMsg },
			});
			return c.json({ error: errMsg }, 400);
		}

		let tenant;
		try {
			tenant = await resolveTenant(c.env, tenantOrErr);
		} catch (err) {
			const msg = err instanceof Error ? err.message : 'Tenant not found';
			const status = msg.startsWith('Tenant not found') ? 404 : 400;
			const errMsg = status === 404 ? msg : msg.startsWith('Invalid') ? msg : 'Invalid tenant identifier';
			dispatchAudit(c, {
				action: 'report.read',
				resourceType: 'cycle',
				resourceId: params.cycle_id,
				subTenantId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: status === 404 ? 'tenant_not_found' : 'tenant_lookup_failed', error: errMsg },
			});
			return c.json({ error: errMsg }, status);
		}

		// FINDING #5 (BOLA): opt-in per-credential tenant-scope assertion.
		if (!(await assertTenantScope(c, tenant.subTenantId))) {
			dispatchAudit(c, {
				action: 'report.read',
				resourceType: 'cycle',
				resourceId: params.cycle_id,
				subTenantId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'tenant_scope_denied' },
			});
			return c.json({ error: 'Resource not found' }, 403);
		}

		const tenantDb = (c.env as Record<string, unknown>)[tenant.dbBinding] as D1Database | undefined;
		if (!tenantDb) {
			dispatchAudit(c, {
				action: 'report.read',
				resourceType: 'cycle',
				resourceId: params.cycle_id,
				subTenantId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'tenant_db_binding_missing' },
			});
			return c.json({ error: `Tenant not found: ${tenantOrErr}` }, 404);
		}

		// Per-tenant rate limit. `reports:min` is dashboard-style read traffic.
		const rl = await maybeRateLimit(c, tenant.subTenantId, 'reports:min', tenant.tier);
		if (!rl.allowed) {
			dispatchAudit(c, {
				action: 'report.read',
				resourceType: 'cycle',
				resourceId: params.cycle_id,
				subTenantId: safeResourceId(tenantOrErr),
				outcome: 'denied',
				blob: { reason: 'rate_limit_exceeded', bucket: 'reports:min', tier: tenant.tier },
			});
			return rateLimited(c, rl.resetAt);
		}

		const scans = await tenantDb
			.prepare(REPORT_SCANS_SQL)
			.bind(params.cycle_id)
			.all<{ score: number | null; grade: string | null }>();
		const findings = await tenantDb
			.prepare(REPORT_FINDINGS_SQL)
			.bind(params.cycle_id)
			.all<{ category: string; severity: string; count: number }>();

		const scanRows = scans.results ?? [];
		const findingRows = findings.results ?? [];

		const scoreSum = scanRows.reduce((acc, r) => acc + (r.score ?? 0), 0);
		const meanScore = scanRows.length > 0 ? scoreSum / scanRows.length : 0;
		const gradeDist: Record<string, number> = {};
		for (const r of scanRows) {
			const g = r.grade ?? 'unknown';
			gradeDist[g] = (gradeDist[g] ?? 0) + 1;
		}
		const severityCounts: Record<string, number> = {};
		for (const f of findingRows) {
			severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + Number(f.count ?? 0);
		}

		dispatchAudit(c, {
			action: 'report.read',
			resourceType: 'cycle',
			resourceId: params.cycle_id,
			subTenantId: tenantOrErr,
			outcome: 'success',
			blob: { domains: scanRows.length },
		});

		return c.json({
			cycle_id: params.cycle_id,
			summary: {
				domains: scanRows.length,
				mean_score: meanScore,
				grade_dist: gradeDist,
				severity_counts: severityCounts,
			},
			findings_by_category: findingRows,
		});
	} catch (err) {
		const message = err instanceof Error ? err.message.slice(0, 256) : 'unknown';
		dispatchAudit(c, {
			action: 'report.read',
			resourceType: 'cycle',
			resourceId: safeResourceId(c.req.param('cycle_id')),
			subTenantId: safeResourceId(c.req.header('x-tenant')),
			outcome: 'error',
			blob: { reason: 'unhandled_exception', message },
		});
		return c.json({ error: 'Internal error' }, 500);
	}
});
