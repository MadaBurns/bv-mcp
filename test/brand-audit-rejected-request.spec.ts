// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-394 — a rejected or failed REQUEST on the async brand-audit / discovery / watch tools is
 * a tool error, not a scored HIGH finding about the domain.
 *
 * Before: `register_brand_audit_watch {webhook_url:'http://…'}`, `delete_brand_audit_watch
 * {watchId:<unknown>}` and `brand_audit_batch_start {domains:['169.254.169.254']}` returned
 * `isError:false` with `structuredContent {passed:true, score:75, findings:[{severity:'high',…}]}`
 * and the generic "Potential Impact" boilerplate. These specs drive the REAL dispatch
 * (`handleToolsCall`) against the real Workers D1 shim, then pin the producer-level kinds.
 */

import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import type { ToolRuntimeOptions } from '../src/handlers/tools';

function brandAuditDb(): D1Database {
	return (env as unknown as { BRAND_AUDIT_DB: D1Database }).BRAND_AUDIT_DB;
}

// Mirrors the production tables (src/lib/db/brand-audit-schema.ts), as the sibling specs do.
const SCHEMA = `
CREATE TABLE IF NOT EXISTS brand_audit_watches (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, domain TEXT NOT NULL, interval TEXT NOT NULL, webhook_url TEXT,
  last_run_at INTEGER, last_classification_hash TEXT, last_classification_result_json TEXT, pending_webhook_json TEXT,
  active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS brand_audits (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, status TEXT NOT NULL, total_targets INTEGER NOT NULL,
  completed_targets INTEGER NOT NULL DEFAULT 0, format TEXT NOT NULL, results_json TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, completed_at INTEGER
);
CREATE TABLE IF NOT EXISTS brand_audit_targets (
  audit_id TEXT NOT NULL REFERENCES brand_audits(id), target TEXT NOT NULL, status TEXT NOT NULL, result_json TEXT,
  pdf_r2_key TEXT, error TEXT, created_at INTEGER NOT NULL, completed_at INTEGER, PRIMARY KEY (audit_id, target)
);
CREATE TABLE IF NOT EXISTS brand_audit_steps (
  audit_id TEXT NOT NULL, target TEXT NOT NULL, step TEXT NOT NULL, status TEXT NOT NULL, payload_json TEXT,
  error TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (audit_id, target, step)
);`;

beforeAll(async () => {
	await brandAuditDb().exec(SCHEMA.replace(/\s+/g, ' ').trim());
});

beforeEach(async () => {
	await brandAuditDb().exec('DELETE FROM brand_audit_watches;');
});

function runtime(extra: Partial<ToolRuntimeOptions> = {}): ToolRuntimeOptions {
	return {
		authTier: 'owner',
		principalId: 'principal-sq394',
		brandAuditDb: brandAuditDb(),
		brandAuditQueue: { send: vi.fn().mockResolvedValue(undefined) } as never,
		...extra,
	} as ToolRuntimeOptions;
}

async function call(name: string, args: Record<string, unknown>, ro: ToolRuntimeOptions = runtime()) {
	const { handleToolsCall } = await import('../src/handlers/tools');
	const result = await handleToolsCall({ name, arguments: args }, undefined, ro);
	const first = result.content[0];
	return { result, text: first && 'text' in first ? first.text : '' };
}

/** The contract every rejected request must meet, whatever the kind. */
function expectToolError(out: Awaited<ReturnType<typeof call>>, kind: string) {
	expect(out.result.isError, 'a rejected request must be a tool error').toBe(true);
	expect(out.result.structuredContent?.kind).toBe(kind);
	expect(out.result.structuredContent).not.toHaveProperty('score');
	expect(out.result.structuredContent).not.toHaveProperty('passed');
	expect(out.result.structuredContent).not.toHaveProperty('findings');
	expect(out.text).not.toContain('Potential Impact');
	expect(out.text).not.toMatch(/Score:|Status:/);
	expect(out.text.startsWith('Error: ')).toBe(true);
}

describe('rejected requests surface as tool errors (dispatch)', () => {
	it('register_brand_audit_watch with an http webhook -> invalidInput tool error, no watch created', async () => {
		const out = await call('register_brand_audit_watch', { domain: 'nic.cz', interval: 'monthly', webhook_url: 'http://example.com/hook' });
		expectToolError(out, 'invalidInput');
		expect(out.text).toContain('Invalid request: webhook_url failed SSRF validation');
		const rows = await brandAuditDb().prepare('SELECT COUNT(*) AS n FROM brand_audit_watches').first<{ n: number }>();
		expect(rows?.n).toBe(0);
	});

	it('delete_brand_audit_watch for an unknown id -> notFound tool error that bv-web can still recognise', async () => {
		const out = await call('delete_brand_audit_watch', { watchId: 'no-such-watch-0000' });
		expectToolError(out, 'notFound');
		expect(out.text.startsWith('Error: Resource not found: ')).toBe(true);
		expect(out.result.structuredContent?.watchId).toBe('no-such-watch-0000');
		// bv-web-prod removeBrandAuditWatch (app/lib/tenant/brand-audit-watch.server.ts) treats
		// isError as success-with-reconcile ONLY when the payload matches this exact pattern.
		expect(JSON.stringify(out.result)).toMatch(/notFound|no watch with id/i);
	});

	it('brand_audit_batch_start with an IP literal -> invalidInput tool error naming the target', async () => {
		const out = await call('brand_audit_batch_start', { domains: ['169.254.169.254'] });
		expectToolError(out, 'invalidInput');
		expect(out.text).toContain('IP addresses are not allowed');
		expect(out.result.structuredContent?.invalidTargets).toEqual([{ input: '169.254.169.254', error: expect.stringContaining('IP') }]);
	});

	it('brand_audit_status and discover_brand_domains_findings for an unknown id -> notFound tool errors', async () => {
		expectToolError(await call('brand_audit_status', { auditId: 'aud-unknown' }), 'notFound');
		expectToolError(await call('discover_brand_domains_findings', { operationId: 'op-unknown' }), 'notFound');
	});

	it('brand_audit_get_report for an unknown id -> notFound tool error', async () => {
		expectToolError(await call('brand_audit_get_report', { auditId: 'aud-unknown' }), 'notFound');
	});

	it('does not hand the raw scored CheckResult to resultCapture (the /internal structured door)', async () => {
		const resultCapture = vi.fn();
		await call('delete_brand_audit_watch', { watchId: 'no-such-watch-0000' }, runtime({ resultCapture }));
		expect(resultCapture).not.toHaveBeenCalled();
	});

	it('leaves the success path untouched: a valid registration is still a scored CheckResult', async () => {
		const out = await call('register_brand_audit_watch', { domain: 'example.com', interval: 'monthly' });
		expect(out.result.isError).toBeUndefined();
		expect(out.result.structuredContent).toMatchObject({ passed: true, score: 100 });
	});
});

describe('outputSchema vs the kind-only error structuredContent', () => {
	// A strict MCP client validates structuredContent against outputSchema even when isError is true,
	// so a tool that can return a score-less error must not publish the score/passed-required schema.
	it('the five tools with rejection paths publish no outputSchema; the read-only list tool keeps it', async () => {
		const { TOOLS } = await import('../src/schemas/tool-definitions');
		const schemaOf = (name: string) => TOOLS.find((t) => t.name === name)?.outputSchema;
		for (const name of [
			'brand_audit_batch_start',
			'brand_audit_status',
			'brand_audit_get_report',
			'register_brand_audit_watch',
			'delete_brand_audit_watch',
		]) {
			expect(TOOLS.some((t) => t.name === name), `${name} must exist`).toBe(true);
			expect(schemaOf(name), `${name} must not declare an outputSchema`).toBeUndefined();
		}
		expect(schemaOf('list_brand_audit_watches')).toBeDefined();
	});
});

describe('producer kinds stay machine-readable', () => {
	it('batch start: batchTooLarge, quotaExceeded and persistenceFailure each carry their kind and extras', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const { getRejectedRequest } = await import('../src/tools/async-start-error-result');
		const deps = { db: brandAuditDb(), queue: { send: vi.fn() } };

		const tooMany = Array.from({ length: 51 }, (_, i) => `example${i}.com`);
		const large = getRejectedRequest(await brandAuditBatchStart(tooMany, {}, 'p', deps));
		expect(large?.kind).toBe('batchTooLarge');
		expect(large?.text.startsWith('Invalid request: ')).toBe(true);
		expect(large?.structured).toMatchObject({ kind: 'batchTooLarge', submittedCount: 51 });

		const throwingDb = {
			prepare: () => {
				throw new Error('d1_down');
			},
		} as unknown as D1Database;
		const persist = getRejectedRequest(await brandAuditBatchStart(['example.com'], {}, 'p', { ...deps, db: throwingDb }));
		expect(persist?.kind).toBe('persistenceFailure');
		expect(persist?.text).toContain('d1_down');

		const quota = getRejectedRequest(
			await brandAuditBatchStart(['example.com'], {}, 'p', {
				...deps,
				enforceQuota: vi.fn().mockResolvedValue({ allowed: false, limit: 50, remaining: 0, retryAfterMs: 5000 }),
			}),
		);
		expect(quota?.kind).toBe('quotaExceeded');
		expect(quota?.text.startsWith('Rate limit exceeded: ')).toBe(true);
		expect(quota?.structured).toMatchObject({ kind: 'quotaExceeded', limit: 50, remaining: 0, retryAfterMs: 5000, requested: 1 });
	});

	it('discover_brand_domains_start: a failing queue is an enqueueFailure rejection', async () => {
		const { discoverBrandDomainsStart } = await import('../src/tools/discover-brand-domains-start');
		const { getRejectedRequest } = await import('../src/tools/async-start-error-result');
		const rejected = getRejectedRequest(
			await discoverBrandDomainsStart('example.com', {}, 'p', {
				db: brandAuditDb(),
				queue: { send: vi.fn().mockRejectedValue(new Error('queue_down')) },
			} as never),
		);
		expect(rejected?.kind).toBe('enqueueFailure');
		expect(rejected?.structured).toMatchObject({ kind: 'enqueueFailure', target: 'example.com' });
	});

	it('only marked results are rejections: a poll-again notReady finding and an ordinary result are not', async () => {
		const { getRejectedRequest } = await import('../src/tools/async-start-error-result');
		const { buildCheckResult, createFinding } = await import('../src/lib/scoring');
		const notReady = buildCheckResult('brand_discovery', [
			createFinding('brand_discovery', 'Brand audit get report: notReady', 'high', 'still running', { notReady: true }),
		]);
		expect(getRejectedRequest(notReady)).toBeUndefined();
		expect(getRejectedRequest(buildCheckResult('brand_discovery', []))).toBeUndefined();
	});
});
