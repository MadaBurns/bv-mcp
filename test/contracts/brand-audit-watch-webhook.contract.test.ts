// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: brand-audit watch webhook payload shape.
 *
 * Two complementary layers:
 *   1. Schema-only contract — the Zod schema rejects any malformed payload.
 *      Per testing-methodology.md principle 3: Zod schemas ARE the inter-service
 *      contract.
 *   2. Emitter round-trip contract — the LIVE emitter path
 *      (`processBrandAuditMessage` → `deliverWatchWebhookIfShifted`) produces a
 *      payload that `BrandAuditWatchWebhookPayloadSchema.safeParse()` accepts.
 *      This locks the emitter against silent drift from the frozen C3 contract
 *      (`contracts-frozen.md §C3`) regardless of future refactors. Two cases
 *      are exercised: drift delivery (previousHash = prior hash) and first-ever
 *      delivery (previousHash = null, `added` contains the full current set).
 *
 * Downstream consumers (customer webhook receivers, bv-web G1 alert receiver)
 * parse this payload; any wire-format change requires a `schemaVersion` bump.
 */

import { describe, it, expect, vi } from 'vitest';
import {
	BrandAuditWatchWebhookPayloadSchema,
	type BrandAuditWatchWebhookPayload,
} from '../../src/schemas/brand-audit-watch-webhook';
import type { BrandAuditConsumerDeps } from '../../src/queue/brand-audit-consumer';

const validPayload: BrandAuditWatchWebhookPayload = {
	schemaVersion: 1,
	watchId: 'w-1',
	auditId: 'aud-1',
	target: 'apple.com',
	interval: 'weekly',
	detectedAt: 1_750_000_000_000,
	previousHash: 'a'.repeat(64),
	currentHash: 'b'.repeat(64),
	changes: {
		added: [{ domain: 'apple-new.com', bucket: 'consolidated' }],
		removed: [{ domain: 'apple-old.com', bucket: 'shadowIt' }],
		modified: [{ domain: 'apple-shift.com', bucket: 'consolidated', previousBucket: 'shadowIt' }],
	},
};

describe('BrandAuditWatchWebhookPayloadSchema contract', () => {
	it('accepts a well-formed payload', () => {
		const parsed = BrandAuditWatchWebhookPayloadSchema.safeParse(validPayload);
		expect(parsed.success).toBe(true);
	});

	it('accepts previousHash=null (first-ever delivery)', () => {
		const parsed = BrandAuditWatchWebhookPayloadSchema.safeParse({ ...validPayload, previousHash: null });
		expect(parsed.success).toBe(true);
	});

	it('rejects payloads missing schemaVersion (mandatory for forward-compat)', () => {
		const { schemaVersion, ...rest } = validPayload;
		void schemaVersion;
		const parsed = BrandAuditWatchWebhookPayloadSchema.safeParse(rest);
		expect(parsed.success).toBe(false);
	});

	it('rejects schemaVersion != 1 (must use new payload version when wire changes)', () => {
		const parsed = BrandAuditWatchWebhookPayloadSchema.safeParse({ ...validPayload, schemaVersion: 2 });
		expect(parsed.success).toBe(false);
	});

	it('rejects non-hex / wrong-length hash values', () => {
		const bad = BrandAuditWatchWebhookPayloadSchema.safeParse({ ...validPayload, currentHash: 'not-hex' });
		expect(bad.success).toBe(false);
		const tooShort = BrandAuditWatchWebhookPayloadSchema.safeParse({ ...validPayload, currentHash: 'a'.repeat(63) });
		expect(tooShort.success).toBe(false);
	});

	it('rejects unknown bucket values', () => {
		const bad = BrandAuditWatchWebhookPayloadSchema.safeParse({
			...validPayload,
			changes: { ...validPayload.changes, added: [{ domain: 'x.com', bucket: 'unknown' as 'consolidated' }] },
		});
		expect(bad.success).toBe(false);
	});

	it('requires all three change collections (added/removed/modified) — even if empty', () => {
		const partial = BrandAuditWatchWebhookPayloadSchema.safeParse({
			...validPayload,
			changes: { added: [], removed: [] },
		});
		expect(partial.success).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Emitter round-trip: the LIVE emitter produces schema-valid C3 payloads
//
// Motivation: the schema-only tests above confirm the Zod schema rejects
// malformed data, but they don't prove the emitter (`deliverWatchWebhookIfShifted`
// inside `processBrandAuditMessage`) actually constructs a conforming payload.
// These tests run the real emitter path end-to-end and validate its output
// against `BrandAuditWatchWebhookPayloadSchema` — locking the emitter against
// silent drift from the frozen C3 contract regardless of future refactors.
// ---------------------------------------------------------------------------

function makeEmitterD1(opts: {
	target: { status: string; completed_at: number | null };
	auditAfter: { completed_targets: number; total_targets: number };
	watch: {
		id: string;
		owner_id: string;
		domain: string;
		interval: string;
		webhook_url: string | null;
		last_classification_hash: string | null;
	};
	priorResult?: { result_json: string } | null;
}): D1Database {
	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) { binds = args; return stmt; },
				async first() {
					if (sql.includes('SELECT status, completed_at FROM brand_audit_targets')) return opts.target;
					if (sql.includes('SELECT completed_targets, total_targets FROM brand_audits')) return opts.auditAfter;
					if (sql.includes('FROM brand_audit_watches WHERE id =')) return opts.watch;
					if (sql.includes('FROM brand_audit_targets WHERE target =')) return opts.priorResult ?? null;
					void binds;
					return null;
				},
				async run() { return { success: true, meta: { changes: 1 } }; },
				async all() { return { results: [], success: true, meta: {} }; },
			};
			return stmt;
		},
	} as unknown as D1Database;
	return db;
}

function makeBrandAuditResult(domains: Array<{ domain: string; bucket: string }>) {
	return {
		category: 'brand_discovery' as const,
		passed: true,
		score: 100,
		findings: domains.map((d) => ({
			category: 'brand_discovery',
			title: `Candidate: ${d.domain}`,
			severity: 'info' as const,
			detail: '',
			metadata: { candidate: d.domain, bucket: d.bucket, signals: ['ns'], combinedConfidence: 0.9, registrar: 'X', registrarSource: 'rdap' },
		})),
	};
}

describe('emitter round-trip: processBrandAuditMessage → BrandAuditWatchWebhookPayloadSchema', () => {
	it('drift delivery (previousHash ≠ null) emits a C3-valid payload with all required fields', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');

		const currentResult = makeBrandAuditResult([
			{ domain: 'apple-new.com', bucket: 'consolidated' },
			{ domain: 'apple-shift.com', bucket: 'impersonation' },
		]);
		const priorResult = makeBrandAuditResult([
			{ domain: 'apple-old.com', bucket: 'shadowIt' },
			{ domain: 'apple-shift.com', bucket: 'consolidated' },
		]);
		const priorHash = 'a'.repeat(64); // arbitrary non-matching sentinel

		const db = makeEmitterD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-drift',
				owner_id: 'owner-1',
				domain: 'apple.com',
				interval: 'weekly',
				webhook_url: 'https://hooks.example.com/drift',
				last_classification_hash: priorHash,
			},
			priorResult: { result_json: JSON.stringify(priorResult) },
		});
		const deliverWebhook = vi.fn().mockResolvedValue(true);
		const brandAuditSingle = vi.fn().mockResolvedValue(currentResult);

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-drift', target: 'apple.com', format: 'json', watchId: 'w-drift', ownerId: 'owner-1' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, deliverWebhook } as BrandAuditConsumerDeps,
		);

		expect(verdict).toBe('ack');
		expect(deliverWebhook).toHaveBeenCalledOnce();

		const [, payload] = deliverWebhook.mock.calls[0] as [string, unknown];

		// THE LOCK: emitted payload must be a valid C3 payload.
		const parsed = BrandAuditWatchWebhookPayloadSchema.safeParse(payload);
		expect(parsed.success, `emitter produced a non-C3 payload: ${JSON.stringify((parsed as { error?: unknown }).error)}`).toBe(true);

		if (parsed.success) {
			expect(parsed.data.schemaVersion).toBe(1);
			expect(parsed.data.watchId).toBe('w-drift');
			expect(parsed.data.auditId).toBe('aud-drift');
			expect(parsed.data.target).toBe('apple.com');
			expect(parsed.data.interval).toBe('weekly');
			expect(parsed.data.detectedAt).toBe(1_750_000_000_000);
			// previousHash is the PRE-UPDATE value (priorHash sentinel), not currentHash
			expect(parsed.data.previousHash).toBe(priorHash);
			expect(typeof parsed.data.currentHash).toBe('string');
			expect(parsed.data.currentHash).toHaveLength(64);
			// changes are populated
			expect(parsed.data.changes.added.map((e) => e.domain)).toContain('apple-new.com');
			expect(parsed.data.changes.removed.map((e) => e.domain)).toContain('apple-old.com');
			expect(parsed.data.changes.modified.map((e) => e.domain)).toContain('apple-shift.com');
		}
	});

	it('first-ever delivery (previousHash = null) emits a C3-valid payload with added = full set', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');

		const currentResult = makeBrandAuditResult([
			{ domain: 'brand-x.com', bucket: 'consolidated' },
			{ domain: 'brand-x.net', bucket: 'shadowIt' },
		]);

		const db = makeEmitterD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-first',
				owner_id: 'owner-1',
				domain: 'brand-x.com',
				interval: 'daily',
				webhook_url: 'https://hooks.example.com/first',
				last_classification_hash: null, // first-ever delivery
			},
			// No priorResult row — genuinely first run.
		});
		const deliverWebhook = vi.fn().mockResolvedValue(true);
		const brandAuditSingle = vi.fn().mockResolvedValue(currentResult);

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-first', target: 'brand-x.com', format: 'json', watchId: 'w-first', ownerId: 'owner-1' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_001, deliverWebhook } as BrandAuditConsumerDeps,
		);

		expect(verdict).toBe('ack');
		expect(deliverWebhook).toHaveBeenCalledOnce();

		const [, payload] = deliverWebhook.mock.calls[0] as [string, unknown];

		// THE LOCK: first-ever delivery must also be a valid C3 payload.
		const parsed = BrandAuditWatchWebhookPayloadSchema.safeParse(payload);
		expect(parsed.success, `first-ever emitter produced a non-C3 payload: ${JSON.stringify((parsed as { error?: unknown }).error)}`).toBe(true);

		if (parsed.success) {
			expect(parsed.data.previousHash).toBeNull(); // C3: null on first-ever delivery
			// G1 invariant: on first delivery, `added` must carry the entire current candidate set.
			const addedDomains = parsed.data.changes.added.map((e) => e.domain).sort();
			expect(addedDomains).toEqual(['brand-x.com', 'brand-x.net']);
			expect(parsed.data.changes.removed).toEqual([]);
			expect(parsed.data.changes.modified).toEqual([]);
		}
	});
});
