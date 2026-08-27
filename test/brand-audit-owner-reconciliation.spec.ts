// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';

import { adoptAnonymousBrandAuditWatchInternal, reconcileLegacyBrandAuditOwner } from '../src/lib/brand-audit-owner-reconciliation';
import { computeClassificationHash } from '../src/lib/brand-audit-classification-diff';
import type { CheckResult } from '../src/lib/scoring';

interface CapturedStatement {
	sql: string;
	values: unknown[];
}

function makeDb(options: { fail?: Error } = {}) {
	const captured: CapturedStatement[] = [];
	const rows = {
		audits: new Map<string, string>([
			['audit-old', '0123456789abcdef'],
			['audit-other', 'fedcba9876543210'],
		]),
		watches: new Map<string, string>([
			['watch-old', '0123456789abcdef'],
			['watch-other', 'fedcba9876543210'],
		]),
	};

	const prepare = vi.fn((sql: string) => ({
		bind: (...values: unknown[]) => ({ sql, values }),
	}));
	const batch = vi.fn(async (statements: CapturedStatement[]) => {
		captured.push(...statements);
		if (options.fail) throw options.fail;

		return statements.map((statement) => {
			const [nextOwner, oldOwner] = statement.values as [string, string];
			const table = statement.sql.includes('brand_audit_watches') ? rows.watches : rows.audits;
			let changes = 0;
			for (const [id, owner] of table) {
				if (owner !== oldOwner) continue;
				table.set(id, nextOwner);
				changes += 1;
			}
			return { success: true, meta: { changes }, results: [] };
		});
	});

	return {
		db: { prepare, batch } as unknown as D1Database,
		prepare,
		batch,
		captured,
		rows,
	};
}

const CANONICAL_OWNER = 'a'.repeat(64);

describe('reconcileLegacyBrandAuditOwner', () => {
	it('atomically moves only matching audit and watch rows to the canonical owner', async () => {
		const { db, batch, captured, rows } = makeDb();

		await expect(reconcileLegacyBrandAuditOwner(db, '0123456789abcdef', CANONICAL_OWNER)).resolves.toEqual({ attempted: true });

		expect(batch).toHaveBeenCalledTimes(1);
		expect(captured).toHaveLength(2);
		expect(captured[0]).toEqual({
			sql: 'UPDATE brand_audits SET owner_id = ? WHERE owner_id = ?',
			values: [CANONICAL_OWNER, '0123456789abcdef'],
		});
		expect(captured[1]).toEqual({
			sql: 'UPDATE brand_audit_watches SET owner_id = ? WHERE owner_id = ?',
			values: [CANONICAL_OWNER, '0123456789abcdef'],
		});
		expect(rows.audits.get('audit-old')).toBe(CANONICAL_OWNER);
		expect(rows.watches.get('watch-old')).toBe(CANONICAL_OWNER);
		expect(rows.audits.get('audit-other')).toBe('fedcba9876543210');
		expect(rows.watches.get('watch-other')).toBe('fedcba9876543210');
	});

	it('is idempotent when the same reconciliation is retried', async () => {
		const { db, rows } = makeDb();

		await reconcileLegacyBrandAuditOwner(db, '0123456789abcdef', CANONICAL_OWNER);
		await reconcileLegacyBrandAuditOwner(db, '0123456789abcdef', CANONICAL_OWNER);

		expect(rows.audits.get('audit-old')).toBe(CANONICAL_OWNER);
		expect(rows.watches.get('watch-old')).toBe(CANONICAL_OWNER);
	});

	it('atomically reconciles an exact validated legacy internal tenant owner', async () => {
		const { db, captured, rows } = makeDb();
		rows.audits.set('audit-tenant', 'tenant:Acme_customer-1');
		rows.watches.set('watch-tenant', 'tenant:Acme_customer-1');

		await expect(reconcileLegacyBrandAuditOwner(db, 'tenant:Acme_customer-1', CANONICAL_OWNER)).resolves.toEqual({ attempted: true });

		expect(captured).toHaveLength(2);
		expect(captured.every((statement) => statement.values[1] === 'tenant:Acme_customer-1')).toBe(true);
		expect(rows.audits.get('audit-tenant')).toBe(CANONICAL_OWNER);
		expect(rows.watches.get('watch-tenant')).toBe(CANONICAL_OWNER);
	});

	it.each([null, undefined])('does nothing when the legacy owner is absent (%s)', async (legacyOwnerId) => {
		const { db, prepare, batch } = makeDb();

		await expect(reconcileLegacyBrandAuditOwner(db, legacyOwnerId, CANONICAL_OWNER)).resolves.toEqual({ attempted: false });
		expect(prepare).not.toHaveBeenCalled();
		expect(batch).not.toHaveBeenCalled();
	});

	it('does nothing when the owner is already canonical', async () => {
		const { db, prepare, batch } = makeDb();

		await expect(reconcileLegacyBrandAuditOwner(db, CANONICAL_OWNER, CANONICAL_OWNER)).resolves.toEqual({ attempted: false });
		expect(prepare).not.toHaveBeenCalled();
		expect(batch).not.toHaveBeenCalled();
	});

	it.each([
		['short canonical owner', 'a'.repeat(63), '0123456789abcdef'],
		['uppercase canonical owner', 'A'.repeat(64), '0123456789abcdef'],
		['non-hex canonical owner', 'g'.repeat(64), '0123456789abcdef'],
		['short legacy owner', CANONICAL_OWNER, '0123456789abcde'],
		['uppercase legacy owner', CANONICAL_OWNER, '0123456789abcdeF'],
		['different canonical owner as legacy input', CANONICAL_OWNER, 'b'.repeat(64)],
		['empty tenant owner', CANONICAL_OWNER, 'tenant:'],
		['tenant owner with unsafe punctuation', CANONICAL_OWNER, 'tenant:acme.example'],
		['tenant owner longer than 128 characters', CANONICAL_OWNER, `tenant:a${'b'.repeat(128)}`],
	])('rejects a %s before touching D1', async (_label, canonicalOwner, legacyOwner) => {
		const { db, prepare, batch } = makeDb();

		await expect(reconcileLegacyBrandAuditOwner(db, legacyOwner, canonicalOwner)).rejects.toThrow(/Invalid/);
		expect(prepare).not.toHaveBeenCalled();
		expect(batch).not.toHaveBeenCalled();
	});

	it('propagates a transactional D1 failure before a caller can continue', async () => {
		const failure = new Error('D1 unavailable');
		const { db, batch } = makeDb({ fail: failure });
		const ownerScopedOperation = vi.fn();

		await expect(
			(async () => {
				await reconcileLegacyBrandAuditOwner(db, '0123456789abcdef', CANONICAL_OWNER);
				ownerScopedOperation();
			})(),
		).rejects.toBe(failure);

		expect(batch).toHaveBeenCalledTimes(1);
		expect(ownerScopedOperation).not.toHaveBeenCalled();
	});

	it('rejects an incomplete batch result instead of continuing', async () => {
		const { db, batch } = makeDb();
		batch.mockResolvedValueOnce([{ success: true, meta: { changes: 1 }, results: [] }]);

		await expect(reconcileLegacyBrandAuditOwner(db, '0123456789abcdef', CANONICAL_OWNER)).rejects.toThrow(
			'Brand-audit owner reconciliation failed',
		);
	});
});

interface AnonymousWatch {
	id: string;
	owner_id: string;
	active: number;
	webhook_url: string | null;
	domain?: string;
	last_classification_hash?: string | null;
	last_classification_result_json?: string | null;
	pending_webhook_json?: string | null;
}

async function tokenFingerprint(token: string): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
	return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function makeAnonymousWatchDb(
	initialRows: AnonymousWatch[],
	options: { raceBeforeUpdate?: boolean; historyResults?: Array<{ result_json: string | null }> } = {},
) {
	const rows = initialRows.map((row) => ({
		...row,
		domain: row.domain ?? 'example.com',
		last_classification_hash: row.last_classification_hash ?? null,
		last_classification_result_json: row.last_classification_result_json ?? null,
		pending_webhook_json: row.pending_webhook_json ?? null,
	}));
	const calls: CapturedStatement[] = [];
	const prepare = vi.fn((sql: string) => ({
		bind: (...values: unknown[]) => {
			const statement = {
				async all<T>() {
					calls.push({ sql, values });
					if (sql.includes('FROM brand_audit_targets')) {
						return { success: true, results: (options.historyResults ?? []) as T[], meta: {} };
					}
					const requestedId = sql.includes('AND id = ?') ? String(values[0]) : undefined;
					const limit = Number(values[values.length - 1]);
					const results = rows
						.filter((row) => row.owner_id === 'anonymous' && row.active === 1 && (!requestedId || row.id === requestedId))
						.slice(0, limit)
						.map((row) => ({
							id: row.id,
							webhook_url: row.webhook_url,
							domain: row.domain,
							last_classification_hash: row.last_classification_hash,
							last_classification_result_json: row.last_classification_result_json,
							pending_webhook_json: row.pending_webhook_json,
						})) as T[];
					return { success: true, results, meta: {} };
				},
				async run() {
					calls.push({ sql, values });
					if (options.raceBeforeUpdate) {
						const raced = rows.find((row) => row.id === values[2]);
						if (raced) raced.owner_id = 'c'.repeat(64);
					}
					let changes = 0;
					for (const row of rows) {
						if (
							row.id !== values[2] ||
							row.owner_id !== 'anonymous' ||
							row.active !== 1 ||
							row.webhook_url !== values[3] ||
							row.domain !== values[4] ||
							row.last_classification_hash !== values[5] ||
							row.last_classification_result_json !== values[6] ||
							row.pending_webhook_json !== values[7]
						)
							continue;
						row.owner_id = String(values[0]);
						row.last_classification_result_json = values[1] as string | null;
						changes += 1;
					}
					return { success: true, results: [], meta: { changes } };
				},
			};
			return statement;
		},
	}));

	return { db: { prepare } as unknown as D1Database, rows, calls };
}

const CALLBACK_TOKEN = 'callback_token_with_enough_entropy_1234567890';

describe('adoptAnonymousBrandAuditWatchInternal', () => {
	it('adopts the sole anonymous active watch matching the trusted fingerprint', async () => {
		const fingerprint = await tokenFingerprint(CALLBACK_TOKEN);
		const { db, rows, calls } = makeAnonymousWatchDb([
			{
				id: 'watch-1',
				owner_id: 'anonymous',
				active: 1,
				webhook_url: `https://hooks.example.test/brand?t=${CALLBACK_TOKEN}`,
			},
			{
				id: 'watch-owned',
				owner_id: 'b'.repeat(64),
				active: 1,
				webhook_url: `https://hooks.example.test/brand?t=${CALLBACK_TOKEN}`,
			},
			{
				id: 'watch-inactive',
				owner_id: 'anonymous',
				active: 0,
				webhook_url: `https://hooks.example.test/brand?t=${CALLBACK_TOKEN}`,
			},
		]);

		await expect(
			adoptAnonymousBrandAuditWatchInternal(db, {
				canonicalOwnerId: CANONICAL_OWNER,
				webhookTokenFingerprint: fingerprint,
			}),
		).resolves.toEqual({ status: 'reconciled', watchId: 'watch-1' });

		expect(rows[0].owner_id).toBe(CANONICAL_OWNER);
		expect(rows[1].owner_id).toBe('b'.repeat(64));
		expect(rows[2].owner_id).toBe('anonymous');
		expect(calls[0].sql).toContain("owner_id = 'anonymous'");
		expect(calls[1]).toEqual({
			sql: "UPDATE brand_audit_watches SET owner_id = ?, last_classification_result_json = ? WHERE id = ? AND owner_id = 'anonymous' AND active = 1 AND webhook_url = ? AND domain = ? AND last_classification_hash IS ? AND last_classification_result_json IS ? AND pending_webhook_json IS ?",
			values: [CANONICAL_OWNER, null, 'watch-1', `https://hooks.example.test/brand?t=${CALLBACK_TOKEN}`, 'example.com', null, null, null],
		});
	});

	it('persists the exact anonymous baseline for the first post-adoption drift even when the parent audit is stale', async () => {
		const fingerprint = await tokenFingerprint(CALLBACK_TOKEN);
		const baseline: CheckResult = {
			category: 'brand_discovery',
			passed: true,
			score: 100,
			findings: [
				{
					category: 'brand_discovery',
					title: 'Candidate: old.example',
					severity: 'info',
					detail: '',
					metadata: { candidate: 'old.example', bucket: 'shadowIt' },
				},
			],
		};
		const baselineJson = JSON.stringify(baseline);
		const baselineHash = await computeClassificationHash(baseline);
		const { db, rows, calls } = makeAnonymousWatchDb(
			[
				{
					id: 'watch-adopted',
					owner_id: 'anonymous',
					active: 1,
					webhook_url: `https://hooks.example.test/brand?t=${CALLBACK_TOKEN}`,
					domain: 'example.com',
					last_classification_hash: baselineHash,
					last_classification_result_json: null,
				},
			],
			{ historyResults: [{ result_json: JSON.stringify({ ...baseline, findings: [] }) }, { result_json: baselineJson }] },
		);

		await expect(
			adoptAnonymousBrandAuditWatchInternal(db, {
				canonicalOwnerId: CANONICAL_OWNER,
				webhookTokenFingerprint: fingerprint,
			}),
		).resolves.toEqual({ status: 'reconciled', watchId: 'watch-adopted' });

		expect(rows[0].owner_id).toBe(CANONICAL_OWNER);
		expect(rows[0].last_classification_result_json).toBe(baselineJson);
		const historyLookup = calls.find((call) => call.sql.includes('FROM brand_audit_targets'));
		expect(historyLookup?.sql).toContain("a.owner_id = 'anonymous'");
		expect(historyLookup?.sql).toContain("t.status = 'completed'");
		expect(historyLookup?.sql).not.toContain('a.status');
	});

	it('fails adoption closed when a persisted hash has no exact anonymous baseline', async () => {
		const fingerprint = await tokenFingerprint(CALLBACK_TOKEN);
		const { db, rows, calls } = makeAnonymousWatchDb([
			{
				id: 'watch-missing-baseline',
				owner_id: 'anonymous',
				active: 1,
				webhook_url: `https://hooks.example.test/brand?t=${CALLBACK_TOKEN}`,
				domain: 'example.com',
				last_classification_hash: 'e'.repeat(64),
				last_classification_result_json: null,
			},
		]);

		await expect(
			adoptAnonymousBrandAuditWatchInternal(db, {
				canonicalOwnerId: CANONICAL_OWNER,
				webhookTokenFingerprint: fingerprint,
			}),
		).rejects.toThrow(/baseline recovery failed/);

		expect(rows[0].owner_id).toBe('anonymous');
		expect(calls.some((call) => call.sql.startsWith('UPDATE brand_audit_watches'))).toBe(false);
	});

	it('returns no_match for a wrong fingerprint without mutating a watch', async () => {
		const { db, rows, calls } = makeAnonymousWatchDb([
			{
				id: 'watch-1',
				owner_id: 'anonymous',
				active: 1,
				webhook_url: `https://hooks.example.test/brand?t=${CALLBACK_TOKEN}`,
			},
		]);

		await expect(
			adoptAnonymousBrandAuditWatchInternal(db, {
				canonicalOwnerId: CANONICAL_OWNER,
				webhookTokenFingerprint: 'd'.repeat(64),
			}),
		).resolves.toEqual({ status: 'no_match' });
		expect(rows[0].owner_id).toBe('anonymous');
		expect(calls).toHaveLength(1);
	});

	it('does not fingerprint a low-entropy URL token', async () => {
		const lowEntropyToken = 'guessable';
		const { db, rows, calls } = makeAnonymousWatchDb([
			{
				id: 'watch-1',
				owner_id: 'anonymous',
				active: 1,
				webhook_url: `https://hooks.example.test/brand?t=${lowEntropyToken}`,
			},
		]);

		await expect(
			adoptAnonymousBrandAuditWatchInternal(db, {
				canonicalOwnerId: CANONICAL_OWNER,
				webhookTokenFingerprint: await tokenFingerprint(lowEntropyToken),
			}),
		).resolves.toEqual({ status: 'no_match' });
		expect(rows[0].owner_id).toBe('anonymous');
		expect(calls).toHaveLength(1);
	});

	it('returns ambiguous when multiple anonymous watches share the fingerprint', async () => {
		const fingerprint = await tokenFingerprint(CALLBACK_TOKEN);
		const { db, rows, calls } = makeAnonymousWatchDb(
			['watch-1', 'watch-2'].map((id) => ({
				id,
				owner_id: 'anonymous',
				active: 1,
				webhook_url: `https://hooks.example.test/brand?t=${CALLBACK_TOKEN}`,
			})),
		);

		await expect(
			adoptAnonymousBrandAuditWatchInternal(db, {
				canonicalOwnerId: CANONICAL_OWNER,
				webhookTokenFingerprint: fingerprint,
			}),
		).resolves.toEqual({ status: 'ambiguous' });
		expect(rows.every((row) => row.owner_id === 'anonymous')).toBe(true);
		expect(calls).toHaveLength(1);
	});

	it('uses an exact watch ID to resolve an otherwise ambiguous fingerprint', async () => {
		const fingerprint = await tokenFingerprint(CALLBACK_TOKEN);
		const { db, rows, calls } = makeAnonymousWatchDb(
			['watch-1', 'watch-2'].map((id) => ({
				id,
				owner_id: 'anonymous',
				active: 1,
				webhook_url: `https://hooks.example.test/brand?t=${CALLBACK_TOKEN}`,
			})),
		);

		await expect(
			adoptAnonymousBrandAuditWatchInternal(db, {
				canonicalOwnerId: CANONICAL_OWNER,
				webhookTokenFingerprint: fingerprint,
				watchId: 'watch-2',
			}),
		).resolves.toEqual({ status: 'reconciled', watchId: 'watch-2' });
		expect(rows[0].owner_id).toBe('anonymous');
		expect(rows[1].owner_id).toBe(CANONICAL_OWNER);
		expect(calls[0].values[0]).toBe('watch-2');
	});

	it('fails closed when the bounded anonymous candidate set overflows', async () => {
		const fingerprint = await tokenFingerprint(CALLBACK_TOKEN);
		const { db, calls } = makeAnonymousWatchDb(
			Array.from({ length: 201 }, (_, index) => ({
				id: `watch-${index}`,
				owner_id: 'anonymous',
				active: 1,
				webhook_url: `https://hooks.example.test/brand?t=${CALLBACK_TOKEN}-${index}`,
			})),
		);

		await expect(
			adoptAnonymousBrandAuditWatchInternal(db, {
				canonicalOwnerId: CANONICAL_OWNER,
				webhookTokenFingerprint: fingerprint,
			}),
		).rejects.toThrow('candidate limit exceeded');
		expect(calls).toHaveLength(1);
	});

	it('loses a conditional-update race without claiming another owner watch', async () => {
		const fingerprint = await tokenFingerprint(CALLBACK_TOKEN);
		const { db, rows } = makeAnonymousWatchDb(
			[
				{
					id: 'watch-1',
					owner_id: 'anonymous',
					active: 1,
					webhook_url: `https://hooks.example.test/brand?t=${CALLBACK_TOKEN}`,
				},
			],
			{ raceBeforeUpdate: true },
		);

		await expect(
			adoptAnonymousBrandAuditWatchInternal(db, {
				canonicalOwnerId: CANONICAL_OWNER,
				webhookTokenFingerprint: fingerprint,
			}),
		).resolves.toEqual({ status: 'no_match' });
		expect(rows[0].owner_id).toBe('c'.repeat(64));
	});

	it.each([
		['canonical owner', 'A'.repeat(64), 'b'.repeat(64), undefined],
		['fingerprint', CANONICAL_OWNER, 'g'.repeat(64), undefined],
		['watch ID', CANONICAL_OWNER, 'b'.repeat(64), '../watch'],
	])('rejects an invalid %s before querying D1', async (_label, canonicalOwnerId, webhookTokenFingerprint, watchId) => {
		const { db, calls } = makeAnonymousWatchDb([]);
		await expect(adoptAnonymousBrandAuditWatchInternal(db, { canonicalOwnerId, webhookTokenFingerprint, watchId })).rejects.toThrow(
			'Invalid',
		);
		expect(calls).toHaveLength(0);
	});
});
