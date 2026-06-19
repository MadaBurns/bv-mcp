// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the discover_brand_domains_start MCP tool.
 *
 * Async producer for brand-domain discovery: writes one `brand_audits` parent +
 * one `brand_audit_targets` child row, enqueues ONE `phase: 'discover_only'`
 * message, and returns `{ auditId, queuedAt, etaSeconds }`. Side effects (D1,
 * queue) are injected so tests stay offline.
 */

import { describe, it, expect, vi } from 'vitest';
import type { DiscoverBrandDomainsStartDeps } from '../src/tools/discover-brand-domains-start';

interface D1Call {
	sql: string;
	binds: unknown[];
}

function makeMockD1(opts: { throwOnRun?: boolean } = {}) {
	const calls: D1Call[] = [];
	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async run() {
					calls.push({ sql, binds });
					if (opts.throwOnRun) throw new Error('d1_run_failed');
					return { success: true, meta: { changes: 1 } };
				},
				async first() {
					calls.push({ sql, binds });
					return null;
				},
				async all() {
					calls.push({ sql, binds });
					return { results: [], success: true, meta: {} };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return { db, calls };
}

function makeDeps(overrides: Partial<DiscoverBrandDomainsStartDeps> = {}): DiscoverBrandDomainsStartDeps {
	const { db } = makeMockD1();
	return {
		db,
		queue: { send: vi.fn().mockResolvedValue(undefined) },
		generateId: () => 'disc-test-id',
		now: () => 1_750_000_000_000,
		...overrides,
	};
}

describe('discoverBrandDomainsStart', () => {
	it('writes parent + target row, enqueues one discover_only message, returns auditId', async () => {
		const { discoverBrandDomainsStart } = await import('../src/tools/discover-brand-domains-start');
		const { db, calls } = makeMockD1();
		const queueSend = vi.fn().mockResolvedValue(undefined);
		const deps = makeDeps({ db, queue: { send: queueSend } });

		const result = await discoverBrandDomainsStart(
			'brand-example.net',
			{ signals: ['san', 'ns'], depth: 'standard', min_confidence: 0.6, discovery_mode: 'classic' },
			'principal-key-hash-abc',
			deps,
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.auditId).toBe('disc-test-id');
		expect(summary?.metadata?.targetCount).toBe(1);
		expect(summary?.metadata?.queuedAt).toBe(1_750_000_000_000);
		expect(typeof summary?.metadata?.etaSeconds).toBe('number');

		// Parent + 1 child row inserted.
		const inserts = calls.filter((c) => c.sql.includes('INSERT INTO brand_audit'));
		expect(inserts.length).toBe(2);

		// Exactly one queue message carrying phase=discover_only + the discovery args.
		expect(queueSend).toHaveBeenCalledTimes(1);
		const sent = queueSend.mock.calls[0][0] as Record<string, unknown>;
		expect(sent.phase).toBe('discover_only');
		expect(sent.auditId).toBe('disc-test-id');
		expect(sent.target).toBe('brand-example.net');
		expect(sent.signals).toEqual(['san', 'ns']);
		expect(sent.min_confidence).toBe(0.6);
	});

	it('rejects an invalid seed domain without writing or enqueuing', async () => {
		const { discoverBrandDomainsStart } = await import('../src/tools/discover-brand-domains-start');
		const { db, calls } = makeMockD1();
		const queueSend = vi.fn();
		const deps = makeDeps({ db, queue: { send: queueSend } });

		const result = await discoverBrandDomainsStart('not a domain!!', {}, 'pk', deps);

		const errorFinding = result.findings.find((f) => f.metadata?.invalidInput === true);
		expect(errorFinding).toBeDefined();
		expect(errorFinding?.severity).toBe('high');
		expect(calls.length).toBe(0);
		expect(queueSend).not.toHaveBeenCalled();
	});

	it('flips the audit to failed and surfaces enqueueFailure when queue.send throws', async () => {
		const { discoverBrandDomainsStart } = await import('../src/tools/discover-brand-domains-start');
		const { db, calls } = makeMockD1();
		const queueSend = vi.fn().mockRejectedValue(new Error('queue_unavailable'));
		const deps = makeDeps({ db, queue: { send: queueSend } });

		const result = await discoverBrandDomainsStart('brand-example.net', {}, 'pk', deps);

		const errorFinding = result.findings.find((f) => f.metadata?.enqueueFailure === true);
		expect(errorFinding).toBeDefined();
		// Best-effort UPDATE brand_audits ... status='failed' fired.
		expect(calls.some((c) => c.sql.includes("status = 'failed'"))).toBe(true);
	});
});
