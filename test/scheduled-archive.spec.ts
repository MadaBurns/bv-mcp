// test/scheduled-archive.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 1 — decision #3: archive-then-delete for the retention cron.
//
// Contract (DARK behind the ANALYTICS_ARCHIVE_ENABLED flag + the optional
// MCP_ACCESS_LOG_ARCHIVE R2 binding, both new on ScheduledEnv):
//   - flag ON + binding present → before issuing the retention DELETE, write a
//     gzipped NDJSON object of the expiring rows to R2, with PII columns
//     EXCLUDED from the payload. The R2 put MUST precede the DELETE.
//   - flag OFF, OR binding absent → only DELETE runs; R2 is never touched
//     (byte-for-byte today's behavior).
//
// Written BEFORE the implementation: the "ON" case is expected to FAIL until the
// archive step lands (today handleScheduled only DELETEs). The OFF / absent
// cases lock the dark default and should stay green throughout.

import { afterEach, describe, expect, it, vi } from 'vitest';

/** Columns that must NEVER appear in an archived NDJSON record (PII-gated set). */
const PII_COLUMNS = ['ip_ciphertext', 'ip_key_version', 'ptr_hostname', 'city', 'latitude', 'longitude', 'user_agent'];

/** A representative expiring row carrying both PII and non-PII columns. */
function expiringRow() {
	return {
		id: 1,
		created_at: 1,
		ip_hash: 'i_abc',
		ip_masked: '203.0.113.xxx',
		tool_name: 'check_spf',
		domain: 'example.com',
		country: 'NZ',
		region: 'AKL',
		asn: 13335,
		as_org: 'Cloudflare',
		colo: 'AKL',
		source: 'public',
		status: 'pass',
		method: 'tools/call',
		transport: 'json',
		// PII — must be stripped from the archive payload:
		ip_ciphertext: 'v1:deadbeef',
		ip_key_version: 'v1',
		ptr_hostname: 'host.example.net',
		city: 'Auckland',
		latitude: '-36.8',
		longitude: '174.7',
		user_agent: 'curl/8.0',
	};
}

/** D1 fake: SELECT (.all) returns rows + logs 'select'; DELETE (.run) logs 'delete'. */
function fakeIntelDb(rows: unknown[], timeline: string[]) {
	const all = vi.fn(async () => {
		timeline.push('select');
		return { results: rows, success: true };
	});
	const run = vi.fn(async () => {
		timeline.push('delete');
		return { success: true };
	});
	const stmt: { bind: ReturnType<typeof vi.fn>; all: typeof all; run: typeof run } = {
		bind: vi.fn(() => stmt),
		all,
		run,
	};
	const prepare = vi.fn(() => stmt);
	return { db: { prepare } as unknown as D1Database, prepare, all, run };
}

/** R2 fake with a put() spy that captures the object body for later inspection. */
function fakeArchive(timeline: string[]) {
	const bodies: { key: string; value: unknown }[] = [];
	const put = vi.fn(async (key: string, value: unknown) => {
		timeline.push('put');
		bodies.push({ key, value });
		return { key } as unknown as R2Object;
	});
	return { binding: { put } as unknown as R2Bucket, put, bodies };
}

/** Gunzip whatever shape the put() body takes back into UTF-8 text (proves gzip). */
async function gunzipToText(body: unknown): Promise<string> {
	let stream: ReadableStream<Uint8Array>;
	if (body instanceof ReadableStream) {
		stream = body as ReadableStream<Uint8Array>;
	} else if (body instanceof Uint8Array) {
		stream = new Response(body).body as ReadableStream<Uint8Array>;
	} else if (body instanceof ArrayBuffer) {
		stream = new Response(new Uint8Array(body)).body as ReadableStream<Uint8Array>;
	} else {
		stream = new Response(body as BodyInit).body as ReadableStream<Uint8Array>;
	}
	const decompressed = stream.pipeThrough(new DecompressionStream('gzip'));
	return await new Response(decompressed).text();
}

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('access-log archive-then-delete (decision #3)', () => {
	it('flag ON + binding present → writes a gzipped NDJSON object before DELETE', async () => {
		const timeline: string[] = [];
		const intel = fakeIntelDb([expiringRow()], timeline);
		const archive = fakeArchive(timeline);
		const env = {
			INTELLIGENCE_DB: intel.db,
			MCP_ACCESS_LOG_ARCHIVE: archive.binding,
			ANALYTICS_ARCHIVE_ENABLED: 'true',
			ANALYTICS_RETENTION_DAYS: '90',
		} as unknown as import('../src/scheduled').ScheduledEnv;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(env);

		// Archive happened exactly once, and BEFORE the DELETE.
		expect(archive.put).toHaveBeenCalledTimes(1);
		expect(intel.run).toHaveBeenCalled();
		expect(timeline.indexOf('put')).toBeGreaterThanOrEqual(0);
		expect(timeline.indexOf('put')).toBeLessThan(timeline.indexOf('delete'));

		// Object key is a gzipped artefact.
		const { key } = archive.bodies[0];
		expect(typeof key).toBe('string');
		expect(key).toMatch(/\.gz$/i);
	});

	it('archived payload is NDJSON with PII columns EXCLUDED', async () => {
		const timeline: string[] = [];
		const intel = fakeIntelDb([expiringRow()], timeline);
		const archive = fakeArchive(timeline);
		const env = {
			INTELLIGENCE_DB: intel.db,
			MCP_ACCESS_LOG_ARCHIVE: archive.binding,
			ANALYTICS_ARCHIVE_ENABLED: 'true',
			ANALYTICS_RETENTION_DAYS: '90',
		} as unknown as import('../src/scheduled').ScheduledEnv;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(env);

		expect(archive.put).toHaveBeenCalledTimes(1);
		const text = await gunzipToText(archive.bodies[0].value);

		// NDJSON: one JSON object per non-empty line.
		const lines = text.split('\n').filter((l) => l.trim().length > 0);
		expect(lines.length).toBe(1);
		const record = JSON.parse(lines[0]) as Record<string, unknown>;

		// Non-PII columns are retained …
		expect(record.tool_name).toBe('check_spf');
		expect(record.source).toBe('public');
		expect(record.country).toBe('NZ');

		// … and every PII column is stripped.
		for (const col of PII_COLUMNS) {
			expect(record).not.toHaveProperty(col);
		}
	});

	it('flag OFF → only DELETE runs, R2 never called (dark default)', async () => {
		const timeline: string[] = [];
		const intel = fakeIntelDb([expiringRow()], timeline);
		const archive = fakeArchive(timeline);
		const env = {
			INTELLIGENCE_DB: intel.db,
			MCP_ACCESS_LOG_ARCHIVE: archive.binding,
			// ANALYTICS_ARCHIVE_ENABLED intentionally unset
			ANALYTICS_RETENTION_DAYS: '90',
		} as unknown as import('../src/scheduled').ScheduledEnv;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(env);

		expect(archive.put).not.toHaveBeenCalled();
		expect(intel.run).toHaveBeenCalled();
		expect(timeline).toContain('delete');
		expect(timeline).not.toContain('put');
	});

	it('flag ON but binding absent → only DELETE runs, no R2 call', async () => {
		const timeline: string[] = [];
		const intel = fakeIntelDb([expiringRow()], timeline);
		const env = {
			INTELLIGENCE_DB: intel.db,
			// MCP_ACCESS_LOG_ARCHIVE intentionally absent
			ANALYTICS_ARCHIVE_ENABLED: 'true',
			ANALYTICS_RETENTION_DAYS: '90',
		} as unknown as import('../src/scheduled').ScheduledEnv;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(env);

		expect(intel.run).toHaveBeenCalled();
		expect(timeline).toContain('delete');
		expect(timeline).not.toContain('put');
	});
});

/**
 * S1 — TOCTOU boundary: the archive SELECT and the retention DELETE must bind the
 * SAME JS-computed cutoff literal, and neither may re-evaluate strftime('now').
 *
 * Capturing D1 fake: records each prepared statement's SQL + every bind() arg list.
 */
function capturingIntelDb(rows: unknown[]) {
	const statements: { sql: string; bindArgs: unknown[][] }[] = [];
	const prepare = vi.fn((sql: string) => {
		const rec = { sql, bindArgs: [] as unknown[][] };
		statements.push(rec);
		const stmt: Record<string, unknown> = {
			bind: vi.fn((...args: unknown[]) => {
				rec.bindArgs.push(args);
				return stmt;
			}),
			all: vi.fn(async () => ({ results: rows, success: true })),
			run: vi.fn(async () => ({ success: true })),
		};
		return stmt;
	});
	return { db: { prepare } as unknown as D1Database, statements };
}

describe('access-log retention TOCTOU boundary (S1)', () => {
	it('binds the SAME cutoff literal to both the archive SELECT and the DELETE', async () => {
		const intel = capturingIntelDb([expiringRow()]);
		const archive = fakeArchive([]);
		const env = {
			INTELLIGENCE_DB: intel.db,
			MCP_ACCESS_LOG_ARCHIVE: archive.binding,
			ANALYTICS_ARCHIVE_ENABLED: 'true',
			ANALYTICS_RETENTION_DAYS: '90',
		} as unknown as import('../src/scheduled').ScheduledEnv;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(env);

		const select = intel.statements.find((s) => /SELECT/i.test(s.sql) && /mcp_access_log/.test(s.sql));
		const del = intel.statements.find((s) => /DELETE FROM mcp_access_log/i.test(s.sql));
		expect(select).toBeDefined();
		expect(del).toBeDefined();

		// Same single literal reaches both — the SELECT binds (cutoff, lastId, pageSize),
		// the DELETE binds (cutoff). The first arg of each must be identical.
		const selectCutoff = select!.bindArgs[0][0];
		const deleteCutoff = del!.bindArgs[0][0];
		expect(typeof selectCutoff).toBe('number');
		expect(deleteCutoff).toBe(selectCutoff);

		// Neither statement re-derives the boundary from wall-clock SQL.
		expect(select!.sql).not.toMatch(/strftime/i);
		expect(del!.sql).not.toMatch(/strftime/i);
	});
});

describe('access-log archive idempotency (S3)', () => {
	it('two runs over the same retention window produce the same R2 key', async () => {
		// Fix the day, vary the wall-clock instant by a few seconds. The old per-run
		// ISO-timestamp key would differ across the two; a window-bucket key is stable.
		const base = Date.UTC(2026, 5, 28, 12, 0, 0); // mid-day, well clear of a UTC boundary
		const nowSpy = vi.spyOn(Date, 'now');

		const { handleScheduled } = await import('../src/scheduled');

		const makeEnv = (archiveBinding: R2Bucket) =>
			({
				INTELLIGENCE_DB: fakeIntelDb([expiringRow()], []).db,
				MCP_ACCESS_LOG_ARCHIVE: archiveBinding,
				ANALYTICS_ARCHIVE_ENABLED: 'true',
				ANALYTICS_RETENTION_DAYS: '90',
			}) as unknown as import('../src/scheduled').ScheduledEnv;

		nowSpy.mockReturnValue(base);
		const archive1 = fakeArchive([]);
		await handleScheduled(makeEnv(archive1.binding));

		nowSpy.mockReturnValue(base + 5_000); // 5s later, same retention window
		const archive2 = fakeArchive([]);
		await handleScheduled(makeEnv(archive2.binding));

		expect(archive1.bodies.length).toBe(1);
		expect(archive2.bodies.length).toBe(1);
		expect(archive2.bodies[0].key).toBe(archive1.bodies[0].key);
	});
});

describe('scan_rollup prune (S2)', () => {
	it('prunes scan_rollup older than the retention window when SCAN_SCHEDULE_DB is bound', async () => {
		const base = Date.UTC(2026, 5, 28, 12, 0, 0);
		vi.spyOn(Date, 'now').mockReturnValue(base);

		const scan = capturingIntelDb([]);
		const env = {
			SCAN_SCHEDULE_DB: scan.db,
			ANALYTICS_RETENTION_DAYS: '90',
		} as unknown as import('../src/scheduled').ScheduledEnv;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(env);

		const prune = scan.statements.find((s) => /DELETE FROM scan_rollup/i.test(s.sql));
		expect(prune).toBeDefined();
		expect(prune!.sql).toMatch(/bucket_day < \?/);

		const expectedCutoff = Math.floor((base - 90 * 86_400_000) / 86_400_000);
		expect(prune!.bindArgs[0][0]).toBe(expectedCutoff);
	});

	it('does NOT touch scan_rollup when SCAN_SCHEDULE_DB is absent (dark default)', async () => {
		const scan = capturingIntelDb([]); // spy exists but is NOT wired onto env
		const env = {
			INTELLIGENCE_DB: fakeIntelDb([expiringRow()], []).db,
			ANALYTICS_RETENTION_DAYS: '90',
		} as unknown as import('../src/scheduled').ScheduledEnv;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(env);

		expect((scan.db as unknown as { prepare: ReturnType<typeof vi.fn> }).prepare).not.toHaveBeenCalled();
	});
});
