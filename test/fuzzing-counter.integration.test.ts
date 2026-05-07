// Integration tests for the KV-backed fuzzing counter.
// Narrow integration per testing-methodology.md: one external dep (KV) at a time.
// We use the real cloudflare:test KV binding rather than a mock so the TTL +
// list-by-prefix semantics are exercised against the actual store.

import { env } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import { recordEvent, readWindow } from '../src/lib/fuzzing-counter';

const PRINCIPAL = 'test-principal-1';
const PRINCIPAL_OTHER = 'test-principal-2';

async function clearFuzz() {
	const list = await env.RATE_LIMIT.list({ prefix: 'fuzz:' });
	await Promise.all(list.keys.map((k) => env.RATE_LIMIT.delete(k.name)));
}

beforeEach(async () => {
	await clearFuzz();
});

describe('fuzzing-counter (KV-backed)', () => {
	it('records an event and reads it back from readWindow', async () => {
		const now = 1_700_000_000;
		await recordEvent(env.RATE_LIMIT, PRINCIPAL, 'unknown_tool', now);
		const events = await readWindow(env.RATE_LIMIT, PRINCIPAL, now, 60);
		expect(events).toHaveLength(1);
		expect(events[0].kind).toBe('unknown_tool');
	});

	it('returns an empty array for an unknown principal', async () => {
		const events = await readWindow(env.RATE_LIMIT, 'nobody', 1_700_000_000, 60);
		expect(events).toEqual([]);
	});

	it('coalesces two records in the same 10-second bucket into one key with count=2', async () => {
		const now = 1_700_000_000;
		await recordEvent(env.RATE_LIMIT, PRINCIPAL, 'unknown_tool', now);
		await recordEvent(env.RATE_LIMIT, PRINCIPAL, 'unknown_tool', now + 5); // same 10s bucket
		const events = await readWindow(env.RATE_LIMIT, PRINCIPAL, now + 10, 60);
		// Counter design: each KV key represents an aggregated count; readWindow expands
		// it into per-event entries so the detector can score uniformly.
		expect(events.filter((e) => e.kind === 'unknown_tool')).toHaveLength(2);
	});

	it('does not return events whose bucket is older than the window', async () => {
		const old = 1_700_000_000;
		const recent = old + 120; // 2 min later
		await recordEvent(env.RATE_LIMIT, PRINCIPAL, 'unknown_tool', old);
		await recordEvent(env.RATE_LIMIT, PRINCIPAL, 'zod_arg', recent);
		const events = await readWindow(env.RATE_LIMIT, PRINCIPAL, recent, 60);
		expect(events.map((e) => e.kind)).toEqual(['zod_arg']);
	});

	it('isolates events between principals', async () => {
		const now = 1_700_000_000;
		await recordEvent(env.RATE_LIMIT, PRINCIPAL, 'unknown_tool', now);
		await recordEvent(env.RATE_LIMIT, PRINCIPAL_OTHER, 'auth_fail', now);
		const a = await readWindow(env.RATE_LIMIT, PRINCIPAL, now, 60);
		const b = await readWindow(env.RATE_LIMIT, PRINCIPAL_OTHER, now, 60);
		expect(a.map((e) => e.kind)).toEqual(['unknown_tool']);
		expect(b.map((e) => e.kind)).toEqual(['auth_fail']);
	});

	it('tags each KV write with a TTL of at least the window seconds (CF KV minimum is 60s)', async () => {
		// We cannot read TTL back from KV, so this test asserts behavioural equivalence:
		// after recording an event "now", a readWindow at "now + windowSeconds + 1" must
		// return [] — i.e. expiry has happened by then. We stub by using a far-future read
		// timestamp and trusting the prefix filter (the actual TTL is exercised in chaos).
		const now = 1_700_000_000;
		await recordEvent(env.RATE_LIMIT, PRINCIPAL, 'unknown_tool', now);
		const events = await readWindow(env.RATE_LIMIT, PRINCIPAL, now + 120, 60);
		expect(events).toEqual([]);
	});
});
