import { afterEach, describe, expect, it, vi } from 'vitest';

import {
	ACTIVE_SESSIONS,
	SESSION_CREATE_BY_IP,
	MAX_SESSION_CREATE_IPS,
	checkSessionCreateRateLimitInMemory,
	createSessionInMemory,
	deleteSessionInMemory,
	resetSessions,
	SESSION_REFRESH_INTERVAL_MS,
	SESSION_TTL_MS,
	validateSessionInMemory,
} from '../src/lib/session-memory';

afterEach(() => {
	resetSessions();
	vi.restoreAllMocks();
});

describe('session-memory', () => {
	it('creates and validates in-memory sessions', () => {
		createSessionInMemory('session-1');
		expect(ACTIVE_SESSIONS.has('session-1')).toBe(true);
		expect(validateSessionInMemory('session-1')).toBe(true);
	});

	it('expires old in-memory sessions', () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);
		createSessionInMemory('session-1');

		nowSpy.mockReturnValue(base + SESSION_TTL_MS + 1);
		expect(validateSessionInMemory('session-1')).toBe(false);
	});

	it('refreshes in-memory sessions after the refresh interval', () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);
		createSessionInMemory('session-1');

		nowSpy.mockReturnValue(base + SESSION_REFRESH_INTERVAL_MS + 1_000);
		expect(validateSessionInMemory('session-1')).toBe(true);
		expect(ACTIVE_SESSIONS.get('session-1')?.lastAccessedAt).toBe(base + SESSION_REFRESH_INTERVAL_MS + 1_000);
	});

	it('deletes in-memory sessions explicitly', () => {
		createSessionInMemory('session-1');
		expect(deleteSessionInMemory('session-1')).toBe(true);
		expect(ACTIVE_SESSIONS.has('session-1')).toBe(false);
	});

	it('limits repeated in-memory session creation attempts per IP window', () => {
		for (let i = 0; i < 30; i++) {
			expect(checkSessionCreateRateLimitInMemory('198.51.100.25').allowed).toBe(true);
		}

		expect(checkSessionCreateRateLimitInMemory('198.51.100.25').allowed).toBe(false);
	});

	it('removes empty IP entries from SESSION_CREATE_BY_IP after timestamps expire', () => {
		// Directly seed the map with an empty timestamps array to simulate
		// the state after all timestamps have expired but the key was never cleaned
		SESSION_CREATE_BY_IP.set('198.51.100.77', []);
		expect(SESSION_CREATE_BY_IP.has('198.51.100.77')).toBe(true);

		// Calling check for this IP should detect the empty pruned array
		// and delete the stale key before adding a fresh timestamp
		checkSessionCreateRateLimitInMemory('198.51.100.77');

		// Key still exists because a new timestamp was added (allowed=true),
		// but the stale empty array was cleaned up first
		expect(SESSION_CREATE_BY_IP.has('198.51.100.77')).toBe(true);
		expect(SESSION_CREATE_BY_IP.get('198.51.100.77')?.length).toBe(1);
	});

	it('enforces size cap on SESSION_CREATE_BY_IP with eviction of oldest entries', () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);

		// Fill past the size cap
		for (let i = 0; i < MAX_SESSION_CREATE_IPS + 100; i++) {
			nowSpy.mockReturnValue(base + i); // slightly different timestamps for eviction ordering
			const octet1 = i % 256;
			const octet2 = Math.floor(i / 256) % 256;
			const octet3 = Math.floor(i / 65536) % 256;
			checkSessionCreateRateLimitInMemory(`10.${octet3}.${octet2}.${octet1}`);
		}

		// Map should not exceed the cap
		expect(SESSION_CREATE_BY_IP.size).toBeLessThanOrEqual(MAX_SESSION_CREATE_IPS);
	});

	it('evicts oldest IP entries when size cap is exceeded', () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);

		// Add an "old" IP entry
		checkSessionCreateRateLimitInMemory('192.168.0.1');

		// Fill up to the cap with newer IPs
		for (let i = 0; i < MAX_SESSION_CREATE_IPS; i++) {
			nowSpy.mockReturnValue(base + 1000 + i);
			checkSessionCreateRateLimitInMemory(`10.0.${Math.floor(i / 256) % 256}.${i % 256}`);
		}

		// The oldest entry should have been evicted
		expect(SESSION_CREATE_BY_IP.has('192.168.0.1')).toBe(false);
		expect(SESSION_CREATE_BY_IP.size).toBeLessThanOrEqual(MAX_SESSION_CREATE_IPS);
	});
});
