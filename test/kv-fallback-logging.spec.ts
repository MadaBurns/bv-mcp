import { describe, it, expect, vi, afterEach } from 'vitest';
import {
	checkRateLimit,
	checkControlPlaneRateLimit,
	checkToolDailyRateLimit,
	checkGlobalDailyLimit,
	resetAllRateLimits,
} from '../src/lib/rate-limiter';
import { createSession, validateSession, deleteSession, resetSessions, checkSessionCreateRateLimit } from '../src/lib/session';
import { cacheGet, cacheSet, IN_MEMORY_CACHE } from '../src/lib/cache';

afterEach(() => {
	resetAllRateLimits();
	resetSessions();
	IN_MEMORY_CACHE.clear();
	vi.restoreAllMocks();
});

/**
 * logError → logEvent → console.log(JSON.stringify({...}))
 * We spy on console.log and check for structured JSON with severity: 'error'
 */
function getStructuredErrorLogs(spy: ReturnType<typeof vi.fn>): Record<string, unknown>[] {
	const logs: Record<string, unknown>[] = [];
	for (const call of spy.mock.calls) {
		const arg = call[0];
		if (typeof arg === 'string') {
			try {
				const parsed = JSON.parse(arg) as Record<string, unknown>;
				if (parsed.severity === 'error') {
					logs.push(parsed);
				}
			} catch {
				// not JSON, skip
			}
		}
	}
	return logs;
}

describe('KV/DO fallback structured logging', () => {
	describe('rate-limiter', () => {
		it('emits structured error log when KV fails during rate limiting', async () => {
			const consoleSpy = vi.spyOn(console, 'log');

			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn(),
			} as unknown as KVNamespace;

			await checkRateLimit('1.2.3.4', kv);

			const errorLogs = getStructuredErrorLogs(consoleSpy);
			expect(errorLogs.length).toBeGreaterThan(0);
			expect(errorLogs[0].error).toContain('KV');
		});

		it('emits structured error log when quota coordinator fails during rate limiting', async () => {
			const consoleSpy = vi.spyOn(console, 'log');

			const quotaCoordinator = {
				idFromName: vi.fn().mockReturnValue({ toString: () => 'test-id' }),
				get: vi.fn().mockReturnValue({
					fetch: vi.fn().mockRejectedValue(new Error('DO unavailable')),
				}),
			} as unknown as DurableObjectNamespace;

			await checkRateLimit('1.2.3.4', undefined, quotaCoordinator);

			const errorLogs = getStructuredErrorLogs(consoleSpy);
			expect(errorLogs.length).toBeGreaterThan(0);
			expect(errorLogs[0].error).toContain('quota coordinator');
		});

		it('emits structured error log when KV fails during tool daily rate limit', async () => {
			const consoleSpy = vi.spyOn(console, 'log');

			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn(),
			} as unknown as KVNamespace;

			await checkToolDailyRateLimit('1.2.3.4', 'scan_domain', 5, kv);

			const errorLogs = getStructuredErrorLogs(consoleSpy);
			expect(errorLogs.length).toBeGreaterThan(0);
			expect(errorLogs[0].error).toContain('KV');
		});

		it('emits structured error log when KV fails during global daily limit', async () => {
			const consoleSpy = vi.spyOn(console, 'log');

			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn(),
			} as unknown as KVNamespace;

			await checkGlobalDailyLimit(500_000, kv);

			const errorLogs = getStructuredErrorLogs(consoleSpy);
			expect(errorLogs.length).toBeGreaterThan(0);
			expect(errorLogs[0].error).toContain('KV');
		});

		it('emits structured error log when KV fails during control plane rate limit', async () => {
			const consoleSpy = vi.spyOn(console, 'log');

			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn(),
			} as unknown as KVNamespace;

			await checkControlPlaneRateLimit('1.2.3.4', kv);

			const errorLogs = getStructuredErrorLogs(consoleSpy);
			expect(errorLogs.length).toBeGreaterThan(0);
			expect(errorLogs[0].error).toContain('KV');
		});
	});

	describe('session', () => {
		it('emits structured error log when KV fails during session create', async () => {
			const consoleSpy = vi.spyOn(console, 'log');

			const kv = {
				get: vi.fn().mockResolvedValue(null),
				put: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				delete: vi.fn(),
			} as unknown as KVNamespace;

			await createSession(kv);

			const errorLogs = getStructuredErrorLogs(consoleSpy);
			expect(errorLogs.length).toBeGreaterThan(0);
			expect(errorLogs[0].error).toContain('KV');
		});

		it('emits structured error log when KV fails during session validate', async () => {
			const consoleSpy = vi.spyOn(console, 'log');

			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn(),
				delete: vi.fn(),
			} as unknown as KVNamespace;

			// Validate a session that doesn't exist in memory — forces KV path
			await validateSession('nonexistent-session-id', kv);

			const errorLogs = getStructuredErrorLogs(consoleSpy);
			expect(errorLogs.length).toBeGreaterThan(0);
			expect(errorLogs[0].error).toContain('KV');
		});

		it('emits structured error log when KV fails during session delete', async () => {
			const consoleSpy = vi.spyOn(console, 'log');

			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				delete: vi.fn(),
			} as unknown as KVNamespace;

			const id = await createSession(); // create in-memory only
			await deleteSession(id, kv);

			const errorLogs = getStructuredErrorLogs(consoleSpy);
			expect(errorLogs.length).toBeGreaterThan(0);
			expect(errorLogs.some((l) => typeof l.error === 'string' && l.error.includes('KV'))).toBe(true);
		});

		it('emits structured error log when KV fails during session create rate limit', async () => {
			const consoleSpy = vi.spyOn(console, 'log');

			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn(),
			} as unknown as KVNamespace;

			await checkSessionCreateRateLimit('1.2.3.4', kv);

			const errorLogs = getStructuredErrorLogs(consoleSpy);
			expect(errorLogs.length).toBeGreaterThan(0);
			expect(errorLogs[0].error).toContain('KV');
		});
	});

	describe('cache', () => {
		it('emits structured error log when KV fails during cache get', async () => {
			const consoleSpy = vi.spyOn(console, 'log');

			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn(),
			} as unknown as KVNamespace;

			await cacheGet('test-key', kv);

			const errorLogs = getStructuredErrorLogs(consoleSpy);
			expect(errorLogs.length).toBeGreaterThan(0);
			expect(errorLogs[0].error).toContain('KV');
		});

		it('emits structured error log when KV fails during cache set', async () => {
			const consoleSpy = vi.spyOn(console, 'log');

			const kv = {
				get: vi.fn(),
				put: vi.fn().mockRejectedValue(new Error('KV unavailable')),
			} as unknown as KVNamespace;

			await cacheSet('test-key', 'value', kv);

			const errorLogs = getStructuredErrorLogs(consoleSpy);
			expect(errorLogs.length).toBeGreaterThan(0);
			expect(errorLogs[0].error).toContain('KV');
		});
	});
});
