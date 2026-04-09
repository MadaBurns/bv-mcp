// SPDX-License-Identifier: BUSL-1.1

import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
});

/**
 * Parse all structured JSON objects emitted via console.log.
 */
function getConsoleLogs(spy: ReturnType<typeof vi.spyOn>): Record<string, unknown>[] {
	const logs: Record<string, unknown>[] = [];
	for (const call of spy.mock.calls) {
		const arg = call[0];
		if (typeof arg === 'string') {
			try {
				const parsed = JSON.parse(arg) as Record<string, unknown>;
				logs.push(parsed);
			} catch {
				// not JSON, skip
			}
		}
	}
	return logs;
}

describe('auditSessionCreated', () => {
	it('emits a log event with category=audit', async () => {
		const { auditSessionCreated } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditSessionCreated('1.2.3.4', 'a'.repeat(64));

		const logs = getConsoleLogs(consoleSpy);
		expect(logs.length).toBeGreaterThan(0);
		expect(logs[0].category).toBe('audit');
	});

	it('sets eventType to session-created', async () => {
		const { auditSessionCreated } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditSessionCreated('1.2.3.4', 'b'.repeat(64));

		const logs = getConsoleLogs(consoleSpy);
		const details = logs[0].details as Record<string, unknown>;
		expect(details.eventType).toBe('session-created');
	});

	it('sets severity to info', async () => {
		const { auditSessionCreated } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditSessionCreated('203.0.113.1', 'c'.repeat(64));

		const logs = getConsoleLogs(consoleSpy);
		expect(logs[0].severity).toBe('info');
	});

	it('includes the IP address in the log details (redacted by sanitizer per sensitive-key rule)', async () => {
		const { auditSessionCreated } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditSessionCreated('198.51.100.7', 'd'.repeat(64));

		const logs = getConsoleLogs(consoleSpy);
		const details = logs[0].details as Record<string, unknown>;
		// The `ip` key matches the SENSITIVE_KEY_PATTERN in log.ts (^ip$) and is redacted at emit time.
		// The field is present but its value is masked — this is the correct security behavior.
		expect(details.ip).toBe('[redacted]');
	});

	it('sets hasSessionId to true when a sessionId is provided', async () => {
		const { auditSessionCreated } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditSessionCreated('10.0.0.1', 'e'.repeat(64));

		const logs = getConsoleLogs(consoleSpy);
		const details = logs[0].details as Record<string, unknown>;
		expect(details.hasSessionId).toBe(true);
	});

	it('does not emit the raw sessionId value in the log output', async () => {
		const { auditSessionCreated } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		const sensitiveId = 'f'.repeat(64);
		auditSessionCreated('10.0.0.1', sensitiveId);

		const raw = String(consoleSpy.mock.calls[0]?.[0]);
		// The sessionId itself must not appear verbatim in the emitted JSON
		expect(raw).not.toContain(sensitiveId);
		// The details object should not have a sessionId property
		const parsed = JSON.parse(raw) as { details: Record<string, unknown> };
		expect(parsed.details.sessionId).toBeUndefined();
	});

	it('includes a message of "New session created"', async () => {
		const { auditSessionCreated } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditSessionCreated('192.0.2.55', '0'.repeat(64));

		const logs = getConsoleLogs(consoleSpy);
		const details = logs[0].details as Record<string, unknown>;
		expect(details.message).toBe('New session created');
	});

	it('includes a timestamp in the log output', async () => {
		const { auditSessionCreated } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		const before = Date.now();
		auditSessionCreated('192.0.2.1', '1'.repeat(64));
		const after = Date.now();

		const logs = getConsoleLogs(consoleSpy);
		expect(typeof logs[0].timestamp).toBe('string');
		const ts = new Date(logs[0].timestamp as string).getTime();
		expect(ts).toBeGreaterThanOrEqual(before);
		expect(ts).toBeLessThanOrEqual(after);
	});
});

describe('auditLog', () => {
	it('passes through custom details into the log event', async () => {
		const { auditLog } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditLog({
			eventType: 'session-created',
			ip: '10.10.10.10',
			timestamp: new Date().toISOString(),
			severity: 'warn',
			message: 'Suspicious session',
			details: { rateLimitHit: true, attemptCount: 5 },
		});

		const logs = getConsoleLogs(consoleSpy);
		expect(logs.length).toBeGreaterThan(0);
		const details = logs[0].details as Record<string, unknown>;
		expect(details.rateLimitHit).toBe(true);
		expect(details.attemptCount).toBe(5);
	});

	it('emits warn severity when specified', async () => {
		const { auditLog } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditLog({
			eventType: 'session-created',
			ip: '10.10.10.10',
			timestamp: new Date().toISOString(),
			severity: 'warn',
			message: 'Rate limit approaching',
		});

		const logs = getConsoleLogs(consoleSpy);
		expect(logs[0].severity).toBe('warn');
	});

	it('falls back to a generated timestamp when none is provided', async () => {
		const { auditLog } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditLog({
			eventType: 'session-created',
			ip: '127.0.0.1',
			timestamp: '', // empty string triggers fallback in logEvent
			severity: 'info',
			message: 'test fallback',
		});

		const logs = getConsoleLogs(consoleSpy);
		expect(typeof logs[0].timestamp).toBe('string');
		// Should be a valid ISO 8601 date (non-empty, parseable)
		expect(new Date(logs[0].timestamp as string).getTime()).toBeGreaterThan(0);
	});

	it('omits tool and domain from details when not provided', async () => {
		const { auditLog } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditLog({
			eventType: 'session-created',
			ip: '1.1.1.1',
			timestamp: new Date().toISOString(),
			severity: 'info',
			message: 'minimal event',
		});

		const logs = getConsoleLogs(consoleSpy);
		const details = logs[0].details as Record<string, unknown>;
		// tool and domain should be undefined (not set in details)
		expect(details.tool).toBeUndefined();
		expect(details.domain).toBeUndefined();
	});

	it('includes tool and domain in details when provided', async () => {
		const { auditLog } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditLog({
			eventType: 'session-created',
			ip: '1.1.1.1',
			timestamp: new Date().toISOString(),
			severity: 'info',
			message: 'tool event',
			tool: 'scan_domain',
			domain: 'example.com',
		});

		const logs = getConsoleLogs(consoleSpy);
		const details = logs[0].details as Record<string, unknown>;
		expect(details.tool).toBe('scan_domain');
		expect(details.domain).toBe('example.com');
	});

	it('sets category=audit on all emitted log events', async () => {
		const { auditLog } = await import('../src/lib/audit');

		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditLog({
			eventType: 'session-created',
			ip: '2.2.2.2',
			timestamp: new Date().toISOString(),
			severity: 'info',
			message: 'category test',
		});

		const logs = getConsoleLogs(consoleSpy);
		expect(logs[0].category).toBe('audit');
	});
});
