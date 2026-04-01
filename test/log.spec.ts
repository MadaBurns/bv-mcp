import { afterEach, describe, expect, it, vi } from 'vitest';
import { auditSessionCreated } from '../src/lib/audit';
import { logEvent, sanitizeHeadersForLog, sanitizeLogValue } from '../src/lib/log';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('log redaction', () => {
	it('redacts sensitive headers', () => {
		const sanitized = sanitizeHeadersForLog({
			authorization: 'Bearer secret-token',
			'Mcp-Session-Id': 'session-123',
			'content-type': 'application/json',
		});

		expect(sanitized.authorization).toBe('[redacted]');
		expect(sanitized['mcp-session-id']).toBe('[redacted]');
		expect(sanitized['content-type']).toBe('application/json');
	});

	it('redacts nested sensitive values in log details', () => {
		const sanitized = sanitizeLogValue({
			sessionId: 'session-123',
			rawBody: '{"secret":"value"}',
			params: {
				apiKey: 'abc123',
				ok: 'visible',
			},
		});

		expect(sanitized).toEqual({
			sessionId: '[redacted]',
			rawBody: '[redacted]',
			params: {
				apiKey: '[redacted]',
				ok: 'visible',
			},
		});
	});

	it('audit logs do not emit raw session identifiers', () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		auditSessionCreated('203.0.113.9', 'session-secret-value');

		const payload = JSON.parse(String(consoleSpy.mock.calls[0]?.[0])) as {
			details: { hasSessionId: boolean; sessionId?: string };
		};
		expect(payload.details.hasSessionId).toBe(true);
		expect(payload.details.sessionId).toBeUndefined();
		expect(JSON.stringify(payload)).not.toContain('session-secret-value');
	});

	it('logEvent redacts sensitive fields before emission', () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		logEvent({
			timestamp: new Date().toISOString(),
			severity: 'info',
			details: {
				token: 'secret-token',
				nested: { session: 'session-123' },
			},
		});

		const payload = JSON.parse(String(consoleSpy.mock.calls[0]?.[0])) as { details: { token: string; nested: { session: string } } };
		expect(payload.details.token).toBe('[redacted]');
		expect(payload.details.nested.session).toBe('[redacted]');
	});
});