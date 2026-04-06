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

describe('log string truncation', () => {
	it('truncates long strings at default limit via sanitizeLogValue', () => {
		const longString = 'a'.repeat(500);
		const result = sanitizeLogValue(longString) as string;
		// Default 256 limit: truncated output should be well under 300 chars
		expect(result.length).toBeLessThan(300);
	});

	it('preserves start and end when truncating via sanitizeLogValue', () => {
		const longString = 'START' + 'x'.repeat(300) + 'END';
		const result = sanitizeLogValue(longString) as string;
		expect(result).toContain('START');
		expect(result).toContain(' ... ');
		expect(result).toContain('END');
	});

	it('uses longer truncation limit for error-level logs', () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		const longError = 'Error: ' + 'x'.repeat(800) + ' at stack';
		logEvent({
			timestamp: new Date().toISOString(),
			severity: 'error',
			error: longError,
		});

		const payload = JSON.parse(String(consoleSpy.mock.calls[0]?.[0])) as { error: string };
		// Error-level uses 1024 limit; 810-char string should be fully preserved
		expect(payload.error).toBe(longError);
	});

	it('truncates error strings that exceed the error limit', () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		const veryLongError = 'Error: ' + 'x'.repeat(2000) + ' at stack';
		logEvent({
			timestamp: new Date().toISOString(),
			severity: 'error',
			error: veryLongError,
		});

		const payload = JSON.parse(String(consoleSpy.mock.calls[0]?.[0])) as { error: string };
		// Should be truncated but longer than default 256
		expect(payload.error.length).toBeGreaterThan(300);
		expect(payload.error.length).toBeLessThanOrEqual(1030);
		expect(payload.error).toContain(' ... ');
	});

	it('uses longer truncation for error-level log details', () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		const longDetail = 'a'.repeat(500);
		logEvent({
			timestamp: new Date().toISOString(),
			severity: 'error',
			details: { message: longDetail },
		});

		const payload = JSON.parse(String(consoleSpy.mock.calls[0]?.[0])) as { details: { message: string } };
		// Error-level uses 1024 limit; 500-char string should be fully preserved
		expect(payload.details.message).toBe(longDetail);
	});

	it('info-level logs still truncate details at default limit', () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		const longDetail = 'a'.repeat(500);
		logEvent({
			timestamp: new Date().toISOString(),
			severity: 'info',
			details: { message: longDetail },
		});

		const payload = JSON.parse(String(consoleSpy.mock.calls[0]?.[0])) as { details: { message: string } };
		// Info-level uses default 256 limit; 500-char string should be truncated
		expect(payload.details.message.length).toBeLessThan(300);
	});
});