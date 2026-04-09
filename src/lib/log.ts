// SPDX-License-Identifier: BUSL-1.1

/**
 * Structured logging utility for Cloudflare Worker (MCP server)
 * Logs JSON objects with request, tool, result, and error metadata
 * Usage: logEvent({ ... })
 */

export type LogEvent = {
	timestamp: string;
	requestId?: string;
	ip?: string;
	tool?: string;
	domain?: string;
	severity?: 'info' | 'warn' | 'error';
	category?: string;
	result?: string;
	details?: unknown;
	error?: string;
	durationMs?: number;
	userAgent?: string;
};

const REDACTED = '[redacted]';
const MAX_LOG_STRING_LENGTH = 256;
const MAX_ERROR_STRING_LENGTH = 1024;
const SENSITIVE_KEY_PATTERN = /(^ip$|authorization|mcp-session-id|session|token|api[-_]?key|secret|password|cookie|rawbody)/i;

function isSensitiveKey(key: string): boolean {
	return !/^has[A-Z]/.test(key) && SENSITIVE_KEY_PATTERN.test(key);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sanitizeString(value: string, maxLength = MAX_LOG_STRING_LENGTH): string {
	// Strip control characters (except tab) to prevent log injection via newlines/ANSI sequences
	const stripped = value.replace(/[\x00-\x08\x0a-\x1f\x7f]/g, ' ');
	if (stripped.length <= maxLength) return stripped;
	// Preserve start and end for error context (type + stack tail)
	const half = Math.floor((maxLength - 5) / 2);
	return `${stripped.slice(0, half)} ... ${stripped.slice(-half)}`;
}

export function sanitizeLogValue(value: unknown, key?: string, maxLength?: number): unknown {
	if (key && isSensitiveKey(key)) {
		return REDACTED;
	}

	if (typeof value === 'string') {
		return sanitizeString(value, maxLength);
	}

	if (Array.isArray(value)) {
		return value.map((item) => sanitizeLogValue(item, undefined, maxLength));
	}

	if (isPlainObject(value)) {
		const sanitized: Record<string, unknown> = {};
		for (const [entryKey, entryValue] of Object.entries(value)) {
			sanitized[entryKey] = sanitizeLogValue(entryValue, entryKey, maxLength);
		}
		return sanitized;
	}

	return value;
}

export function sanitizeHeadersForLog(headers: Headers | Record<string, string>): Record<string, string> {
	const sanitized: Record<string, string> = {};
	if (headers instanceof Headers) {
		headers.forEach((value, rawKey) => {
			const key = rawKey.toLowerCase();
			sanitized[key] = isSensitiveKey(key) ? REDACTED : sanitizeString(value);
		});
		return sanitized;
	}

	for (const [rawKey, value] of Object.entries(headers)) {
		const key = rawKey.toLowerCase();
		sanitized[key] = isSensitiveKey(key) ? REDACTED : sanitizeString(value);
	}
	return sanitized;
}

/**
 * Emit a structured log event (console.log as JSON)
 */
export function logEvent(event: LogEvent): void {
	const isError = event.severity === 'error';
	const maxLen = isError ? MAX_ERROR_STRING_LENGTH : MAX_LOG_STRING_LENGTH;
	const log = {
		...event,
		timestamp: event.timestamp || new Date().toISOString(),
		details: sanitizeLogValue(event.details, undefined, maxLen),
		error: typeof event.error === 'string' ? sanitizeString(event.error, maxLen) : event.error,
	};
	console.log(JSON.stringify(log));
}

/**
 * Helper for error logging
 */
export function logError(error: Error | string, context?: Partial<LogEvent>): void {
	logEvent({
		timestamp: new Date().toISOString(),
		severity: 'error',
		error: typeof error === 'string' ? error : error.message,
		...context,
	});
}
