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
const SENSITIVE_KEY_PATTERN = /(authorization|mcp-session-id|session|token|api[-_]?key|secret|password|cookie|rawbody)/i;

function isSensitiveKey(key: string): boolean {
	return !/^has[A-Z]/.test(key) && SENSITIVE_KEY_PATTERN.test(key);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sanitizeString(value: string): string {
	return value.length > MAX_LOG_STRING_LENGTH ? `${value.slice(0, MAX_LOG_STRING_LENGTH)}...` : value;
}

export function sanitizeLogValue(value: unknown, key?: string): unknown {
	if (key && isSensitiveKey(key)) {
		return REDACTED;
	}

	if (typeof value === 'string') {
		return sanitizeString(value);
	}

	if (Array.isArray(value)) {
		return value.map((item) => sanitizeLogValue(item));
	}

	if (isPlainObject(value)) {
		const sanitized: Record<string, unknown> = {};
		for (const [entryKey, entryValue] of Object.entries(value)) {
			sanitized[entryKey] = sanitizeLogValue(entryValue, entryKey);
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
	const log = {
		...event,
		timestamp: event.timestamp || new Date().toISOString(),
		details: sanitizeLogValue(event.details),
		error: typeof event.error === 'string' ? sanitizeString(event.error) : event.error,
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
