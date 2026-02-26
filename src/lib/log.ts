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

/**
 * Emit a structured log event (console.log as JSON)
 */
export function logEvent(event: LogEvent): void {
	const log = {
		...event,
		timestamp: event.timestamp || new Date().toISOString(),
	};
	console.log(JSON.stringify(log));
}

/**
 * Helper for error logging
 */
export function logError(error: Error | string, context?: Partial<LogEvent>): void {
	logEvent({
		severity: 'error',
		error: typeof error === 'string' ? error : error.message,
		...context,
	});
}
