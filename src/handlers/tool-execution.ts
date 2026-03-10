// SPDX-License-Identifier: MIT

import { logEvent, logError } from '../lib/log';
import type { AnalyticsClient } from '../lib/analytics';

type ToolSuccessStatus = 'pass' | 'fail';
type ToolFailureSeverity = 'warn' | 'error';

interface ToolExecutionBase {
	toolName: string;
	durationMs: number;
	domain?: string;
	analytics?: AnalyticsClient;
}

export function logToolSuccess(options: ToolExecutionBase & {
	status: ToolSuccessStatus;
	logResult: string;
	logDetails: unknown;
	severity?: 'info' | 'warn';
}): void {
	options.analytics?.emitToolEvent({
		toolName: options.toolName,
		status: options.status,
		durationMs: options.durationMs,
		domain: options.domain,
		isError: false,
	});

	logEvent({
		timestamp: new Date().toISOString(),
		tool: options.toolName,
		domain: options.domain,
		result: options.logResult,
		details: options.logDetails,
		durationMs: options.durationMs,
		severity: options.severity ?? (options.status === 'pass' ? 'info' : 'warn'),
	});
}

export function logToolFailure(options: ToolExecutionBase & {
	error: unknown;
	args: Record<string, unknown>;
	severity?: ToolFailureSeverity;
}): void {
	options.analytics?.emitToolEvent({
		toolName: options.toolName,
		status: 'error',
		durationMs: options.durationMs,
		domain: options.domain,
		isError: true,
	});

	logError(options.error instanceof Error ? options.error : String(options.error), {
		tool: options.toolName,
		domain: options.domain,
		details: options.args,
		severity: options.severity ?? 'error',
	});
}