// SPDX-License-Identifier: BUSL-1.1

import { logEvent, logError } from '../lib/log';
import type { AnalyticsClient } from '../lib/analytics';
import type { McpClientType } from '../lib/client-detection';

type ToolSuccessStatus = 'pass' | 'fail';
type ToolFailureSeverity = 'warn' | 'error';

interface ToolExecutionBase {
	toolName: string;
	durationMs: number;
	domain?: string;
	analytics?: AnalyticsClient;
	country?: string;
	clientType?: McpClientType;
	authTier?: string;
	score?: number;
	cacheStatus?: 'hit' | 'miss' | 'n/a';
	keyHash?: string;
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
		score: options.score,
		cacheStatus: options.cacheStatus,
		country: options.country,
		clientType: options.clientType,
		authTier: options.authTier,
		keyHash: options.keyHash,
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
		score: options.score,
		cacheStatus: options.cacheStatus,
		country: options.country,
		clientType: options.clientType,
		authTier: options.authTier,
		keyHash: options.keyHash,
	});

	logError(options.error instanceof Error ? options.error : String(options.error), {
		tool: options.toolName,
		domain: options.domain,
		details: options.args,
		severity: options.severity ?? 'error',
	});
}