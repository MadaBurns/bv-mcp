// SPDX-License-Identifier: BUSL-1.1

import { checkRateLimit, checkToolDailyRateLimit, checkGlobalDailyLimit } from '../lib/rate-limiter';
import { logEvent, logError } from '../lib/log';
import { jsonRpcError, JSON_RPC_ERRORS, sanitizeErrorMessage } from '../lib/json-rpc';
import { buildControlPlaneRateLimitResponse, validateSessionRequest } from './route-gates';
import { FREE_TOOL_DAILY_LIMITS, GLOBAL_DAILY_TOOL_LIMIT, TIER_DAILY_LIMITS, TIER_TOOL_DAILY_LIMITS } from '../lib/config';
import { normalizeToolName } from '../handlers/tool-args';
import { acceptsSSE } from '../lib/sse';
import { dispatchMcpMethod } from './dispatch';
import { validateJsonRpcRequest } from './request';
import type { JsonRpcRequest } from '../lib/json-rpc';
import type { AnalyticsClient } from '../lib/analytics';

export type ProcessedRequestResult =
	| {
			kind: 'notification';
	  }
	| {
			kind: 'response';
			payload: unknown;
			headers: Record<string, string>;
			httpStatus: number;
			useErrorEnvelope: boolean;
			eventId?: string;
			streamOperation?: Promise<unknown>;
	  };

export interface ExecuteMcpRequestOptions {
	body: JsonRpcRequest;
	accept?: string;
	allowStreaming: boolean;
	batchMode: boolean;
	batchSize: number;
	responseTransport: 'json' | 'sse';
	startTime: number;
	ip: string;
	isAuthenticated: boolean;
	tierAuthResult?: import('../lib/tier-auth').TierAuthResult;
	userAgent?: string;
	sessionId?: string;
	validateSession: boolean;
	sessionErrorMessage?: string;
	createSessionOnInitialize?: boolean;
	existingSessionId?: string;
	serverVersion: string;
	rateLimitKv?: KVNamespace;
	quotaCoordinator?: DurableObjectNamespace;
	sessionStore?: KVNamespace;
	scanCache?: KVNamespace;
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string;
	providerSignaturesSha256?: string;
	analytics?: AnalyticsClient;
	profileAccumulator?: DurableObjectNamespace;
	waitUntil?: (promise: Promise<unknown>) => void;
	scoringConfig?: import('../lib/scoring-config').ScoringConfig;
	cacheTtlSeconds?: number;
	/** Custom secondary DoH endpoint URL (bv-dns). */
	secondaryDohEndpoint?: string;
	/** Auth token for custom secondary DoH. */
	secondaryDohToken?: string;
	country?: string;
	clientType?: string;
	authTier?: string;
	sessionHash?: string;
}

function getDomainFromParams(params: Record<string, unknown> | undefined): string | undefined {
	return typeof params === 'object' && params && 'domain' in params ? String(params.domain) : undefined;
}

function extractHeaders(response: Response): Record<string, string> {
	const headers: Record<string, string> = {};
	response.headers.forEach((value, key) => {
		const lower = key.toLowerCase();
		if (lower === 'content-type' || lower === 'cache-control' || lower === 'content-length') return;
		headers[key] = value;
	});
	return headers;
}

async function readJsonRpcPayload(response: Response): Promise<ReturnType<typeof jsonRpcError>> {
	const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
	if (contentType.includes('text/event-stream')) {
		const text = await response.text();
		const dataLine = text
			.split('\n')
			.find((line) => line.startsWith('data: '));
		if (!dataLine) {
			return jsonRpcError(null, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error');
		}
		return JSON.parse(dataLine.slice('data: '.length)) as ReturnType<typeof jsonRpcError>;
	}

	return (await response.json()) as ReturnType<typeof jsonRpcError>;
}

function emitRequestAnalytics(
	options: ExecuteMcpRequestOptions,
	method: string,
	status: 'ok' | 'error',
	hasJsonRpcError: boolean,
): void {
	options.analytics?.emitRequestEvent({
		method,
		status,
		durationMs: Date.now() - options.startTime,
		isAuthenticated: options.isAuthenticated,
		hasJsonRpcError,
		transport: options.responseTransport,
		country: options.country,
		clientType: options.clientType as import('../lib/client-detection').McpClientType,
		authTier: options.authTier,
		sessionHash: options.sessionHash,
	});
}

export async function executeMcpRequest(options: ExecuteMcpRequestOptions): Promise<ProcessedRequestResult> {
	const validationError = validateJsonRpcRequest(options.body);
	if (validationError) {
		emitRequestAnalytics(
			options,
			typeof options.body?.method === 'string' ? options.body.method : 'invalid',
			'error',
			true,
		);
		return {
			kind: 'response',
			payload: validationError.payload,
			headers: {},
			httpStatus: validationError.status,
			useErrorEnvelope: true,
			eventId: options.body.id != null ? String(options.body.id) : undefined,
		};
	}

	const { id, method, params } = options.body;
	const eventId = id != null ? String(id) : undefined;

	if (options.batchMode && options.batchSize > 1 && method === 'initialize') {
		emitRequestAnalytics(options, method, 'error', true);
		return {
			kind: 'response',
			payload: jsonRpcError(id, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC batch request: initialize cannot be batched with other messages'),
			headers: {},
			httpStatus: 400,
			useErrorEnvelope: true,
			eventId,
		};
	}

	let rateHeaders: Record<string, string> = {};
	if (!options.isAuthenticated && method === 'tools/call') {
		const globalResult = await checkGlobalDailyLimit(GLOBAL_DAILY_TOOL_LIMIT, options.rateLimitKv, options.quotaCoordinator);
		if (!globalResult.allowed) {
			const globalHeaders: Record<string, string> = {};
			if (globalResult.retryAfterMs !== undefined) {
				globalHeaders['retry-after'] = String(Math.ceil(globalResult.retryAfterMs / 1000));
			}
			options.analytics?.emitRateLimitEvent({
				limitType: 'daily_global',
				toolName: 'n/a',
				limit: GLOBAL_DAILY_TOOL_LIMIT,
				remaining: 0,
				country: options.country,
				authTier: options.authTier,
			});
			emitRequestAnalytics(options, method, 'error', true);
			return {
				kind: 'response',
				payload: jsonRpcError(
					id,
					JSON_RPC_ERRORS.RATE_LIMITED,
					'Service capacity reached for today. Please try again tomorrow or deploy your own instance.',
				),
				headers: globalHeaders,
				httpStatus: 429,
				useErrorEnvelope: true,
				eventId,
			};
		}

		const rateResult = await checkRateLimit(options.ip, options.rateLimitKv, options.quotaCoordinator);
		const minuteResetEpoch = Math.ceil(Date.now() / 60_000) * 60;
		rateHeaders = {
			'x-ratelimit-limit': '50',
			'x-ratelimit-remaining': String(rateResult.minuteRemaining),
			'x-ratelimit-reset': String(minuteResetEpoch),
		};
		if (!rateResult.allowed) {
			if (rateResult.retryAfterMs !== undefined) {
				rateHeaders['retry-after'] = String(Math.ceil(rateResult.retryAfterMs / 1000));
			}
			options.analytics?.emitRateLimitEvent({
				limitType: 'minute',
				toolName: 'n/a',
				limit: 50,
				remaining: rateResult.minuteRemaining,
				country: options.country,
				authTier: options.authTier,
			});
			emitRequestAnalytics(options, method, 'error', true);
			return {
				kind: 'response',
				payload: jsonRpcError(
					id,
					JSON_RPC_ERRORS.RATE_LIMITED,
					`Rate limit exceeded. Retry after ${Math.ceil((rateResult.retryAfterMs ?? 0) / 1000)}s`,
				),
				headers: rateHeaders,
				httpStatus: 429,
				useErrorEnvelope: true,
				eventId,
			};
		}

		const toolNameRaw = typeof params === 'object' && params !== null && 'name' in params ? (params as Record<string, unknown>).name : undefined;
		const toolName = typeof toolNameRaw === 'string' ? normalizeToolName(toolNameRaw) : '';
		const toolDailyLimit = toolName ? FREE_TOOL_DAILY_LIMITS[toolName] : undefined;
		if (toolDailyLimit !== undefined) {
			const toolQuotaResult = await checkToolDailyRateLimit(
				options.ip,
				toolName,
				toolDailyLimit,
				options.rateLimitKv,
				options.quotaCoordinator,
			);
			const dailyResetEpoch = Math.ceil(Date.now() / 86_400_000) * 86_400;
			rateHeaders['x-quota-limit'] = String(toolQuotaResult.limit);
			rateHeaders['x-quota-remaining'] = String(toolQuotaResult.remaining);
			rateHeaders['x-quota-reset'] = String(dailyResetEpoch);
			if (!toolQuotaResult.allowed) {
				if (toolQuotaResult.retryAfterMs !== undefined) {
					rateHeaders['retry-after'] = String(Math.ceil(toolQuotaResult.retryAfterMs / 1000));
				}
				options.analytics?.emitRateLimitEvent({
					limitType: 'daily_tool',
					toolName,
					limit: toolDailyLimit,
					remaining: 0,
					country: options.country,
					authTier: options.authTier ?? 'anon',
				});
				emitRequestAnalytics(options, method, 'error', true);
				return {
					kind: 'response',
					payload: jsonRpcError(
						id,
						JSON_RPC_ERRORS.RATE_LIMITED,
						`Rate limit exceeded. ${toolName} is limited to ${toolDailyLimit} requests per day for free tier users.`,
					),
					headers: rateHeaders,
					httpStatus: 429,
					useErrorEnvelope: true,
					eventId,
				};
			}
		}
	} else if (options.tierAuthResult?.authenticated && options.tierAuthResult.tier && method === 'tools/call') {
		// Authenticated tier-based rate limiting (keyed by API key hash, not IP)
		const tier = options.tierAuthResult.tier;
		const principalId = options.tierAuthResult.keyHash ?? options.ip;

		const toolNameRaw = typeof params === 'object' && params !== null && 'name' in params ? (params as Record<string, unknown>).name : undefined;
		const toolName = typeof toolNameRaw === 'string' ? normalizeToolName(toolNameRaw) : 'unknown';

		// Per-tool tier override takes precedence over flat tier limit
		const dailyLimit = TIER_TOOL_DAILY_LIMITS[tier]?.[toolName] ?? TIER_DAILY_LIMITS[tier];

		const tierQuotaResult = await checkToolDailyRateLimit(
			principalId,
			toolName,
			dailyLimit,
			options.rateLimitKv,
			options.quotaCoordinator,
		);
		const tierDailyResetEpoch = Math.ceil(Date.now() / 86_400_000) * 86_400;
		rateHeaders['x-quota-limit'] = String(tierQuotaResult.limit);
		rateHeaders['x-quota-remaining'] = String(tierQuotaResult.remaining);
		rateHeaders['x-quota-reset'] = String(tierDailyResetEpoch);
		rateHeaders['x-quota-tier'] = tier;
		if (!tierQuotaResult.allowed) {
			if (tierQuotaResult.retryAfterMs !== undefined) {
				rateHeaders['retry-after'] = String(Math.ceil(tierQuotaResult.retryAfterMs / 1000));
			}
			options.analytics?.emitRateLimitEvent({
				limitType: 'daily_tool',
				toolName,
				limit: dailyLimit,
				remaining: 0,
				country: options.country,
				authTier: tier,
			});
			emitRequestAnalytics(options, method, 'error', true);
			return {
				kind: 'response',
				payload: jsonRpcError(
					id,
					JSON_RPC_ERRORS.RATE_LIMITED,
					`Rate limit exceeded. ${tier} tier is limited to ${dailyLimit} requests per day.`,
				),
				headers: rateHeaders,
				httpStatus: 429,
				useErrorEnvelope: true,
				eventId,
			};
		}
	}

	if (method !== 'tools/call') {
		const controlPlaneLimited = await buildControlPlaneRateLimitResponse(
			options.ip,
			options.rateLimitKv,
			method,
			options.isAuthenticated,
			id,
			options.accept,
			options.quotaCoordinator,
		);
		if (controlPlaneLimited) {
			emitRequestAnalytics(options, method, 'error', true);
			return {
				kind: 'response',
				payload: await readJsonRpcPayload(controlPlaneLimited),
				headers: extractHeaders(controlPlaneLimited),
				httpStatus: controlPlaneLimited.status,
				useErrorEnvelope: true,
				eventId,
			};
		}
	}

	if (options.validateSession && method !== 'initialize' && !method.startsWith('notifications/')) {
		const sessionError = await validateSessionRequest(
			options.sessionId,
			options.sessionStore,
			id,
			options.sessionErrorMessage ?? 'Bad Request: missing session',
		);
		if (sessionError) {
			emitRequestAnalytics(options, method, 'error', true);
			return {
				kind: 'response',
				payload: sessionError.payload,
				headers: {},
				httpStatus: sessionError.status,
				useErrorEnvelope: true,
				eventId,
			};
		}
	}

	const isNotification = id === undefined || id === null;
	if (isNotification && method !== 'initialize') {
		emitRequestAnalytics(options, method, 'ok', false);
		return { kind: 'notification' };
	}

	if (options.allowStreaming && method === 'tools/call' && options.responseTransport === 'sse' && acceptsSSE(options.accept)) {
		const dispatchPromise = dispatchMcpMethod({
			id,
			method,
			params,
			ip: options.ip,
			isAuthenticated: options.isAuthenticated,
			rateHeaders,
			serverVersion: options.serverVersion,
			rateLimitKv: options.rateLimitKv,
			quotaCoordinator: options.quotaCoordinator,
			sessionStore: options.sessionStore,
			scanCache: options.scanCache,
			providerSignaturesUrl: options.providerSignaturesUrl,
			providerSignaturesAllowedHosts: options.providerSignaturesAllowedHosts,
			providerSignaturesSha256: options.providerSignaturesSha256,
			analytics: options.analytics,
			profileAccumulator: options.profileAccumulator,
			waitUntil: options.waitUntil,
			createSessionOnInitialize: options.createSessionOnInitialize,
			existingSessionId: options.existingSessionId,
			scoringConfig: options.scoringConfig,
			cacheTtlSeconds: options.cacheTtlSeconds,
			secondaryDohEndpoint: options.secondaryDohEndpoint,
			secondaryDohToken: options.secondaryDohToken,
			country: options.country,
			clientType: options.clientType,
			authTier: options.authTier,
		}).then((dispatchResult) => {
			if (dispatchResult.kind === 'early-error') {
				return dispatchResult.payload;
			}

			logEvent({
				timestamp: new Date().toISOString(),
				requestId: typeof id === 'string' ? id : undefined,
				ip: options.ip,
				tool: dispatchResult.logTool,
				category: dispatchResult.logCategory,
				result: dispatchResult.logResult,
				details: dispatchResult.logDetails,
				durationMs: Date.now() - options.startTime,
				userAgent: options.userAgent,
				severity: dispatchResult.logCategory === 'error' ? 'error' : 'info',
				domain: getDomainFromParams(params),
			});

			const hasJsonRpcError = typeof dispatchResult.payload === 'object' && dispatchResult.payload !== null && 'error' in dispatchResult.payload;
			emitRequestAnalytics(options, method, hasJsonRpcError ? 'error' : 'ok', hasJsonRpcError);
			return dispatchResult.payload;
		});

		return {
			kind: 'response',
			payload: null,
			headers: { ...rateHeaders },
			httpStatus: 200,
			useErrorEnvelope: false,
			eventId,
			streamOperation: dispatchPromise,
		};
	}

	try {
		const dispatchResult = await dispatchMcpMethod({
			id,
			method,
			params,
			ip: options.ip,
			isAuthenticated: options.isAuthenticated,
			rateHeaders,
			serverVersion: options.serverVersion,
			rateLimitKv: options.rateLimitKv,
			quotaCoordinator: options.quotaCoordinator,
			sessionStore: options.sessionStore,
			scanCache: options.scanCache,
			providerSignaturesUrl: options.providerSignaturesUrl,
			providerSignaturesAllowedHosts: options.providerSignaturesAllowedHosts,
			providerSignaturesSha256: options.providerSignaturesSha256,
			analytics: options.analytics,
			profileAccumulator: options.profileAccumulator,
			waitUntil: options.waitUntil,
			createSessionOnInitialize: options.createSessionOnInitialize,
			existingSessionId: options.existingSessionId,
			scoringConfig: options.scoringConfig,
			cacheTtlSeconds: options.cacheTtlSeconds,
			secondaryDohEndpoint: options.secondaryDohEndpoint,
			secondaryDohToken: options.secondaryDohToken,
			country: options.country,
			clientType: options.clientType,
			authTier: options.authTier,
		});

		if (dispatchResult.kind === 'early-error') {
			return {
				kind: 'response',
				payload: dispatchResult.payload,
				headers: dispatchResult.headers,
				httpStatus: dispatchResult.status,
				useErrorEnvelope: true,
				eventId,
			};
		}

		const headers: Record<string, string> = {};
		if (dispatchResult.newSessionId) {
			headers['mcp-session-id'] = dispatchResult.newSessionId;
		}
		Object.assign(headers, rateHeaders);

		logEvent({
			timestamp: new Date().toISOString(),
			requestId: typeof id === 'string' ? id : undefined,
			ip: options.ip,
			tool: dispatchResult.logTool,
			category: dispatchResult.logCategory,
			result: dispatchResult.logResult,
			details: dispatchResult.logDetails,
			durationMs: Date.now() - options.startTime,
			userAgent: options.userAgent,
			severity: dispatchResult.logCategory === 'error' ? 'error' : 'info',
			domain: getDomainFromParams(params),
		});

		const hasJsonRpcError = typeof dispatchResult.payload === 'object' && dispatchResult.payload !== null && 'error' in dispatchResult.payload;
		emitRequestAnalytics(options, method, hasJsonRpcError ? 'error' : 'ok', hasJsonRpcError);

		return {
			kind: 'response',
			payload: dispatchResult.payload,
			headers,
			httpStatus: 200,
			useErrorEnvelope: false,
			eventId,
		};
	} catch (err) {
		emitRequestAnalytics(options, method, 'error', true);
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			ip: options.ip,
			requestId: typeof options.body?.id === 'string' ? options.body.id : undefined,
			tool: typeof options.body?.method === 'string' ? options.body.method : undefined,
			details: { params: options.body?.params && typeof options.body.params === 'object' ? { keys: Object.keys(options.body.params).sort().slice(0, 25) } : undefined },
			durationMs: Date.now() - options.startTime,
			userAgent: options.userAgent,
		});
		return {
			kind: 'response',
			payload: jsonRpcError(id, JSON_RPC_ERRORS.INTERNAL_ERROR, sanitizeErrorMessage(err, 'Internal server error')),
			headers: {},
			httpStatus: 500,
			useErrorEnvelope: true,
			eventId,
		};
	}
}