// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS Security MCP Server - Main Entry Point
 *
 * Cloudflare Worker implementing the Model Context Protocol (MCP)
 * with DNS security analysis tools. Uses Hono framework for routing.
 *
 * Implements MCP transports:
 *   GET  /health        - Worker health check
 *   POST /mcp           - Streamable HTTP JSON-RPC 2.0 endpoint
 *   GET  /mcp           - Streamable HTTP SSE stream or legacy SSE bootstrap
 *   DELETE /mcp         - Session termination
 *   POST /mcp/messages  - Legacy HTTP+SSE client-to-server messages
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { checkRateLimit, checkToolDailyRateLimit } from './lib/rate-limiter';
import { logEvent, logError, sanitizeHeadersForLog } from './lib/log';
import { jsonRpcError, JSON_RPC_ERRORS } from './lib/json-rpc';
import { normalizeHeaders, parseJsonRpcRequest, readRequestBody } from './mcp/request';
import { createSession, deleteSession, validateSession } from './lib/session';
import { unauthorizedResponse } from './lib/auth';
import { sseEvent, acceptsSSE, createSseStream, sseErrorResponse, createStreamingSseResponse } from './lib/sse';
import { createAnalyticsClient } from './lib/analytics';
import type { JsonRpcRequest } from './lib/json-rpc';
import { buildControlPlaneRateLimitResponse, resolveSseSession, validateSessionRequest } from './mcp/route-gates';
import { MAX_REQUEST_BODY_BYTES, FREE_TOOL_DAILY_LIMITS } from './lib/config';
import { validateDomain, sanitizeDomain } from './lib/sanitize';
import { scanDomain } from './tools/scan-domain';
import { gradeBadge, errorBadge } from './lib/badge';
import { SERVER_VERSION } from './lib/server-version';
import { executeMcpRequest } from './mcp/execute';
import { parseScoringConfig } from './lib/scoring-config';
import { closeLegacyStream, enqueueLegacyMessage, openLegacySseStream } from './lib/legacy-sse';
import { internalRoutes } from './internal';
export { QuotaCoordinator } from './lib/quota-coordinator';
export { ProfileAccumulator } from './lib/profile-accumulator';

let hasLoggedAnalyticsBindingStatus = false;

function logAnalyticsBindingStatus(enabled: boolean): void {
	if (hasLoggedAnalyticsBindingStatus) return;
	hasLoggedAnalyticsBindingStatus = true;
	logEvent({
		timestamp: new Date().toISOString(),
		category: 'analytics',
		result: enabled ? 'enabled' : 'disabled',
		severity: enabled ? 'info' : 'warn',
		details: {
			message: enabled
				? 'Analytics Engine binding detected'
				: 'Analytics Engine binding missing; telemetry emits are no-op',
		},
	});
}

type BvMcpEnv = {
	RATE_LIMIT?: KVNamespace;
	SCAN_CACHE?: KVNamespace;
	SESSION_STORE?: KVNamespace;
	QUOTA_COORDINATOR?: DurableObjectNamespace;
	PROFILE_ACCUMULATOR?: DurableObjectNamespace;
	MCP_ANALYTICS?: AnalyticsEngineDataset;
	BV_API_KEY?: string;
	BV_WEB?: Fetcher;
	BV_WEB_INTERNAL_KEY?: string;
	ALLOWED_ORIGINS?: string;
	PROVIDER_SIGNATURES_URL?: string;
	PROVIDER_SIGNATURES_ALLOWED_HOSTS?: string;
	PROVIDER_SIGNATURES_SHA256?: string;
	SCORING_CONFIG?: string;
};

import type { TierAuthResult } from './lib/tier-auth';
import { resolveTier } from './lib/tier-auth';

const app = new Hono<{ Bindings: BvMcpEnv; Variables: { isAuthenticated: boolean; tierAuthResult: TierAuthResult } }>();
const mcpPaths = ['/mcp', '/mcp/messages', '/mcp/sse'] as const;

for (const path of mcpPaths) {
	app.use(
		path,
		cors({
			origin: (origin, c) => {
				if (!origin) return '';

				try {
					const originHost = new URL(origin).host;
					const requestHost = new URL(c.req.url).host;
					if (originHost === requestHost) return origin;
				} catch {
					// Malformed Origin falls through to rejection below.
				}

				const allowedOrigins = (c.env as BvMcpEnv).ALLOWED_ORIGINS?.trim();
				if (allowedOrigins) {
					const allowed = allowedOrigins
						.split(',')
						.map((value) => value.trim().toLowerCase())
						.filter((value) => value.length > 0);
					if (allowed.includes(origin.toLowerCase())) return origin;
				}

				return '';
			},
			allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
			allowHeaders: ['Content-Type', 'Accept', 'Mcp-Session-Id', 'Authorization'],
			exposeHeaders: ['Mcp-Session-Id'],
		}),
	);

	app.use(path, async (c, next) => {
		const origin = c.req.header('origin');
		if (!origin) return next();

		try {
			const originHost = new URL(origin).host;
			const requestHost = new URL(c.req.url).host;
			if (originHost === requestHost) return next();
		} catch {
			return new Response('Forbidden: invalid Origin header', { status: 403 });
		}

		const allowedOrigins = c.env.ALLOWED_ORIGINS?.trim();
		if (allowedOrigins) {
			const allowed = allowedOrigins
				.split(',')
				.map((value) => value.trim().toLowerCase())
				.filter((value) => value.length > 0);
			if (allowed.includes(origin.toLowerCase())) return next();
		}

		return new Response('Forbidden: unauthorized Origin', { status: 403 });
	});

	app.use(path, async (c, next) => {
		const authHeader = c.req.header('authorization');
		const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;

		// Resolve tier via KV cache → service binding → static BV_API_KEY fallback
		const tierResult = await resolveTier(token, c.env);
		c.set('tierAuthResult', tierResult);
		c.set('isAuthenticated', tierResult.authenticated);

		// If token was provided but not recognized, reject
		if (token && !tierResult.authenticated) {
			return unauthorizedResponse();
		}

		return next();
	});
}

app.use('*', async (c, next) => {
	await next();
	c.header('X-Content-Type-Options', 'nosniff');
	c.header('X-Frame-Options', 'DENY');
	c.header('X-XSS-Protection', '0');
	c.header('Referrer-Policy', 'no-referrer');
	c.header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
	c.header('Content-Security-Policy', "default-src 'self'; script-src 'none'; object-src 'none'; frame-ancestors 'none'");
	c.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
});

app.use('*', async (c, next) => {
	try {
		await next();
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			details: {
				method: c.req.method,
				url: c.req.url,
				headers: sanitizeHeadersForLog(c.req.raw.headers),
			},
		});
		return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error'), 500);
	}
});

app.get('/health', (c) => {
	return c.json({
		status: 'ok',
		service: 'bv-dns-security-mcp',
		timestamp: new Date().toISOString(),
	});
});

app.get('/badge/:domain', async (c) => {
	const svgHeaders = {
		'Content-Type': 'image/svg+xml',
		'Cache-Control': 'public, max-age=300',
	};

	const ip = c.req.header('cf-connecting-ip') ?? 'unknown';
	const rateResult = await checkRateLimit(ip, c.env.RATE_LIMIT, c.env.QUOTA_COORDINATOR);
	if (!rateResult.allowed) {
		return new Response(errorBadge(), { status: 429, headers: svgHeaders });
	}

	const toolQuota = await checkToolDailyRateLimit(ip, 'scan_domain', FREE_TOOL_DAILY_LIMITS.scan_domain, c.env.RATE_LIMIT, c.env.QUOTA_COORDINATOR);
	if (!toolQuota.allowed) {
		return c.text('Rate limit exceeded', 429);
	}

	const rawDomain = c.req.param('domain');
	const validation = validateDomain(rawDomain);
	if (!validation.valid) {
		return new Response(errorBadge(), { status: 400, headers: svgHeaders });
	}

	const domain = sanitizeDomain(rawDomain);
	if (!domain) {
		return new Response(errorBadge(), { status: 400, headers: svgHeaders });
	}

	try {
		const result = await scanDomain(domain, c.env.SCAN_CACHE, {
			profileAccumulator: c.env.PROFILE_ACCUMULATOR,
			waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
			scoringConfig: parseScoringConfig(c.env.SCORING_CONFIG),
		});
		return new Response(gradeBadge(result.score.grade), { status: 200, headers: svgHeaders });
	} catch {
		return new Response(errorBadge(), { status: 500, headers: svgHeaders });
	}
});

app.post('/mcp', async (c) => {
	const startTime = Date.now();
	const analytics = createAnalyticsClient(c.env.MCP_ANALYTICS);
	logAnalyticsBindingStatus(analytics.enabled);
	const headersLc = normalizeHeaders(c.req.raw.headers);
	const accept = headersLc['accept'];
	const ip = headersLc['cf-connecting-ip'] ?? 'unknown';
	const isAuthenticated = c.get('isAuthenticated');
	const tierAuthResult = c.get('tierAuthResult');

	const bodyReadResult = await readRequestBody(c.req.raw, MAX_REQUEST_BODY_BYTES);
	if (!bodyReadResult.ok) {
		return sseErrorResponse(bodyReadResult.payload!, bodyReadResult.status!, accept);
	}

	const parsedRequest = parseJsonRpcRequest(bodyReadResult.rawBody!);
	if (!parsedRequest.ok) {
		logError('Parse error: invalid JSON', {
			severity: 'error',
			ip,
			details: { bodyLength: bodyReadResult.rawBody!.length, bodyPreviewRedacted: true },
		});
		return sseErrorResponse(parsedRequest.payload!, parsedRequest.status!, accept);
	}

	const parsedBodies = parsedRequest.isBatch ? (parsedRequest.body as unknown[]) : [parsedRequest.body as JsonRpcRequest];
	if (parsedRequest.isBatch) {
		const batch = parsedBodies;
		if (batch.length > 20) {
			return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Batch size exceeds maximum of 20 requests'), 400);
		}

		const results = await Promise.all(
			parsedBodies.map(async (entry) => {
				if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
					return {
						kind: 'response' as const,
						payload: jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC 2.0 request'),
						headers: {},
						httpStatus: 400,
						useErrorEnvelope: true,
					};
				}

				return executeMcpRequest({
					body: entry as JsonRpcRequest,
					allowStreaming: false,
					batchMode: true,
					batchSize: parsedBodies.length,
					responseTransport: acceptsSSE(accept) ? 'sse' : 'json',
					accept,
					startTime,
					ip,
					isAuthenticated,
					tierAuthResult,
					userAgent: headersLc['user-agent'],
					sessionId: headersLc['mcp-session-id'],
					validateSession: true,
					sessionErrorMessage: 'Bad Request: missing session',
					createSessionOnInitialize: true,
					serverVersion: SERVER_VERSION,
					rateLimitKv: c.env.RATE_LIMIT,
					quotaCoordinator: c.env.QUOTA_COORDINATOR,
					sessionStore: c.env.SESSION_STORE,
					scanCache: c.env.SCAN_CACHE,
					providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
					providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS,
					providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
					analytics,
					profileAccumulator: c.env.PROFILE_ACCUMULATOR,
					waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
				scoringConfig: parseScoringConfig(c.env.SCORING_CONFIG),
				});
			}),
		);

		const responsePayloads = results.flatMap((result) => (result.kind === 'response' ? [result.payload] : []));
		if (responsePayloads.length === 0) {
			return new Response(null, { status: 202 });
		}

		if (acceptsSSE(accept)) {
			const ssePayload = sseEvent(responsePayloads);
			return new Response(ssePayload, {
				status: 200,
				headers: {
					'Content-Type': 'text/event-stream',
					'Cache-Control': 'no-cache',
					'Content-Length': String(new TextEncoder().encode(ssePayload).byteLength),
				},
			});
		}

		return c.json(responsePayloads, { status: 200 });
	}

	const singleResult = await executeMcpRequest({
		body: parsedBodies[0] as JsonRpcRequest,
		allowStreaming: true,
		batchMode: false,
		batchSize: 1,
		responseTransport: acceptsSSE(accept) ? 'sse' : 'json',
		accept,
		startTime,
		ip,
		isAuthenticated,
		tierAuthResult,
		userAgent: headersLc['user-agent'],
		sessionId: headersLc['mcp-session-id'],
		validateSession: true,
		sessionErrorMessage: 'Bad Request: missing session',
		createSessionOnInitialize: true,
		serverVersion: SERVER_VERSION,
		rateLimitKv: c.env.RATE_LIMIT,
		quotaCoordinator: c.env.QUOTA_COORDINATOR,
		sessionStore: c.env.SESSION_STORE,
		scanCache: c.env.SCAN_CACHE,
		providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
		providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS,
		providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
		analytics,
		profileAccumulator: c.env.PROFILE_ACCUMULATOR,
		waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
		scoringConfig: parseScoringConfig(c.env.SCORING_CONFIG),
	});

	if (singleResult.kind === 'notification') {
		return new Response(null, { status: 202 });
	}

	if (singleResult.streamOperation) {
		return createStreamingSseResponse(
			singleResult.streamOperation,
			(payload) => sseEvent(payload, singleResult.eventId),
			singleResult.headers,
		);
	}

	if (acceptsSSE(accept)) {
		if (singleResult.useErrorEnvelope) {
			return sseErrorResponse(singleResult.payload, singleResult.httpStatus, accept, singleResult.headers, singleResult.eventId);
		}

		const ssePayload = sseEvent(singleResult.payload, singleResult.eventId);
		return new Response(ssePayload, {
			status: 200,
			headers: {
				'Content-Type': 'text/event-stream',
				'Cache-Control': 'no-cache',
				'Content-Length': String(new TextEncoder().encode(ssePayload).byteLength),
				...singleResult.headers,
			},
		});
	}

	return Response.json(singleResult.payload, {
		status: singleResult.useErrorEnvelope ? singleResult.httpStatus : 200,
		headers: singleResult.headers,
	});
});

app.post('/mcp/messages', async (c) => {
	const startTime = Date.now();
	const analytics = createAnalyticsClient(c.env.MCP_ANALYTICS);
	logAnalyticsBindingStatus(analytics.enabled);
	const headersLc = normalizeHeaders(c.req.raw.headers);
	const ip = headersLc['cf-connecting-ip'] ?? 'unknown';
	const isAuthenticated = c.get('isAuthenticated');
	const tierAuthResult = c.get('tierAuthResult');
	const sessionId = c.req.query('sessionId');

	if (!sessionId) {
		return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Bad Request: missing session'), 400);
	}

	// Early session validation — return HTTP 404 directly for expired/terminated sessions
	// so legacy SSE clients see the error instead of getting 202 with an undeliverable SSE message
	if (!(await validateSession(sessionId, c.env.SESSION_STORE))) {
		closeLegacyStream(sessionId);
		return c.json(
			jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Not Found: session expired or terminated'),
			404,
		);
	}

	const bodyReadResult = await readRequestBody(c.req.raw, MAX_REQUEST_BODY_BYTES);
	if (!bodyReadResult.ok) {
		return Response.json(bodyReadResult.payload, { status: bodyReadResult.status });
	}

	const parsedRequest = parseJsonRpcRequest(bodyReadResult.rawBody!);
	if (!parsedRequest.ok) {
		logError('Parse error: invalid JSON', {
			severity: 'error',
			ip,
			details: { bodyLength: bodyReadResult.rawBody!.length, bodyPreviewRedacted: true },
		});
		return Response.json(parsedRequest.payload, { status: parsedRequest.status });
	}

	const parsedBodies = parsedRequest.isBatch ? (parsedRequest.body as unknown[]) : [parsedRequest.body as JsonRpcRequest];
	const results = await Promise.all(
		parsedBodies.map(async (entry) => {
			if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
				return {
					kind: 'response' as const,
					payload: jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC 2.0 request'),
					headers: {},
					httpStatus: 400,
					useErrorEnvelope: true,
				};
			}

			return executeMcpRequest({
				body: entry as JsonRpcRequest,
				allowStreaming: false,
				batchMode: parsedRequest.isBatch === true,
				batchSize: parsedBodies.length,
				responseTransport: 'sse',
				startTime,
				ip,
				isAuthenticated,
				tierAuthResult,
				userAgent: headersLc['user-agent'],
				sessionId,
				validateSession: true,
				sessionErrorMessage: 'Bad Request: missing session',
				createSessionOnInitialize: false,
				existingSessionId: sessionId,
				serverVersion: SERVER_VERSION,
				rateLimitKv: c.env.RATE_LIMIT,
				quotaCoordinator: c.env.QUOTA_COORDINATOR,
				sessionStore: c.env.SESSION_STORE,
				scanCache: c.env.SCAN_CACHE,
				providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
				providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS,
				providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
				analytics,
				profileAccumulator: c.env.PROFILE_ACCUMULATOR,
				waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
			});
		}),
	);

	const responsePayloads = results.flatMap((result) => (result.kind === 'response' ? [result.payload] : []));
	if (responsePayloads.length > 0) {
		enqueueLegacyMessage(sessionId, parsedRequest.isBatch ? responsePayloads : responsePayloads[0]);
	}

	return new Response(null, { status: 202 });
});

app.get('/mcp', async (c) => {
	if (!acceptsSSE(c.req.header('accept'))) {
		return new Response('Not Acceptable: Accept must include text/event-stream', { status: 406 });
	}

	const sessionId = c.req.header('mcp-session-id');
	const ip = c.req.header('cf-connecting-ip') ?? 'unknown';
	const isAuthenticated = c.get('isAuthenticated');
	const controlPlaneLimited = await buildControlPlaneRateLimitResponse(
		ip,
		c.env.RATE_LIMIT,
		'sse/connect',
		isAuthenticated,
		null,
		undefined,
		c.env.QUOTA_COORDINATOR,
	);
	if (controlPlaneLimited) {
		return controlPlaneLimited;
	}

	const sseSession = await resolveSseSession({
		sessionId,
		ip,
		sessionStore: c.env.SESSION_STORE,
	});
	if (sseSession.response) {
		return sseSession.response;
	}

	return new Response(createSseStream(': stream opened\n\n'), {
		status: 200,
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache',
			'mcp-session-id': sseSession.sessionId!,
		},
	});
});

app.get('/mcp/sse', async (c) => {
	if (!acceptsSSE(c.req.header('accept'))) {
		return new Response('Not Acceptable: Accept must include text/event-stream', { status: 406 });
	}

	const ip = c.req.header('cf-connecting-ip') ?? 'unknown';
	const isAuthenticated = c.get('isAuthenticated');
	const controlPlaneLimited = await buildControlPlaneRateLimitResponse(
		ip,
		c.env.RATE_LIMIT,
		'sse/connect',
		isAuthenticated,
		null,
		undefined,
		c.env.QUOTA_COORDINATOR,
	);
	if (controlPlaneLimited) {
		return controlPlaneLimited;
	}

	const legacySessionId = await createSession(c.env.SESSION_STORE);
	const endpointUrl = new URL(`/mcp/messages?sessionId=${encodeURIComponent(legacySessionId)}`, c.req.url).toString();
	return openLegacySseStream(legacySessionId, endpointUrl);
});

app.delete('/mcp', async (c) => {
	const ip = c.req.header('cf-connecting-ip') ?? 'unknown';
	const isAuthenticated = c.get('isAuthenticated');
	const controlPlaneLimited = await buildControlPlaneRateLimitResponse(
		ip,
		c.env.RATE_LIMIT,
		'session/delete',
		isAuthenticated,
		null,
		undefined,
		c.env.QUOTA_COORDINATOR,
	);
	if (controlPlaneLimited) {
		return controlPlaneLimited;
	}

	const sessionId = c.req.header('mcp-session-id') ?? c.req.query('sessionId');
	const sessionError = await validateSessionRequest(
		sessionId,
		c.env.SESSION_STORE,
		null,
		'Bad Request: missing session',
	);
	if (sessionError) {
		return c.json(sessionError.payload, sessionError.status);
	}

	await deleteSession(sessionId!, c.env.SESSION_STORE);
	closeLegacyStream(sessionId!);
	return new Response(null, { status: 204 });
});

app.route('/internal', internalRoutes);

app.all('*', (c) => {
	return c.json({ error: 'Not found' }, 404);
});

export default app;
