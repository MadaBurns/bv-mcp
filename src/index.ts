/**
 * DNS Security MCP Server - Main Entry Point
 *
 * Cloudflare Worker implementing the Model Context Protocol (MCP)
 * with DNS security analysis tools. Uses Hono framework for routing.
 *
 * Implements MCP Streamable HTTP transport (spec 2025-03-26):
 *   GET  /health      - Worker health check
 *   POST /mcp         - MCP JSON-RPC 2.0 endpoint (supports SSE streaming)
 *   GET  /mcp         - SSE stream for server-to-client notifications
 *   DELETE /mcp       - Session termination
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { checkRateLimit, checkToolDailyRateLimit, checkGlobalDailyLimit } from './lib/rate-limiter';
import { logEvent, logError, sanitizeHeadersForLog } from './lib/log';
import { jsonRpcError, JSON_RPC_ERRORS, sanitizeErrorMessage } from './lib/json-rpc';
import {
	normalizeHeaders,
	parseJsonRpcRequest,
	readRequestBody,
	summarizeParamsForLog,
	validateJsonRpcRequest,
} from './mcp/request';
import { deleteSession } from './lib/session';
import { isAuthorizedRequest, unauthorizedResponse } from './lib/auth';
import { sseEvent, acceptsSSE, createSseStream, sseErrorResponse } from './lib/sse';
import { createAnalyticsClient } from './lib/analytics';
import type { JsonRpcRequest } from './lib/json-rpc';
import { dispatchMcpMethod } from './mcp/dispatch';
import { buildControlPlaneRateLimitResponse, resolveSseSession, validateSessionRequest } from './mcp/route-gates';
import { MAX_REQUEST_BODY_BYTES, FREE_TOOL_DAILY_LIMITS, GLOBAL_DAILY_TOOL_LIMIT } from './lib/config';
import { validateDomain, sanitizeDomain } from './lib/sanitize';
import { scanDomain } from './tools/scan-domain';
import { gradeBadge, errorBadge } from './lib/badge';
export { QuotaCoordinator } from './lib/quota-coordinator';

/** Server version — keep in sync with package.json */
const SERVER_VERSION = '1.0.0';
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

// ---------------------------------------------------------------------------
// Hono app
// ---------------------------------------------------------------------------
// Explicitly type env bindings for clarity and safety
type BvMcpEnv = {
	RATE_LIMIT?: KVNamespace;
	SCAN_CACHE?: KVNamespace;
	SESSION_STORE?: KVNamespace;
	QUOTA_COORDINATOR?: DurableObjectNamespace;
	MCP_ANALYTICS?: AnalyticsEngineDataset;
	BV_API_KEY?: string;
	ALLOWED_ORIGINS?: string;
	PROVIDER_SIGNATURES_URL?: string;
	PROVIDER_SIGNATURES_ALLOWED_HOSTS?: string;
	PROVIDER_SIGNATURES_SHA256?: string;
};

const app = new Hono<{ Bindings: BvMcpEnv; Variables: { isAuthenticated: boolean } }>();


// CORS for MCP clients — dynamic origin so we never send Access-Control-Allow-Origin: *
// when a cross-origin browser request arrives. The origin callback echoes back the
// validated origin for allowed requests; non-browser requests (no Origin header)
// get '*' which is safe since they aren't subject to browser CORS enforcement.
app.use(
	'/mcp',
	cors({
		origin: (origin, c) => {
			// No Origin header → non-browser client, allow
			if (!origin) return '*';

			// Same-origin check: compare Origin host to request Host
			try {
				const originHost = new URL(origin).host;
				const requestHost = new URL(c.req.url).host;
				if (originHost === requestHost) return origin;
			} catch {
				// Malformed Origin → falls through to return '' below
			}

			// Check explicit allowlist from ALLOWED_ORIGINS env var
			// c.env is already typed as BvMcpEnv via Hono generics; cast is redundant but harmless
			const allowedOrigins = (c.env as BvMcpEnv).ALLOWED_ORIGINS?.trim();
			if (allowedOrigins) {
				const allowed = allowedOrigins
					.split(',')
					.map((o) => o.trim().toLowerCase())
					.filter((o) => o.length > 0);
				if (allowed.includes(origin.toLowerCase())) return origin;
			}

			// Unauthorized origin — return empty string so the CORS header
			// is not set to a permissive value; the Origin middleware below
			// will reject with 403.
			return '';
		},
		allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
		allowHeaders: ['Content-Type', 'Accept', 'Mcp-Session-Id', 'Authorization'],
		exposeHeaders: ['Mcp-Session-Id'],
	}),
);

// Origin header validation — prevents DNS rebinding and unauthorized cross-origin access.
// Per MCP spec: "Servers MUST validate the Origin header."
// No Origin header → allow (non-browser / server-to-server clients).
// Origin present → must match request host or be in ALLOWED_ORIGINS env var.
// This middleware complements the CORS origin callback above: the CORS layer
// sets the correct Access-Control-Allow-Origin header, while this middleware
// explicitly blocks unauthorized cross-origin requests with 403.
app.use('/mcp', async (c, next) => {
	const origin = c.req.header('origin');
	if (!origin) return next();

	// Same-origin check: compare Origin host to request Host
	try {
		const originHost = new URL(origin).host;
		const requestHost = new URL(c.req.url).host;
		if (originHost === requestHost) return next();
	} catch {
		// Malformed Origin → reject
		return new Response('Forbidden: invalid Origin header', { status: 403 });
	}

	// Check explicit allowlist from ALLOWED_ORIGINS env var
	const allowedOrigins = c.env.ALLOWED_ORIGINS?.trim();
	if (allowedOrigins) {
		const allowed = allowedOrigins
			.split(',')
			.map((o) => o.trim().toLowerCase())
			.filter((o) => o.length > 0);
		if (allowed.includes(origin.toLowerCase())) return next();
	}

	return new Response('Forbidden: unauthorized Origin', { status: 403 });
});

// Security headers middleware — apply to all responses (registered first so it
// wraps everything including error-handler responses)
app.use('*', async (c, next) => {
	await next();
	// Prevent MIME type sniffing
	c.header('X-Content-Type-Options', 'nosniff');
	// Prevent frame embedding (clickjacking)
	c.header('X-Frame-Options', 'DENY');
	// Enable built-in XSS protection
	c.header('X-XSS-Protection', '1; mode=block');
	// Restrict referrer disclosure
	c.header('Referrer-Policy', 'no-referrer');
	// Disable unnecessary APIs
	c.header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
	// Content Security Policy: no inline scripts, no third-party content
	c.header('Content-Security-Policy', "default-src 'self'; script-src 'none'; object-src 'none'; frame-ancestors 'none'");
	// HTTP Strict Transport Security: 1 year, include subdomains
	c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});

// Centralized error handling middleware
app.use('*', async (c, next) => {
       try {
	       await next();
       } catch (err) {
	       // Structured error logging
	       const reqInfo = {
		       method: c.req.method,
		       url: c.req.url,
		       headers: sanitizeHeadersForLog(c.req.raw.headers),
	       };
	       logError(err instanceof Error ? err : String(err), {
		       severity: 'error',
		       details: reqInfo,
	       });
	       // Sanitize error response
	       return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error'), 500);
       }
});

// Optional bearer auth for /mcp — three modes:
//   1. No BV_API_KEY configured → everyone is unauthenticated (open mode)
//   2. BV_API_KEY configured + no auth header → unauthenticated, rate-limited
//   3. BV_API_KEY configured + valid bearer → authenticated, bypasses rate limits
//   4. BV_API_KEY configured + invalid bearer → 401 rejected
// This allows public users to use the server with rate limits while
// authenticated users (e.g. the operator) get unlimited access.
app.use('/mcp', async (c, next) => {
       const { BV_API_KEY } = c.env;
       const apiKey = BV_API_KEY?.trim();
       if (!apiKey) {
	       c.set('isAuthenticated', false);
	       return next();
       }

       const authHeader = c.req.header('authorization');
       if (!authHeader) {
	       // No token provided — allow through as unauthenticated (rate-limited)
	       c.set('isAuthenticated', false);
	       return next();
       }

       if (!(await isAuthorizedRequest(authHeader, apiKey))) {
	       return unauthorizedResponse();
       }

       c.set('isAuthenticated', true);
       return next();
});

// Health endpoint
app.get('/health', (c) => {
	return c.json({
		status: 'ok',
		service: 'bv-dns-security-mcp',
		analytics: {
			enabled: Boolean(c.env.MCP_ANALYTICS),
		},
		timestamp: new Date().toISOString(),
	});
});

// ---------------------------------------------------------------------------
// Badge endpoint — GET /badge/:domain
// ---------------------------------------------------------------------------
app.get('/badge/:domain', async (c) => {
	const svgHeaders = {
		'Content-Type': 'image/svg+xml',
		'Cache-Control': 'public, max-age=300',
	};

	// Rate limiting by IP (unauthenticated only)
	const ip = c.req.header('cf-connecting-ip') ?? 'unknown';
	const rateResult = await checkRateLimit(ip, c.env.RATE_LIMIT, c.env.QUOTA_COORDINATOR);
	if (!rateResult.allowed) {
		return new Response(errorBadge(), { status: 429, headers: svgHeaders });
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
		const result = await scanDomain(domain, c.env.SCAN_CACHE);
		const svg = gradeBadge(result.score.grade);
		return new Response(svg, { status: 200, headers: svgHeaders });
	} catch {
		return new Response(errorBadge(), { status: 500, headers: svgHeaders });
	}
});

// ---------------------------------------------------------------------------
// MCP Streamable HTTP transport — POST /mcp
// ---------------------------------------------------------------------------
app.post('/mcp', async (c) => {
	const startTime = Date.now();
	const analytics = createAnalyticsClient(c.env.MCP_ANALYTICS);
	logAnalyticsBindingStatus(analytics.enabled);
	const headersLc = normalizeHeaders(c.req.raw.headers);
	const accept = headersLc['accept'];

	// Rate limiting by IP — only trust cf-connecting-ip (set by Cloudflare edge)
	// Do NOT fall back to x-forwarded-for as it is client-controlled and spoofable
	const ip = headersLc['cf-connecting-ip'] ?? 'unknown';

	// Authenticated requests bypass rate limiting — the auth middleware already
	// validated the token and stored the result on the Hono context.
	const isAuthenticated = c.get('isAuthenticated');

	const bodyReadResult = await readRequestBody(c.req.raw, MAX_REQUEST_BODY_BYTES);
	if (!bodyReadResult.ok) {
		return sseErrorResponse(bodyReadResult.payload!, bodyReadResult.status!, accept);
	}
	const rawBody = bodyReadResult.rawBody!;

	// Parse JSON-RPC request
		const parsedRequest = parseJsonRpcRequest(rawBody);
	if (!parsedRequest.ok) {
		logError('Parse error: invalid JSON', {
			severity: 'error',
			ip,
			details: { bodyLength: rawBody.length, bodyPreviewRedacted: true },
		});
		return sseErrorResponse(parsedRequest.payload!, parsedRequest.status!, accept);
	}
	const body: JsonRpcRequest = parsedRequest.body!;

	// Validate JSON-RPC 2.0 structure
	const validationError = validateJsonRpcRequest(body);
	if (validationError) {
		analytics.emitRequestEvent({
			method: typeof body?.method === 'string' ? body.method : 'invalid',
			status: 'error',
			durationMs: Date.now() - startTime,
			isAuthenticated,
			hasJsonRpcError: true,
			transport: 'json',
		});
		return sseErrorResponse(validationError.payload, validationError.status, accept);
	}

	const { id, method, params } = body;

	// Rate limiting — tools/call uses stricter quotas, while protocol/session traffic
	// is still throttled under a lighter control-plane budget. Authenticated requests bypass entirely.
	let rateHeaders: Record<string, string> = {};
	if (!isAuthenticated && method === 'tools/call') {
		// Global daily cap — cost ceiling across all unauthenticated IPs
		const globalResult = await checkGlobalDailyLimit(GLOBAL_DAILY_TOOL_LIMIT, c.env.RATE_LIMIT, c.env.QUOTA_COORDINATOR);
		if (!globalResult.allowed) {
			const globalHeaders: Record<string, string> = {};
			if (globalResult.retryAfterMs !== undefined) {
				globalHeaders['retry-after'] = String(Math.ceil(globalResult.retryAfterMs / 1000));
			}
			analytics.emitRequestEvent({
				method,
				status: 'error',
				durationMs: Date.now() - startTime,
				isAuthenticated,
				hasJsonRpcError: true,
				transport: 'json',
			});
			return sseErrorResponse(
				jsonRpcError(
					id,
					JSON_RPC_ERRORS.RATE_LIMITED,
					'Service capacity reached for today. Please try again tomorrow or deploy your own instance.',
				),
				429,
				accept,
				globalHeaders,
				id != null ? String(id) : undefined,
			);
		}

		const rateResult = await checkRateLimit(ip, c.env.RATE_LIMIT, c.env.QUOTA_COORDINATOR);
		rateHeaders = {
			'x-ratelimit-limit': '30',
			'x-ratelimit-remaining': String(rateResult.minuteRemaining),
		};
		if (!rateResult.allowed) {
			if (rateResult.retryAfterMs !== undefined) {
				rateHeaders['retry-after'] = String(Math.ceil(rateResult.retryAfterMs / 1000));
			}
			analytics.emitRequestEvent({
				method,
				status: 'error',
				durationMs: Date.now() - startTime,
				isAuthenticated,
				hasJsonRpcError: true,
				transport: 'json',
			});
			return sseErrorResponse(
				jsonRpcError(
					id,
					JSON_RPC_ERRORS.RATE_LIMITED,
					`Rate limit exceeded. Retry after ${Math.ceil((rateResult.retryAfterMs ?? 0) / 1000)}s`,
				),
				429,
				accept,
				rateHeaders,
				id != null ? String(id) : undefined,
			);
		}

		const toolNameRaw =
			// 'in' guard ensures 'name' exists; cast to Record is safe after typeof+null check
			typeof params === 'object' && params !== null && 'name' in params ? (params as Record<string, unknown>).name : undefined;
		const toolName = typeof toolNameRaw === 'string' ? toolNameRaw.trim().toLowerCase() : '';
		const toolDailyLimit = toolName ? FREE_TOOL_DAILY_LIMITS[toolName] : undefined;
		if (toolDailyLimit !== undefined) {
			const toolQuotaResult = await checkToolDailyRateLimit(ip, toolName, toolDailyLimit, c.env.RATE_LIMIT, c.env.QUOTA_COORDINATOR);
			rateHeaders['x-quota-limit'] = String(toolQuotaResult.limit);
			rateHeaders['x-quota-remaining'] = String(toolQuotaResult.remaining);
			if (!toolQuotaResult.allowed) {
				if (toolQuotaResult.retryAfterMs !== undefined) {
					rateHeaders['retry-after'] = String(Math.ceil(toolQuotaResult.retryAfterMs / 1000));
				}
				analytics.emitRequestEvent({
					method,
					status: 'error',
					durationMs: Date.now() - startTime,
					isAuthenticated,
					hasJsonRpcError: true,
					transport: 'json',
				});
				return sseErrorResponse(
					jsonRpcError(
						id,
						JSON_RPC_ERRORS.RATE_LIMITED,
						`Rate limit exceeded. ${toolName} is limited to ${toolDailyLimit} requests per day for free tier users.`,
					),
					429,
					accept,
					rateHeaders,
					id != null ? String(id) : undefined,
				);
			}
		}
	}

	if (method !== 'tools/call') {
		const controlPlaneLimited = await buildControlPlaneRateLimitResponse(
			ip,
			c.env.RATE_LIMIT,
			method,
			isAuthenticated,
			id,
			accept,
			c.env.QUOTA_COORDINATOR,
		);
		if (controlPlaneLimited) {
			analytics.emitRequestEvent({
				method,
				status: 'error',
				durationMs: Date.now() - startTime,
				isAuthenticated,
				hasJsonRpcError: true,
				transport: 'json',
			});
			return controlPlaneLimited;
		}
	}

	// Session validation — non-initialize requests must carry a valid session ID
	const sessionId = headersLc['mcp-session-id'];

	if (method !== 'initialize') {
		const sessionError = await validateSessionRequest(
			sessionId,
			c.env.SESSION_STORE,
			id,
			'Bad Request: missing session',
		);
		if (sessionError) {
			analytics.emitRequestEvent({
				method,
				status: 'error',
				durationMs: Date.now() - startTime,
				isAuthenticated,
				hasJsonRpcError: true,
				transport: 'json',
			});
			return sseErrorResponse(sessionError.payload, sessionError.status, accept, undefined, id != null ? String(id) : undefined);
		}
	}

	// Notifications (no id) don't execute tools.
	// tools/call notifications are already rate-limited above once per request.
	const isNotification = body.id === undefined || body.id === null;
	if (isNotification && method !== 'initialize') {
		analytics.emitRequestEvent({
			method,
			status: 'ok',
			durationMs: Date.now() - startTime,
			isAuthenticated,
			hasJsonRpcError: false,
			transport: 'json',
		});
		// Per spec: notifications/responses → 202 Accepted
		return new Response(null, { status: 202 });
	}

	       try {
		       const dispatchResult = await dispatchMcpMethod({
			       id,
			       method,
			       params,
			       ip,
			       isAuthenticated,
			       rateHeaders,
			       serverVersion: SERVER_VERSION,
			       rateLimitKv: c.env.RATE_LIMIT,
			       quotaCoordinator: c.env.QUOTA_COORDINATOR,
			       sessionStore: c.env.SESSION_STORE,
			       scanCache: c.env.SCAN_CACHE,
			       providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
			       providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS,
			       providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
			       analytics,
		       });

		       if (dispatchResult.kind === 'early-error') {
			       return sseErrorResponse(dispatchResult.payload, dispatchResult.status, accept, dispatchResult.headers);
		       }

		       const responsePayload = dispatchResult.payload;
		       const newSessionId = dispatchResult.newSessionId;
		       const logCategory = dispatchResult.logCategory;
		       const logTool = dispatchResult.logTool;
		       const logResult = dispatchResult.logResult;
		       const logDetails = dispatchResult.logDetails;

		       // Structured logging for request
		       logEvent({
			       timestamp: new Date().toISOString(),
			       requestId: typeof id === 'string' ? id : undefined,
			       ip,
			       tool: logTool,
			       category: logCategory,
			       result: logResult,
			       details: logDetails,
			       durationMs: Date.now() - startTime,
			       userAgent: headersLc['user-agent'],
			       severity: logCategory === 'error' ? 'error' : 'info',
			       domain: typeof params === 'object' && params && 'domain' in params ? String(params.domain) : undefined,
		       });

		       // Build response headers
		       const headers: Record<string, string> = {};
		       if (newSessionId) {
			       headers['mcp-session-id'] = newSessionId;
		       }
		       // Always include normalized rate limit headers if present
		       Object.assign(headers, rateHeaders);

		       // If client accepts SSE, stream the response as an SSE event
			const hasJsonRpcError = typeof responsePayload === 'object' && responsePayload !== null && 'error' in responsePayload;
		       if (acceptsSSE(accept)) {
				analytics.emitRequestEvent({
					method,
					status: hasJsonRpcError ? 'error' : 'ok',
					durationMs: Date.now() - startTime,
					isAuthenticated,
					hasJsonRpcError,
					transport: 'sse',
				});
				const eventId = id != null ? String(id) : undefined;
			       const ssePayload = sseEvent(responsePayload, eventId);
			       return new Response(ssePayload, {
				       status: 200,
				       headers: {
					       'Content-Type': 'text/event-stream',
					       'Cache-Control': 'no-cache',
					       'Content-Length': String(new TextEncoder().encode(ssePayload).byteLength),
					       ...headers,
				       },
			       });
		       }

		       // Default: plain JSON response (backward compatible)
			analytics.emitRequestEvent({
				method,
				status: hasJsonRpcError ? 'error' : 'ok',
				durationMs: Date.now() - startTime,
				isAuthenticated,
				hasJsonRpcError,
				transport: 'json',
			});
		       return c.json(responsePayload, { status: 200, headers });
	       } catch (err) {
			analytics.emitRequestEvent({
				method: typeof body?.method === 'string' ? body.method : 'unknown',
				status: 'error',
				durationMs: Date.now() - startTime,
				isAuthenticated,
				hasJsonRpcError: true,
				transport: 'json',
			});
		       logError(err instanceof Error ? err : String(err), {
			       severity: 'error',
			       ip,
			       requestId: typeof body?.id === 'string' ? body.id : undefined,
			       tool: typeof body?.method === 'string' ? body.method : undefined,
			       details: { params: summarizeParamsForLog(body?.params) },
			       durationMs: Date.now() - startTime,
			       userAgent: headersLc['user-agent'],
		       });
		       const message = sanitizeErrorMessage(err, 'Internal server error');
		       return sseErrorResponse(
			       jsonRpcError(id, JSON_RPC_ERRORS.INTERNAL_ERROR, message),
			       500,
			       accept,
			       undefined,
			       id != null ? String(id) : undefined,
		       );
	       }
	});

// ---------------------------------------------------------------------------
// MCP Streamable HTTP transport — GET /mcp (SSE stream for notifications)
// ---------------------------------------------------------------------------
app.get('/mcp', async (c) => {
	// Must accept SSE
	if (!acceptsSSE(c.req.header('accept'))) {
		return new Response('Not Acceptable: Accept must include text/event-stream', { status: 406 });
	}

	// Session validation — GET requires an existing session (created via POST initialize)
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
	const effectiveSessionId = sseSession.sessionId!;

	// Open an SSE stream. For this stateless server we keep the stream open
	// briefly then close — a full implementation would push server-initiated
	// notifications here.
	return new Response(createSseStream(': stream opened\n\n'), {
		status: 200,
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache',
			'mcp-session-id': effectiveSessionId,
		},
	});
});

// ---------------------------------------------------------------------------
// MCP Streamable HTTP transport — DELETE /mcp (session termination)
// ---------------------------------------------------------------------------
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

	const sessionId = c.req.header('mcp-session-id');
	const sessionError = await validateSessionRequest(
		sessionId,
		c.env.SESSION_STORE,
		null,
		'Bad Request: missing session',
	);
	if (sessionError) {
		return c.json(sessionError.payload, sessionError.status);
	}

	const validatedSessionId = sessionId!;
	await deleteSession(validatedSessionId, c.env.SESSION_STORE);
	return new Response(null, { status: 204 });
});

// Fallback 404
app.all('*', (c) => {
	return c.json({ error: 'Not found' }, 404);
});

// export default is required by the Cloudflare Workers runtime (fetch handler contract)
export default app;
