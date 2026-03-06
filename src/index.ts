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
import { checkRateLimit, checkToolDailyRateLimit } from './lib/rate-limiter';
import { handleToolsList, handleToolsCall } from './handlers/tools';
import { handleResourcesList, handleResourcesRead } from './handlers/resources';
import { logEvent, logError } from './lib/log';
import { jsonRpcError, jsonRpcSuccess, JSON_RPC_ERRORS, sanitizeErrorMessage } from './lib/json-rpc';
import { createSession, validateSession, deleteSession, checkSessionCreateRateLimit } from './lib/session';
import { isAuthorizedRequest, unauthorizedResponse } from './lib/auth';
import { sseEvent, acceptsSSE, createSseStream } from './lib/sse';
import { createAnalyticsClient } from './lib/analytics';
import type { JsonRpcRequest } from './lib/json-rpc';
import { auditSessionCreated } from './lib/audit';
import { MAX_REQUEST_BODY_BYTES, FREE_TOOL_DAILY_LIMITS } from './lib/config';

/** Server version — keep in sync with package.json */
const SERVER_VERSION = '1.0.3';
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
	MCP_ANALYTICS?: AnalyticsEngineDataset;
	BV_API_KEY?: string;
	PROVIDER_SIGNATURES_URL?: string;
};

const app = new Hono<{ Bindings: BvMcpEnv; Variables: { isAuthenticated: boolean } }>();


// CORS for MCP clients — allow Streamable HTTP methods and headers
app.use(
       '/mcp',
       cors({
	       origin: '*',
	       allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
	       allowHeaders: ['Content-Type', 'Accept', 'Mcp-Session-Id', 'Authorization'],
	       exposeHeaders: ['Mcp-Session-Id'],
       }),
);

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
		       headers: (() => { const h: Record<string, string> = {}; c.req.raw.headers.forEach((v, k) => { if (k !== 'authorization') h[k] = v; }); return h; })(),
	       };
	       logError(err instanceof Error ? err : String(err), {
		       severity: 'error',
		       details: reqInfo,
	       });
	       // Sanitize error response
	       return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error'), 500);
       }
});

// Optional bearer auth for /mcp; open mode when BV_API_KEY is unset/empty.
// Sets `isAuthenticated` on the Hono context so downstream handlers can check
// auth status without re-deriving it.
app.use('/mcp', async (c, next) => {
       const { BV_API_KEY } = c.env;
       const apiKey = BV_API_KEY?.trim();
       if (!apiKey) {
	       c.set('isAuthenticated', false);
	       return next();
       }

       const authHeader = c.req.header('authorization');
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
// MCP Streamable HTTP transport — POST /mcp
// ---------------------------------------------------------------------------
app.post('/mcp', async (c) => {
	const startTime = Date.now();
	const analytics = createAnalyticsClient(c.env.MCP_ANALYTICS);
	logAnalyticsBindingStatus(analytics.enabled);
	// Defensive: normalize all incoming header keys to lowercase
	const rawHeaders: Record<string, string> = {};
	c.req.raw.headers.forEach((v, k) => { rawHeaders[k] = v; });
	const headersLc: Record<string, string> = {};
	for (const [k, v] of Object.entries(rawHeaders)) headersLc[k.toLowerCase()] = v;

	// Rate limiting by IP — only trust cf-connecting-ip (set by Cloudflare edge)
	// Do NOT fall back to x-forwarded-for as it is client-controlled and spoofable
	const ip = headersLc['cf-connecting-ip'] ?? 'unknown';

	// Authenticated requests bypass rate limiting — the auth middleware already
	// validated the token and stored the result on the Hono context.
	const isAuthenticated = c.get('isAuthenticated');

	// Enforce hard 10KB body size limit (even if content-length is missing or wrong)
	let rawBody = '';
	const reader = c.req.raw.body?.getReader();
	if (reader) {
		let total = 0;
		const decoder = new TextDecoder();
		while (true) {
			const { value, done } = await reader.read();
			if (done) break;
			total += value.length;
			if (total > MAX_REQUEST_BODY_BYTES) {
				return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Request body too large'), 413);
			}
			rawBody += decoder.decode(value);
		}
	} else {
		// Fallback for environments without .body (should not occur in Workers)
		rawBody = await c.req.text();
		if (rawBody.length > MAX_REQUEST_BODY_BYTES) {
			return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Request body too large'), 413);
		}
	}

	       // Parse JSON-RPC request
	       let body: JsonRpcRequest;
	       try {
		       body = JSON.parse(rawBody);
	       } catch (err) {
		       logError(err instanceof Error ? err : String(err), {
			       severity: 'error',
			       ip,
			       details: { rawBody },
		       });
		       return c.json(jsonRpcError(null, JSON_RPC_ERRORS.PARSE_ERROR, 'Parse error: invalid JSON'), 400);
	       }

	// Validate JSON-RPC 2.0 structure
	if (body.jsonrpc !== '2.0' || typeof body.method !== 'string') {
		analytics.emitRequestEvent({
			method: typeof body?.method === 'string' ? body.method : 'invalid',
			status: 'error',
			durationMs: Date.now() - startTime,
			isAuthenticated,
			hasJsonRpcError: true,
			transport: 'json',
		});
		return c.json(jsonRpcError(body.id, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC 2.0 request'), 400);
	}

	// Validate JSON-RPC id field type (must be string, number, or null per spec)
	if (body.id !== undefined && body.id !== null && typeof body.id !== 'string' && typeof body.id !== 'number') {
		analytics.emitRequestEvent({
			method: body.method,
			status: 'error',
			durationMs: Date.now() - startTime,
			isAuthenticated,
			hasJsonRpcError: true,
			transport: 'json',
		});
		return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC id: must be string, number, or null'), 400);
	}

	const { id, method, params } = body;

	// Rate limiting — only applied to tools/call (the expensive DNS-lookup operations).
	// Protocol methods (initialize, tools/list, resources/*, ping, notifications/*) are
	// exempt so MCP handshake flows are never blocked. Authenticated requests bypass entirely.
	let rateHeaders: Record<string, string> = {};
	if (!isAuthenticated && method === 'tools/call') {
		const rateResult = await checkRateLimit(ip, c.env.RATE_LIMIT);
		rateHeaders = {
			'x-ratelimit-limit': '10',
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
			return c.json(
				jsonRpcError(
					id,
					JSON_RPC_ERRORS.RATE_LIMITED,
					`Rate limit exceeded. Retry after ${Math.ceil((rateResult.retryAfterMs ?? 0) / 1000)}s`,
				),
				429,
				rateHeaders,
			);
		}

		const toolNameRaw =
			typeof params === 'object' && params !== null && 'name' in params ? (params as Record<string, unknown>).name : undefined;
		const toolName = typeof toolNameRaw === 'string' ? toolNameRaw.trim().toLowerCase() : '';
		const toolDailyLimit = toolName ? FREE_TOOL_DAILY_LIMITS[toolName] : undefined;
		if (toolDailyLimit !== undefined) {
			const toolQuotaResult = await checkToolDailyRateLimit(ip, toolName, toolDailyLimit, c.env.RATE_LIMIT);
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
				return c.json(
					jsonRpcError(
						id,
						JSON_RPC_ERRORS.RATE_LIMITED,
						`Rate limit exceeded. ${toolName} is limited to ${toolDailyLimit} requests per day for free tier users.`,
					),
					429,
					rateHeaders,
				);
			}
		}
	}

	// Session validation — non-initialize requests must carry a valid session ID
	const sessionId = headersLc['mcp-session-id'];

	if (method !== 'initialize') {
		if (!sessionId || !(await validateSession(sessionId, c.env.SESSION_STORE))) {
			analytics.emitRequestEvent({
				method,
				status: 'error',
				durationMs: Date.now() - startTime,
				isAuthenticated,
				hasJsonRpcError: true,
				transport: 'json',
			});
			return c.json(jsonRpcError(id, JSON_RPC_ERRORS.INVALID_REQUEST, 'Bad Request: invalid or missing session'), 400);
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
		       // Dispatch MCP methods and build the JSON-RPC response payload
		       let responsePayload: ReturnType<typeof jsonRpcSuccess> | ReturnType<typeof jsonRpcError>;
		       let newSessionId: string | undefined;
		       let logCategory = 'generic';
		       let logTool: string | undefined;
		       let logResult: string | undefined;
		       let logDetails: unknown;

		       switch (method) {
			       case 'initialize': {
				       if (!isAuthenticated) {
					       const sessionCreateGate = checkSessionCreateRateLimit(ip);
					       if (!sessionCreateGate.allowed) {
						       const retryAfterSeconds = Math.ceil((sessionCreateGate.retryAfterMs ?? 0) / 1000);
						       return c.json(
							       jsonRpcError(id, JSON_RPC_ERRORS.RATE_LIMITED, `Rate limit exceeded. Retry after ${retryAfterSeconds}s`),
							       429,
							       {
								       ...rateHeaders,
								       'retry-after': String(retryAfterSeconds),
							       },
						       );
					       }
				       }
				       newSessionId = await createSession(c.env.SESSION_STORE);
				       const result = {
					       protocolVersion: '2025-03-26',
					       capabilities: {
						       tools: { listChanged: false },
						       resources: { subscribe: false, listChanged: false },
					       },
					       serverInfo: {
						       name: 'Blackveil DNS',
						       version: SERVER_VERSION,
					       },
				       };
				       responsePayload = jsonRpcSuccess(id, result);
				       logCategory = 'session';
				       logResult = 'initialized';
								       // Audit log session creation with IP tracking
								       if (newSessionId) {
								       	auditSessionCreated(ip, newSessionId);
								       }
				       break;
			       }

			       case 'tools/list': {
				       const result = handleToolsList();
				       responsePayload = jsonRpcSuccess(id, result);
				       logCategory = 'tools';
				       logResult = 'list';
				       break;
			       }

			       case 'tools/call': {
				       const toolParams = params as { name: string; arguments?: Record<string, unknown> };
				       const result = await handleToolsCall(toolParams, c.env.SCAN_CACHE, {
					       providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
						analytics,
				       });
				       responsePayload = jsonRpcSuccess(id, result);
				       logCategory = 'tools';
				       logTool = toolParams.name;
				       logResult = typeof result === 'object' && result && 'status' in result ? String(result.status) : undefined;
				       logDetails = result;
				       break;
			       }

			       case 'resources/list': {
				       const result = handleResourcesList();
				       responsePayload = jsonRpcSuccess(id, result);
				       logCategory = 'resources';
				       logResult = 'list';
				       break;
			       }

			       case 'resources/read': {
				       const resourceParams = params as { uri: string };
				       const result = handleResourcesRead(resourceParams);
				       responsePayload = jsonRpcSuccess(id, result);
				       logCategory = 'resources';
				       logResult = 'read';
				       logDetails = resourceParams;
				       break;
			       }

			       case 'ping': {
				       responsePayload = jsonRpcSuccess(id, {});
				       logCategory = 'session';
				       logResult = 'ping';
				       break;
			       }

			       default:
				       responsePayload = jsonRpcError(id, JSON_RPC_ERRORS.METHOD_NOT_FOUND, `Method not found: ${method}`);
				       logCategory = 'error';
				       logResult = 'method_not_found';
		       }

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
		       const accept = headersLc['accept'];
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
			       return new Response(createSseStream(sseEvent(responsePayload)), {
				       status: 200,
				       headers: {
					       'Content-Type': 'text/event-stream',
					       'Cache-Control': 'no-cache',
					       Connection: 'keep-alive',
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
			       details: { params: body?.params },
			       durationMs: Date.now() - startTime,
			       userAgent: headersLc['user-agent'],
		       });
		       const message = sanitizeErrorMessage(err, 'Internal server error');
		       return c.json(jsonRpcError(id, JSON_RPC_ERRORS.INTERNAL_ERROR, message), 500);
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

	// Session initiation or resume
	const sessionId = c.req.header('mcp-session-id');
	let effectiveSessionId = sessionId;
	const ip = c.req.header('cf-connecting-ip') ?? 'unknown';

	if (!effectiveSessionId) {
		const sessionCreateGate = checkSessionCreateRateLimit(ip);
		if (!sessionCreateGate.allowed) {
			const retryAfterSeconds = Math.ceil((sessionCreateGate.retryAfterMs ?? 0) / 1000);
			return new Response(`Rate limit exceeded. Retry after ${retryAfterSeconds}s`, {
				status: 429,
				headers: {
					'retry-after': String(retryAfterSeconds),
				},
			});
		}
		effectiveSessionId = await createSession(c.env.SESSION_STORE);
	} else if (!(await validateSession(effectiveSessionId, c.env.SESSION_STORE))) {
		return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Bad Request: invalid session'), 400);
	}

	// Open an SSE stream. For this stateless server we keep the stream open
	// briefly then close — a full implementation would push server-initiated
	// notifications here.
	return new Response(createSseStream(': stream opened\n\n'), {
		status: 200,
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache',
			Connection: 'keep-alive',
			'mcp-session-id': effectiveSessionId,
		},
	});
});

// ---------------------------------------------------------------------------
// MCP Streamable HTTP transport — DELETE /mcp (session termination)
// ---------------------------------------------------------------------------
app.delete('/mcp', async (c) => {
	const sessionId = c.req.header('mcp-session-id');
	if (!sessionId || !(await validateSession(sessionId, c.env.SESSION_STORE))) {
		return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Bad Request: invalid or missing session'), 400);
	}

	await deleteSession(sessionId, c.env.SESSION_STORE);
	return new Response(null, { status: 204 });
});

// Fallback 404
app.all('*', (c) => {
	return c.json({ error: 'Not found' }, 404);
});

export default app;
