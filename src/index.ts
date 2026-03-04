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
import { checkRateLimit } from './lib/rate-limiter';
import { handleToolsList, handleToolsCall } from './handlers/tools';
import { handleResourcesList, handleResourcesRead } from './handlers/resources';
import { logEvent, logError } from './lib/log';
import { jsonRpcError, jsonRpcSuccess, JSON_RPC_ERRORS, sanitizeErrorMessage } from './lib/json-rpc';
import { createSession, validateSession, deleteSession } from './lib/session';
import { isAuthorizedRequest, unauthorizedResponse } from './lib/auth';
import { sseEvent, acceptsSSE, createSseStream } from './lib/sse';
import type { JsonRpcRequest } from './lib/json-rpc';

/** Server version — keep in sync with package.json */
const SERVER_VERSION = '1.0.2';

// ---------------------------------------------------------------------------
// Hono app
// ---------------------------------------------------------------------------
// Explicitly type env bindings for clarity and safety
type BvMcpEnv = {
	RATE_LIMIT?: KVNamespace;
	SCAN_CACHE?: KVNamespace;
	SESSION_STORE?: KVNamespace;
	BV_API_KEY?: string;
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

// Centralized error handling middleware
app.use('*', async (c, next) => {
       try {
	       await next();
       } catch (err) {
	       // Structured error logging
	       const reqInfo = {
		       method: c.req.method,
		       url: c.req.url,
		       headers: Object.fromEntries(Array.from(c.req.raw.headers as unknown as Iterable<[string, string]>).filter(([k]) => k !== 'authorization')),
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
       if (!isAuthorizedRequest(authHeader, apiKey)) {
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
		timestamp: new Date().toISOString(),
	});
});

// ---------------------------------------------------------------------------
// MCP Streamable HTTP transport — POST /mcp
// ---------------------------------------------------------------------------
app.post('/mcp', async (c) => {
	const startTime = Date.now();
	// Defensive: normalize all incoming header keys to lowercase
	const rawHeaders = Object.fromEntries(Array.from(c.req.raw.headers as unknown as Iterable<[string, string]>));
	const headersLc: Record<string, string> = {};
	for (const [k, v] of Object.entries(rawHeaders)) headersLc[k.toLowerCase()] = v;

	// Rate limiting by IP — only trust cf-connecting-ip (set by Cloudflare edge)
	// Do NOT fall back to x-forwarded-for as it is client-controlled and spoofable
	const ip = headersLc['cf-connecting-ip'] ?? 'unknown';

	// Authenticated requests bypass rate limiting — the auth middleware already
	// validated the token and stored the result on the Hono context.
	const isAuthenticated = c.get('isAuthenticated');

	// Enforce hard 10KB body size limit (even if content-length is missing or wrong)
	const MAX_BODY = 10_240;
	let rawBody = '';
	const reader = c.req.raw.body?.getReader();
	if (reader) {
		let total = 0;
		while (true) {
			const { value, done } = await reader.read();
			if (done) break;
			total += value.length;
			if (total > MAX_BODY) {
				return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Request body too large'), 413);
			}
			rawBody += new TextDecoder().decode(value);
		}
	} else {
		// Fallback for environments without .body (should not occur in Workers)
		rawBody = await c.req.text();
		if (rawBody.length > MAX_BODY) {
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
		return c.json(jsonRpcError(body.id, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC 2.0 request'), 400);
	}

	// Validate JSON-RPC id field type (must be string, number, or null per spec)
	if (body.id !== undefined && body.id !== null && typeof body.id !== 'string' && typeof body.id !== 'number') {
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
			return c.json(
				jsonRpcError(
					id,
					JSON_RPC_ERRORS.INTERNAL_ERROR,
					`Rate limit exceeded. Retry after ${Math.ceil((rateResult.retryAfterMs ?? 0) / 1000)}s`,
				),
				429,
				rateHeaders,
			);
		}
	}

	// Session validation — non-initialize requests must carry a valid session ID
	const sessionId = headersLc['mcp-session-id'];

	if (method !== 'initialize') {
		if (!sessionId || !(await validateSession(sessionId, c.env.SESSION_STORE))) {
			return c.json(jsonRpcError(id, JSON_RPC_ERRORS.INVALID_REQUEST, 'Bad Request: invalid or missing session'), 400);
		}
	}

	// Notifications (no id) don't execute tools.
	// tools/call notifications are already rate-limited above once per request.
	const isNotification = body.id === undefined || body.id === null;
	if (isNotification && method !== 'initialize') {
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
				       const result = await handleToolsCall(toolParams, c.env.SCAN_CACHE);
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
		       if (acceptsSSE(accept)) {
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
		       return c.json(responsePayload, { status: 200, headers });
	       } catch (err) {
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

	if (!effectiveSessionId) {
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
			'Mcp-Session-Id': effectiveSessionId,
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
