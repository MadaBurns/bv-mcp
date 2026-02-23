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

import { Hono } from "hono";
import { cors } from "hono/cors";
import { checkRateLimit } from "./lib/rate-limiter";
import { handleToolsList, handleToolsCall } from "./handlers/tools";
import { handleResourcesList, handleResourcesRead } from "./handlers/resources";

/** JSON-RPC 2.0 request shape */
interface JsonRpcRequest {
  jsonrpc: string;
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

/** JSON-RPC 2.0 error codes */
const JSON_RPC_ERRORS = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
} as const;

function jsonRpcError(
  id: string | number | null | undefined,
  code: number,
  message: string,
) {
  return {
    jsonrpc: "2.0" as const,
    id: id ?? null,
    error: { code, message },
  };
}

function jsonRpcSuccess(id: string | number | null | undefined, result: unknown) {
  return {
    jsonrpc: "2.0" as const,
    id: id ?? null,
    result,
  };
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * Uses XOR accumulation so runtime is always proportional to the
 * longer string, regardless of where a mismatch occurs.
 */
function timingSafeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  if (bufA.byteLength !== bufB.byteLength) {
    // Still compare full length of shorter to avoid early-exit leak
    const minLen = Math.min(bufA.byteLength, bufB.byteLength);
    let mismatch = 1; // already different lengths
    for (let i = 0; i < minLen; i++) {
      mismatch |= bufA[i] ^ bufB[i];
    }
    // Use mismatch to prevent dead-code elimination
    return mismatch === 0;
  }
  let result = 0;
  for (let i = 0; i < bufA.byteLength; i++) {
    result |= bufA[i] ^ bufB[i];
  }
  return result === 0;
}

// ---------------------------------------------------------------------------
// Session management (in-memory, per-isolate)
// ---------------------------------------------------------------------------
const activeSessions = new Map<string, { createdAt: number }>();

/** Generate a cryptographically secure session ID (hex, visible ASCII) */
function generateSessionId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Format a JSON-RPC message as an SSE `message` event */
function sseEvent(data: unknown, eventId?: string): string {
  let event = "";
  if (eventId) {
    event += `id: ${eventId}\n`;
  }
  event += `event: message\ndata: ${JSON.stringify(data)}\n\n`;
  return event;
}

/** Check whether the Accept header includes text/event-stream */
function acceptsSSE(accept: string | undefined): boolean {
  return !!accept && accept.includes("text/event-stream");
}

// ---------------------------------------------------------------------------
// Hono app
// ---------------------------------------------------------------------------
const app = new Hono<{ Bindings: Env }>();

// CORS for MCP clients — allow Streamable HTTP methods and headers
app.use(
  "/mcp",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization", "Accept", "Mcp-Session-Id"],
    exposeHeaders: ["Mcp-Session-Id"],
  }),
);

// Bearer token authentication for /mcp
app.use("/mcp", async (c, next) => {
  const authHeader = c.req.header("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return c.json(
      jsonRpcError(null, -32001, "Unauthorized: missing or malformed Authorization header"),
      401,
    );
  }
  const token = authHeader.slice("Bearer ".length);
  if (!timingSafeEqual(token, c.env.SECRET)) {
    return c.json(
      jsonRpcError(null, -32001, "Unauthorized: invalid token"),
      401,
    );
  }
  await next();
});

// Health endpoint
app.get("/health", (c) => {
  return c.json({
    status: "ok",
    service: "bv-dns-security-mcp",
    timestamp: new Date().toISOString(),
  });
});

// ---------------------------------------------------------------------------
// MCP Streamable HTTP transport — POST /mcp
// ---------------------------------------------------------------------------
app.post("/mcp", async (c) => {
  // Rate limiting by IP — only trust cf-connecting-ip (set by Cloudflare edge)
  // Do NOT fall back to x-forwarded-for as it is client-controlled and spoofable
  const ip = c.req.header("cf-connecting-ip") ?? "unknown";
  const rateResult = checkRateLimit(ip);

  if (!rateResult.allowed) {
    return c.json(
      jsonRpcError(
        null,
        JSON_RPC_ERRORS.INTERNAL_ERROR,
        `Rate limit exceeded. Retry after ${Math.ceil((rateResult.retryAfterMs ?? 0) / 1000)}s`,
      ),
      429,
    );
  }

  // Reject oversized request bodies (max 10KB — tool arguments are small)
  const contentLength = c.req.header("content-length");
  if (contentLength && parseInt(contentLength, 10) > 10_240) {
    return c.json(
      jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, "Request body too large"),
      413,
    );
  }

  // Parse JSON-RPC request
  let body: JsonRpcRequest;
  try {
    body = await c.req.json<JsonRpcRequest>();
  } catch {
    return c.json(
      jsonRpcError(null, JSON_RPC_ERRORS.PARSE_ERROR, "Parse error: invalid JSON"),
      400,
    );
  }

  // Validate JSON-RPC 2.0 structure
  if (body.jsonrpc !== "2.0" || typeof body.method !== "string") {
    return c.json(
      jsonRpcError(
        body.id,
        JSON_RPC_ERRORS.INVALID_REQUEST,
        "Invalid JSON-RPC 2.0 request",
      ),
      400,
    );
  }

  // Validate JSON-RPC id field type (must be string, number, or null per spec)
  if (
    body.id !== undefined &&
    body.id !== null &&
    typeof body.id !== "string" &&
    typeof body.id !== "number"
  ) {
    return c.json(
      jsonRpcError(
        null,
        JSON_RPC_ERRORS.INVALID_REQUEST,
        "Invalid JSON-RPC id: must be string, number, or null",
      ),
      400,
    );
  }

  // Session validation — non-initialize requests must carry a valid session ID
  const sessionId = c.req.header("mcp-session-id");
  const { id, method, params } = body;

  if (method !== "initialize") {
    if (!sessionId || !activeSessions.has(sessionId)) {
      return c.json(
        jsonRpcError(id, JSON_RPC_ERRORS.INVALID_REQUEST, "Bad Request: invalid or missing session"),
        400,
      );
    }
  }

  // Notifications (no id) and ping don't need SSE — return 202 or JSON
  const isNotification = body.id === undefined || body.id === null;
  if (isNotification && method !== "initialize") {
    // Per spec: notifications/responses → 202 Accepted
    if (method === "notifications/initialized") {
      return new Response(null, { status: 202 });
    }
    return new Response(null, { status: 202 });
  }

  try {
    // Dispatch MCP methods and build the JSON-RPC response payload
    let responsePayload: ReturnType<typeof jsonRpcSuccess> | ReturnType<typeof jsonRpcError>;
    let newSessionId: string | undefined;

    switch (method) {
      case "initialize": {
        newSessionId = generateSessionId();
        activeSessions.set(newSessionId, { createdAt: Date.now() });
        const result = {
          protocolVersion: "2025-03-26",
          capabilities: {
            tools: { listChanged: false },
            resources: { subscribe: false, listChanged: false },
          },
          serverInfo: {
            name: "bv-dns-security-mcp",
            version: "1.0.0",
          },
        };
        responsePayload = jsonRpcSuccess(id, result);
        break;
      }

      case "tools/list": {
        const result = handleToolsList();
        responsePayload = jsonRpcSuccess(id, result);
        break;
      }

      case "tools/call": {
        const toolParams = params as { name: string; arguments?: Record<string, unknown> };
        const result = await handleToolsCall(toolParams);
        responsePayload = jsonRpcSuccess(id, result);
        break;
      }

      case "resources/list": {
        const result = handleResourcesList();
        responsePayload = jsonRpcSuccess(id, result);
        break;
      }

      case "resources/read": {
        const resourceParams = params as { uri: string };
        const result = handleResourcesRead(resourceParams);
        responsePayload = jsonRpcSuccess(id, result);
        break;
      }

      case "ping": {
        responsePayload = jsonRpcSuccess(id, {});
        break;
      }

      default:
        responsePayload = jsonRpcError(id, JSON_RPC_ERRORS.METHOD_NOT_FOUND, `Method not found: ${method}`);
    }

    // Build response headers
    const headers: Record<string, string> = {};
    if (newSessionId) {
      headers["Mcp-Session-Id"] = newSessionId;
    }

    // If client accepts SSE, stream the response as an SSE event
    const accept = c.req.header("accept");
    if (acceptsSSE(accept)) {
      const body = new ReadableStream({
        start(controller) {
          const encoder = new TextEncoder();
          controller.enqueue(encoder.encode(sseEvent(responsePayload)));
          controller.close();
        },
      });
      return new Response(body, {
        status: 200,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
          ...headers,
        },
      });
    }

    // Default: plain JSON response (backward compatible)
    return c.json(responsePayload, { status: 200, headers });
  } catch (err) {
    // Sanitize error messages — only pass through known validation errors,
    // use generic message for unexpected errors to prevent info leaks
    const isValidationError = err instanceof Error && (
      err.message.startsWith("Missing required") ||
      err.message.startsWith("Invalid") ||
      err.message.startsWith("Resource not found")
    );
    const message = isValidationError ? err.message : "Internal server error";
    return c.json(
      jsonRpcError(id, JSON_RPC_ERRORS.INTERNAL_ERROR, message),
      500,
    );
  }
});

// ---------------------------------------------------------------------------
// MCP Streamable HTTP transport — GET /mcp (SSE stream for notifications)
// ---------------------------------------------------------------------------
app.get("/mcp", (c) => {
  // Require valid session
  const sessionId = c.req.header("mcp-session-id");
  if (!sessionId || !activeSessions.has(sessionId)) {
    return c.json(
      jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, "Bad Request: invalid or missing session"),
      400,
    );
  }

  // Must accept SSE
  if (!acceptsSSE(c.req.header("accept"))) {
    return new Response("Not Acceptable: Accept must include text/event-stream", { status: 406 });
  }

  // Open an SSE stream. For this stateless server we keep the stream open
  // briefly then close — a full implementation would push server-initiated
  // notifications here.
  const body = new ReadableStream({
    start(controller) {
      const encoder = new TextEncoder();
      // Send an initial comment to establish the connection
      controller.enqueue(encoder.encode(": stream opened\n\n"));
      // In a stateless Cloudflare Worker we close after the keep-alive.
      // A stateful server would hold this open and push notifications.
      controller.close();
    },
  });

  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "Mcp-Session-Id": sessionId,
    },
  });
});

// ---------------------------------------------------------------------------
// MCP Streamable HTTP transport — DELETE /mcp (session termination)
// ---------------------------------------------------------------------------
app.delete("/mcp", (c) => {
  const sessionId = c.req.header("mcp-session-id");
  if (!sessionId || !activeSessions.has(sessionId)) {
    return c.json(
      jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, "Bad Request: invalid or missing session"),
      400,
    );
  }

  activeSessions.delete(sessionId);
  return new Response(null, { status: 204 });
});

// Fallback 404
app.all("*", (c) => {
  return c.json({ error: "Not found" }, 404);
});

export default app;
