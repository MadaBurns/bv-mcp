/**
 * DNS Security MCP Server - Main Entry Point
 *
 * Cloudflare Worker implementing the Model Context Protocol (MCP)
 * with DNS security analysis tools. Uses Hono framework for routing.
 *
 * Endpoints:
 *   GET  /health  - Worker health check
 *   POST /mcp     - MCP JSON-RPC 2.0 endpoint
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

const app = new Hono();

// CORS for MCP clients
app.use(
  "/mcp",
  cors({
    origin: "*",
    allowMethods: ["POST", "OPTIONS"],
    allowHeaders: ["Content-Type"],
  }),
);

// Health endpoint
app.get("/health", (c) => {
  return c.json({
    status: "ok",
    service: "bv-dns-security-mcp",
    timestamp: new Date().toISOString(),
  });
});

// MCP JSON-RPC 2.0 endpoint
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

  const { id, method, params } = body;

  try {
    // Dispatch MCP methods
    switch (method) {
      case "initialize": {
        const result = {
          protocolVersion: "2024-11-05",
          capabilities: {
            tools: { listChanged: false },
            resources: { subscribe: false, listChanged: false },
          },
          serverInfo: {
            name: "bv-dns-security-mcp",
            version: "1.0.0",
          },
        };
        return c.json(jsonRpcSuccess(id, result));
      }

      case "tools/list": {
        const result = handleToolsList();
        return c.json(jsonRpcSuccess(id, result));
      }

      case "tools/call": {
        const toolParams = params as { name: string; arguments?: Record<string, unknown> };
        const result = await handleToolsCall(toolParams);
        return c.json(jsonRpcSuccess(id, result));
      }

      case "resources/list": {
        const result = handleResourcesList();
        return c.json(jsonRpcSuccess(id, result));
      }

      case "resources/read": {
        const resourceParams = params as { uri: string };
        const result = handleResourcesRead(resourceParams);
        return c.json(jsonRpcSuccess(id, result));
      }

      case "notifications/initialized":
      case "ping": {
        // Notifications don't require a response with result
        if (method === "ping") {
          return c.json(jsonRpcSuccess(id, {}));
        }
        // notifications/initialized is a notification (no id expected)
        return c.json(jsonRpcSuccess(id, {}));
      }

      default:
        return c.json(
          jsonRpcError(id, JSON_RPC_ERRORS.METHOD_NOT_FOUND, `Method not found: ${method}`),
        );
    }
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

// Fallback 404
app.all("*", (c) => {
  return c.json({ error: "Not found" }, 404);
});

export default app;
