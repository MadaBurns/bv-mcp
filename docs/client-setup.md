# Client Setup

This document defines MCP client integration for `bv-mcp`.

## Endpoint

Default hosted endpoint:

`https://dns-mcp.blackveilsecurity.com/mcp`

If self-hosting, replace with your deployed Worker endpoint.

## Transport Requirements

- Protocol: JSON-RPC 2.0 over HTTP
- MCP transport: Streamable HTTP
- Content type: `application/json` for `POST /mcp`

## VS Code / GitHub Copilot

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "dns-security": {
      "type": "http",
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

## Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

## Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

## Authentication

When auth is enabled (`BV_API_KEY` configured), clients must send:

`Authorization: Bearer <BV_API_KEY>`

## Server Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/mcp` | JSON-RPC 2.0 MCP requests |
| GET | `/mcp` | SSE stream (server-to-client notifications) |
| DELETE | `/mcp` | Session termination |
| GET | `/health` | Health check |
