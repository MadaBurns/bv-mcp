#!/bin/bash
# scripts/generate-report.sh
# Usage: npm run generate-report <domain>

if [ -z "$1" ]; then
  echo "Usage: npm run generate-report <domain>"
  exit 1
fi

# Restrict the argument to DNS-label characters before we feed it into file paths.
# Blocks path traversal, shell metacharacters, and sed-special bytes.
if ! [[ "$1" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
  echo "Error: '$1' is not a valid domain (expected lowercase labels separated by '.')." >&2
  exit 1
fi

export TARGET_DOMAIN=$1

# When BV_MCP_ENDPOINT is set (or .dev.vars provides it), the runner routes
# through the deployed worker so service bindings (BV_CERTSTREAM, BV_WHOIS)
# are available. Unset → falls back to local Node imports.
if [ -z "$BV_MCP_ENDPOINT" ] && [ -f ".dev.vars" ]; then
  BV_MCP_ENDPOINT=$(awk -F= '/^BV_MCP_ENDPOINT=/{sub(/^"|"$/, "", $2); print $2}' .dev.vars | head -n1)
fi
if [ -z "$BV_MCP_ENDPOINT" ]; then
  BV_MCP_ENDPOINT="https://dns-mcp.blackveilsecurity.com/mcp"
fi
export BV_MCP_ENDPOINT

if [ -z "$BV_MCP_TOKEN" ] && [ -f ".dev.vars" ]; then
  BV_MCP_TOKEN=$(awk -F= '/^BV_INTERNAL_DEV_KEY=/{sub(/^"|"$/, "", $2); print $2}' .dev.vars | head -n1)
  export BV_MCP_TOKEN
fi

# To force local mode (bypass deployed worker), set BV_MCP_ENDPOINT=local before invoking.
if [ "$BV_MCP_ENDPOINT" = "local" ]; then
  unset BV_MCP_ENDPOINT
  echo "Generating enterprise discovery report for $TARGET_DOMAIN (local mode, forced)..."
else
  echo "Generating enterprise discovery report for $TARGET_DOMAIN via $BV_MCP_ENDPOINT..."
fi

# Remove any prior artifacts so we never mistake stale files for a fresh success.
rm -f "reports/$TARGET_DOMAIN-discovery-report.pdf" "reports/$TARGET_DOMAIN-discovery-report.json"

SPEC_FILE="test/generate-discovery-report.spec.ts"

# Run the discovery engine in standard Node.js environment
npx vitest run -c vitest.node.config.mts "$SPEC_FILE"
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "✅ Success! PDF generated at reports/$TARGET_DOMAIN-discovery-report.pdf"
  echo "✅ Data sidecar generated at reports/$TARGET_DOMAIN-discovery-report.json"
else
  echo "❌ Failed to generate report."
  exit $EXIT_CODE
fi
