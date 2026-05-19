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

BV_REPORT_DEPTH=${BV_REPORT_DEPTH:-deep}
case "$BV_REPORT_DEPTH" in
  standard|deep) ;;
  *)
    echo "Error: BV_REPORT_DEPTH must be standard|deep." >&2
    exit 1
    ;;
esac
export BV_REPORT_DEPTH

BV_REPORT_RUN_ID=${BV_REPORT_RUN_ID:-report-$(date +%s)-$$}
BV_REPORT_REQUESTED_AT=${BV_REPORT_REQUESTED_AT:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}
export BV_REPORT_RUN_ID
export BV_REPORT_REQUESTED_AT

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
  echo "Generating enterprise discovery report for $TARGET_DOMAIN (local mode, forced, depth=$BV_REPORT_DEPTH)..."
else
  echo "Generating enterprise discovery report for $TARGET_DOMAIN via $BV_MCP_ENDPOINT (depth=$BV_REPORT_DEPTH)..."
fi

FINAL_PDF="reports/$TARGET_DOMAIN-discovery-report.pdf"
FINAL_JSON="reports/$TARGET_DOMAIN-discovery-report.json"
TMP_DIR="reports/.tmp"
mkdir -p "$TMP_DIR"
BV_REPORT_PDF_PATH="$TMP_DIR/$TARGET_DOMAIN-$BV_REPORT_RUN_ID-discovery-report.pdf"
BV_REPORT_JSON_PATH="$TMP_DIR/$TARGET_DOMAIN-$BV_REPORT_RUN_ID-discovery-report.json"
export BV_REPORT_PDF_PATH
export BV_REPORT_JSON_PATH

SPEC_FILE="test/generate-discovery-report.spec.ts"

# Run the discovery engine in standard Node.js environment
npx vitest run -c vitest.node.config.mts "$SPEC_FILE"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ Failed to generate report."
  exit $EXIT_CODE
fi

node scripts/audits/brand-report-qa.mjs "$TARGET_DOMAIN" --json "$BV_REPORT_JSON_PATH" --pdf "$BV_REPORT_PDF_PATH"
QA_EXIT_CODE=$?
if [ $QA_EXIT_CODE -ne 0 ]; then
  echo "❌ Report QA failed; previous reports were left untouched."
  exit $QA_EXIT_CODE
fi

mv "$BV_REPORT_PDF_PATH" "$FINAL_PDF"
mv "$BV_REPORT_JSON_PATH" "$FINAL_JSON"

echo "✅ Success! PDF generated at $FINAL_PDF"
echo "✅ Data sidecar generated at $FINAL_JSON"
