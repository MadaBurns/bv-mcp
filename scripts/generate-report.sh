#!/bin/bash
# scripts/generate-report.sh
# Usage: npm run generate-report <domain>

if [ -z "$1" ]; then
  echo "Usage: npm run generate-report <domain>"
  exit 1
fi

export TARGET_DOMAIN=$1
echo "Generating enterprise discovery report for $TARGET_DOMAIN..."

# Remove any prior PDF so we never mistake a stale file for a fresh success.
rm -f "reports/$TARGET_DOMAIN-discovery-report.pdf"

# Inject the target domain into the test script
# Use a temporary file for the run to avoid dirtying git state
SPEC_FILE="test/generate-discovery-report.spec.ts"
sed -i.bak "s/const target = '.*';/const target = '$TARGET_DOMAIN';/" "$SPEC_FILE"

# Run the discovery engine in standard Node.js environment
npx vitest run -c vitest.node.config.mts "$SPEC_FILE"
EXIT_CODE=$?

# Restore the placeholder
mv "$SPEC_FILE.bak" "$SPEC_FILE"

if [ $EXIT_CODE -eq 0 ]; then
  echo "✅ Success! PDF generated at reports/$TARGET_DOMAIN-discovery-report.pdf"
else
  echo "❌ Failed to generate report."
  exit $EXIT_CODE
fi
