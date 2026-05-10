#!/bin/bash
# scripts/generate-report.sh
# Usage: npm run generate-report <domain>

if [ -z "$1" ]; then
  echo "Usage: npm run generate-report <domain>"
  exit 1
fi

export TARGET_DOMAIN=$1
echo "Generating report for $TARGET_DOMAIN..."

# Inject the target domain into the test script
sed -i.bak "s/const target = '.*';/const target = '$TARGET_DOMAIN';/" test/generate-discovery-report.spec.ts

# Run the discovery engine inside Vitest to access bindings/modules and capture output
VITEST_OUT=$(npx vitest run test/generate-discovery-report.spec.ts --reporter=verbose)
VITEST_EXIT_CODE=$?

# Restore the placeholder
mv test/generate-discovery-report.spec.ts.bak test/generate-discovery-report.spec.ts

if [ $VITEST_EXIT_CODE -ne 0 ]; then
  echo "❌ Vitest run failed. Output:"
  echo "$VITEST_OUT"
  exit 1
fi

MD_FILE="reports/$TARGET_DOMAIN-discovery-report.md"

# Extract markdown from stdout using awk
echo "$VITEST_OUT" | awk '/===MARKDOWN_START===/{flag=1; next} /===MARKDOWN_END===/{flag=0} flag' > "$MD_FILE"

# Check if the markdown file was successfully generated and not empty
if [ -s "$MD_FILE" ]; then
  echo "Generating PDF from $MD_FILE..."
  npx md-to-pdf "$MD_FILE"
  echo "✅ Success! PDF generated at reports/$TARGET_DOMAIN-discovery-report.pdf"
else
  echo "❌ Failed to extract Markdown report from output. PDF conversion aborted."
  exit 1
fi
