#!/usr/bin/env bash
set -euo pipefail

: "${BV_TENANT_SCAN_BASE_URL:?Set BV_TENANT_SCAN_BASE_URL to the Worker origin}"
: "${BV_TENANT_ID:?Set BV_TENANT_ID to the tenant identifier}"
: "${BV_WEB_INTERNAL_KEY:?Set BV_WEB_INTERNAL_KEY from the secret manager}"

if [ "$#" -eq 0 ]; then
  echo "Usage: $0 batch_0.json [batch_1.json ...]" >&2
  exit 2
fi

for batch_file in "$@"; do
  echo "Dispatching ${batch_file}..."
  curl -fsS -X POST "${BV_TENANT_SCAN_BASE_URL%/}/internal/tenants/scan" \
    -H "X-Tenant: ${BV_TENANT_ID}" \
    -H "Authorization: Bearer ${BV_WEB_INTERNAL_KEY}" \
    -H 'Content-Type: application/json' \
    -d "@${batch_file}"
  echo
done
