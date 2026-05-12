#!/bin/bash
echo 'Starting dispatch of 10,000 domains...'
curl -X POST https://dns-mcp.blackveilsecurity.com/internal/tenants/scan \
  -H 'X-Tenant: tenant-pilot-1' \
  -H 'Authorization: Bearer $BV_WEB_INTERNAL_KEY' \
  -H 'Content-Type: application/json' \
  -d @batch_0.json
echo 'Batch {i} dispatched.'
curl -X POST https://dns-mcp.blackveilsecurity.com/internal/tenants/scan \
  -H 'X-Tenant: tenant-pilot-1' \
  -H 'Authorization: Bearer $BV_WEB_INTERNAL_KEY' \
  -H 'Content-Type: application/json' \
  -d @batch_1.json
echo 'Batch {i} dispatched.'
curl -X POST https://dns-mcp.blackveilsecurity.com/internal/tenants/scan \
  -H 'X-Tenant: tenant-pilot-1' \
  -H 'Authorization: Bearer $BV_WEB_INTERNAL_KEY' \
  -H 'Content-Type: application/json' \
  -d @batch_2.json
echo 'Batch {i} dispatched.'
curl -X POST https://dns-mcp.blackveilsecurity.com/internal/tenants/scan \
  -H 'X-Tenant: tenant-pilot-1' \
  -H 'Authorization: Bearer $BV_WEB_INTERNAL_KEY' \
  -H 'Content-Type: application/json' \
  -d @batch_3.json
echo 'Batch {i} dispatched.'
