#!/usr/bin/env bash
# cogs-snapshot.sh — one dated COGS reading for bv-mcp.
#
# Measures the two lanes the operator can read without a billing token:
#   1. D1 per-database 24h counters (wrangler d1 info --json): rows written/read,
#      query counts, database size → marginal US$/month at D1 list price.
#   2. Analytics Engine: tool_call events over the last N days by auth tier,
#      sample-weighted (SUM(_sample_interval)), via `cf analytics_engine sql query`.
# Prints a table + the reading's own limits, and appends a dated section to the
# ledger (default docs/economics/cogs-ledger.md) unless --no-append.
#
# Database names are discovered from the wrangler configs present on disk
# (wrangler.production.jsonc is private/untracked; packages/*/wrangler.jsonc are
# tracked), so the public script carries no private config content. Override
# with one or more --db <name>.
#
# Exit codes: 0 = at least one D1 reading succeeded; 2 = nothing measurable
# (no ledger row is written — an empty reading must never look like a result).
#
# bash 3.2 / BSD userland: no mapfile, no declare -A, no GNU flags, no timeout.
set -u

ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$ROOT" || exit 2

DAYS=30
LEDGER="docs/economics/cogs-ledger.md"
APPEND=1
DBS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --days) DAYS=$2; shift 2 ;;
    --ledger) LEDGER=$2; shift 2 ;;
    --no-append) APPEND=0; shift ;;
    --db) DBS="$DBS $2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
case "$DAYS" in ''|*[!0-9]*) echo "--days must be an integer" >&2; exit 2 ;; esac

if [ -z "$DBS" ]; then
  DBS=$(grep -h '"database_name"' wrangler.production.jsonc packages/*/wrangler.jsonc 2>/dev/null \
    | sed -E 's/.*"database_name": *"([^"]+)".*/\1/' | sort -u | tr '\n' ' ')
fi
if [ -z "$(echo "$DBS" | tr -d ' ')" ]; then
  echo "no D1 database names found (no wrangler.production.jsonc / packages/*/wrangler.jsonc) — pass --db <name>" >&2
  exit 2
fi

STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
HEAD_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/cogs-snapshot.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

# ---- 1. D1 counters ------------------------------------------------------------
# D1 list price (Workers Paid, 2026): US$1.00 per 1M rows written, US$0.001 per 1M
# rows read, US$0.75 per GB-month stored. The plan includes 50M writes, 25B reads
# and 5 GB per month ACCOUNT-WIDE; those allowances are NOT netted per database here.
ok=0
: > "$TMP/d1.tsv"
for db in $DBS; do
  if npx --no-install wrangler d1 info "$db" --json > "$TMP/$db.json" 2> "$TMP/$db.err"; then
    node -e '
      const j = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      const w = j.rows_written_24h ?? 0, r = j.rows_read_24h ?? 0, gb = (j.database_size ?? 0) / 1e9;
      const usd = (w * 30 / 1e6) * 1.0 + (r * 30 / 1e6) * 0.001 + gb * 0.75;
      console.log([j.name, w, r, j.write_queries_24h ?? "", j.read_queries_24h ?? "", (j.database_size ?? 0), usd.toFixed(2)].join("\t"));
    ' "$TMP/$db.json" >> "$TMP/d1.tsv" && ok=1
  else
    printf '%s\terror\terror\t\t\t\t\n' "$db" >> "$TMP/d1.tsv"
    sed -n '1,3p' "$TMP/$db.err" | sed "s/^/  [$db] /" >&2
  fi
done

# ---- 2. Analytics Engine tool calls by tier -----------------------------------
# Dataset and blob layout: src/lib/analytics-queries.ts (tool_call: blob7 = tier).
AE_STATUS="ok"
cat > "$TMP/q.sql" <<SQL
SELECT blob7 AS tier, SUM(_sample_interval) AS calls
FROM bv_dns_security_mcp
WHERE index1 = 'tool_call' AND timestamp > NOW() - INTERVAL '$DAYS' DAY
GROUP BY tier ORDER BY calls DESC
FORMAT JSON
SQL
: > "$TMP/ae.tsv"
if command -v cf >/dev/null 2>&1 && cf analytics_engine sql query --file "$TMP/q.sql" > "$TMP/ae.json" 2> "$TMP/ae.err"; then
  node -e '
    const raw = require("fs").readFileSync(process.argv[1], "utf8");
    let j; try { j = JSON.parse(raw); } catch { process.exit(3); }
    const rows = j.data ?? j.result?.data ?? [];
    if (!Array.isArray(rows) || rows.length === 0) process.exit(3);
    let total = 0;
    for (const r of rows) { total += Number(r.calls); console.log(r.tier + "\t" + Math.round(Number(r.calls))); }
    console.log("TOTAL\t" + Math.round(total));
  ' "$TMP/ae.json" > "$TMP/ae.tsv" || { AE_STATUS="unavailable (empty or unparseable response)"; : > "$TMP/ae.tsv"; }
else
  AE_STATUS="unavailable ($(command -v cf >/dev/null 2>&1 && sed -n 1p "$TMP/ae.err" || echo 'cf CLI not on PATH'))"
fi

[ "$ok" = 1 ] || { echo "no D1 reading succeeded — nothing recorded" >&2; exit 2; }

# ---- 3. Render --------------------------------------------------------------------
render() {
  echo "## $STAMP"
  echo
  echo "Repo HEAD at snapshot: \`$HEAD_SHA\` (the checkout, not necessarily the live deployment)."
  echo
  echo "| D1 database | rows written/24h | rows read/24h | write q/24h | read q/24h | size (MB) | marginal US\$/mo (list) |"
  echo "|---|---:|---:|---:|---:|---:|---:|"
  while IFS="$(printf '\t')" read -r name w r wq rq size usd; do
    if [ "$w" = error ]; then echo "| $name | error | error | | | | |"; else
      echo "| $name | $w | $r | $wq | $rq | $(node -e "console.log(($size/1e6).toFixed(1))") | $usd |"; fi
  done < "$TMP/d1.tsv"
  echo
  echo "Analytics Engine tool_call events, last $DAYS days, sample-weighted — $AE_STATUS"
  if [ -s "$TMP/ae.tsv" ]; then
    echo
    echo "| tier | calls |"; echo "|---|---:|"
    while IFS="$(printf '\t')" read -r tier calls; do echo "| $tier | $calls |"; done < "$TMP/ae.tsv"
  fi
  echo
  echo "Limits of this reading: D1 counters are one 24h window scaled ×30 (indicative, not a monthly bill);"
  echo "US\$ is D1 list price with the account-wide included allowances (50M writes, 25B reads, 5 GB) not netted;"
  echo "Worker CPU, KV, Durable Objects, R2, Queues and Browser Rendering are NOT measured here (they need an"
  echo "operator billing token — \`cf\` returns 403 on billing); AE counts are sampled and sample-weighted."
  echo
}

render | tee "$TMP/section.md"

if [ "$APPEND" = 1 ]; then
  mkdir -p "$(dirname "$LEDGER")"
  if [ ! -f "$LEDGER" ]; then
    {
      echo "# bv-mcp COGS ledger"
      echo
      echo "Append-only readings from \`.claude/skills/bv-mcp-cogs/scripts/cogs-snapshot.sh\` (newest last)."
      echo "Compare rows by database over time; a single row is not a bill. Each section states its own limits."
      echo
    } > "$LEDGER"
  fi
  cat "$TMP/section.md" >> "$LEDGER"
  echo "appended to $LEDGER"
fi
