# Operator Runbook — bv-mcp platform operations

Platform-level procedures for anyone operating the hosted deployment. Tenant-level
operations (tenant D1 restore drills, erasure, quota sharding) live in
[tenant-ops-runbook.md](./tenant-ops-runbook.md). All commands assume Node 22+ and
repo root. Nothing here contains real IDs or hostnames — actual values live in the
operator secret manager.

## 1. Deploying (any operator, not just the primary)

Prerequisites:

1. `npm ci` on Node 22+.
2. `npx wrangler login` against the production Cloudflare account.
3. Reconstruct `.dev/wrangler.deploy.jsonc` (gitignored, machine-local). It is the
   private overlay merged over the public `wrangler.jsonc` by
   `scripts/inject-private-config.cjs`, and must supply every private binding kind
   the script enumerates (vars, kv_namespaces, r2_buckets, services,
   durable_objects, queues, d1_databases, analytics_engine_datasets). The
   authoritative copy of this file's current contents is stored in the operator
   secret manager under `bv-mcp/deploy-overlay`; KV/D1/queue IDs can be
   re-derived from the Cloudflare dashboard if the secret-manager copy is stale
   (stale KV IDs → wrangler 422 on deploy).
4. Secrets (`wrangler secret list` to see which are set): BV_API_KEY,
   OAUTH_SIGNING_SECRET, BV_WEB_INTERNAL_KEY, BV_RECON_KEY, BV_TLS_PROBE_KEY,
   BV_BROWSER_RENDERER_KEY, KV_ENVELOPE_KEY, MCP_ACCESS_LOG_IP_ENCRYPTION_KEY,
   BV_DOH_ENDPOINT, BV_DOH_TOKEN, CF_ANALYTICS_TOKEN. Values in the secret
   manager; secrets survive deploys (only re-`put` when rotating).
   `BV_DOH_ENDPOINT`/`BV_DOH_TOKEN` are optional — see §9.

Deploy:

    npm run deploy:prod

Verify (MANDATORY after every deploy):

    curl -s https://<worker-host>/mcp -X POST -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"deploy-check","version":"0"}}}' \
      | grep -o '"version":"[^"]*"'

The reported serverInfo version must match `package.json`.

## 2. Rolling back a bad deploy

Workers keeps prior versions. Fastest path:

    npx wrangler deployments list          # find the last-good version id
    npx wrangler rollback                  # interactive; or pass the version id

Caveats:

- Rollback restores CODE + bound config as of that version; it does NOT revert
  KV/D1 data or secrets. If the bad deploy ran a D1 migration, see §3.
- If the bad deploy came from a bad overlay (not bad code), fix
  `.dev/wrangler.deploy.jsonc` and redeploy forward instead.
- After rollback, re-run the §1 verification and re-deploy forward from a fixed
  commit as soon as possible — rollback is a stopgap, not a state.

## 3. D1 backup & restore (INTELLIGENCE_DB, BRAND_AUDIT_DB)

Posture: **D1 Time Travel is the primary recovery mechanism** (30-day
point-in-time window on the paid plan, zero standing cost), with monthly manual
exports as a belt-and-braces archive.

Point-in-time restore (DESTRUCTIVE — restores the whole DB to the bookmark):

    npx wrangler d1 time-travel info <db-name> --timestamp <unix-or-iso>
    npx wrangler d1 time-travel restore <db-name> --bookmark <bookmark-id>

Monthly export (store in the operator vault, not the repo):

    npx wrangler d1 export <db-name> --remote --output <db-name>-$(date +%Y%m%d).sql

Restore rehearsal (do quarterly; ~15 min):

1. `npx wrangler d1 create restore-drill-tmp`
2. `npx wrangler d1 execute restore-drill-tmp --remote --file <latest-export>.sql`
3. Row-count sanity: `npx wrangler d1 execute restore-drill-tmp --remote --command "SELECT count(*) FROM mcp_access_log"`
4. `npx wrangler d1 delete restore-drill-tmp`
5. Log the drill date + outcome in the operator vault.

Note: the access-log retention cron hard-DELETEs rows past
`ANALYTICS_RETENTION_DAYS`; enable `ANALYTICS_ARCHIVE_ENABLED=true` +
`MCP_ACCESS_LOG_ARCHIVE` R2 binding if pre-deletion archiving is wanted.

## 4. Spend monitoring (operator console — one-time setup)

- [ ] Cloudflare dashboard → Notifications → create **Usage Based Billing**
      alerts for: Workers requests, Workers subrequests, D1 rows read/written,
      R2 storage + Class A ops, Queues operations, Browser Rendering usage.
      Route to the ops email + the alert webhook.
- [ ] Set a monthly account **billing threshold** notification.
- [ ] Record thresholds chosen + date configured in the operator vault.

In-app levers if spend spikes: `GLOBAL_DAILY_TOOL_LIMIT` env var (clamped [10000, 5000000] once the runtime wiring for it has shipped — verify with `grep -n "options.globalDailyLimit ?? GLOBAL_DAILY_TOOL_LIMIT" src/mcp/execute.ts` before relying on it during an incident), per-tool `FREE_TOOL_DAILY_LIMITS`, `SCAN_TIMEOUT_MS`. Queue-heavy features degrade to `unprovisioned` if their
bindings are removed from the overlay — the blunt but immediate kill switch.

## 5. Queue dead-lettering (decision record + optional setup)

- `MCP_ANALYTICS_QUEUE`: **deliberately no DLQ** — messages carry raw IP
  pre-encryption; a DLQ would persist raw PII outside the encrypt path. Failed
  messages drop (fail-open). Do not add a DLQ here.
- `BRAND_AUDIT_QUEUE` / `BRAND_AUDIT_PDF_QUEUE`: currently `max_retries: 3` then
  drop; the stuck-job reaper marks orphaned audits failed. To add DLQs:

      npx wrangler queues create brand-audit-dlq
      # then in .dev/wrangler.deploy.jsonc, on each consumer:
      #   "dead_letter_queue": "brand-audit-dlq"

  and add DLQ depth to the §4 notification set. Until then, this is a recorded,
  accepted tradeoff: a dropped brand-audit job surfaces as a failed audit the
  customer can re-run.

## 6. R2 report retention (operator console — one-time setup)

Brand-report PDFs currently never expire. Set a bucket lifecycle rule (align
with the customer-facing retention promise; 180 days suggested):

    npx wrangler r2 bucket lifecycle add <brand-reports-bucket> --expire-days 180

Verify: `npx wrangler r2 bucket lifecycle list <brand-reports-bucket>`.

## 7. Alerting dead-man switch (operator console — one-time setup)

The 15-min cron self-alerts through the webhook when its AE queries fail, but
nothing external notices if the cron itself stops or the webhook config is
unset. Set up an external heartbeat:

- [ ] Cloudflare dashboard → the worker → Settings → Triggers: confirm the cron
      trigger exists after every deploy (the overlay must carry it).
- [ ] Configure a Cloudflare **Health Check** (or healthchecks.io ping) against
      `GET /health` with alerting to the ops email.

## 8. Secret rotation quick reference

| Secret | Rotate with | Coordinate |
| ------ | ----------- | ---------- |
| `BV_WEB_INTERNAL_KEY` | `npx wrangler secret put BV_WEB_INTERNAL_KEY` | Set the SAME value in bv-web-prod first (it is the caller); brief 401 window is expected |
| `BV_API_KEY` | `npx wrangler secret put BV_API_KEY` | Update Claude Desktop MCPB extension/connector configs |
| `OAUTH_SIGNING_SECRET` | `npx wrangler secret put OAUTH_SIGNING_SECRET` | Invalidates ALL outstanding OAuth JWTs — customers re-consent |
| `MCP_ACCESS_LOG_IP_ENCRYPTION_KEY` | `npx wrangler secret put ...` + bump `MCP_ACCESS_LOG_IP_KEY_VERSION` | Old ciphertexts need the old key retained in the vault for forensics |
| `BV_DOH_TOKEN` | `npx wrangler secret put BV_DOH_TOKEN` | Rotate `BLACKVEIL_DOH_TOKEN` on the bv-dns host to the SAME value. A mismatch is non-fatal — see §9 |

## 9. Secondary DoH resolver (bv-dns) — optional, default-OFF

### What it is

`src/lib/dns-transport.ts` resolves through Cloudflare DoH as primary. When a
primary lookup returns **no answers of the requested type**, `queryDns` calls
`confirmWithSecondaryResolvers` to double-check the absence before a check
reports "not present". That confirmation always queries Google DoH, and
additionally queries a **private BlackVeil-operated DoH resolver** when — and
only when — both of these are populated:

| Env | Kind | Purpose |
| --- | ---- | ------- |
| `BV_DOH_ENDPOINT` | **Secret** | Full `…/dns-query` URL of the private resolver |
| `BV_DOH_TOKEN` | **Secret** | Sent as the `X-BV-Token` request header; must equal `BLACKVEIL_DOH_TOKEN` on the resolver host |

Unset `BV_DOH_ENDPOINT` → the seam is **inert**: `opts.secondaryDoh` is
`undefined` at every call site, no request is issued, and confirmation behaves
exactly as it does today (Google only). This is the shipped default and the
instant kill switch.

### Why the endpoint is a Secret and not a `vars` entry

This repo is source-available. `.gitleaks.toml` carries an `internal-hostname`
rule that fails CI on any commit reintroducing the resolver's hostname, which
was deliberately scrubbed from history. Workers expose **`vars` and secrets on
the same `env` object**, so a secret satisfies the reader
(`c.env.BV_DOH_ENDPOINT`) identically while keeping the hostname out of the
repo. No code, type, or `wrangler.jsonc` change is required to activate it:

- `BV_DOH_ENDPOINT?: string` / `BV_DOH_TOKEN?: string` are already declared on
  the hand-written env types in `src/index.ts`, `src/internal.ts`,
  `src/tenants/routes.ts`, and `src/tenants/queue-consumer.ts` — not on the
  `wrangler types`-generated ambient `Env`, so regenerating types cannot drop
  them and no `vars` entry is needed to typecheck.
- Nothing validates the pair. `REQUIRE_PRODUCTION_BINDINGS` checks only KV /
  D1 / R2 / queue / DO bindings and the alert webhook; an absent secondary
  resolver is not a degraded `/health`.

The alternative — a `vars` entry in the gitignored `.dev/wrangler.deploy.jsonc`
overlay — also keeps the hostname out of the repo, but couples activation to
the overlay copy in the secret manager and to a redeploy. Prefer the secret.

### Activate

Run from repo root against the production account (`npx wrangler login` first):

    npx wrangler secret put BV_DOH_ENDPOINT --config .dev/wrangler.deploy.jsonc
    # paste the full https://<resolver-host>:<port>/dns-query URL

    npx wrangler secret put BV_DOH_TOKEN --config .dev/wrangler.deploy.jsonc
    # paste the SAME value as BLACKVEIL_DOH_TOKEN on the resolver host

Secrets apply to the running Worker immediately — **no deploy needed**, and
they survive subsequent deploys. Record both values in the operator secret
manager under `bv-mcp/secondary-doh` before setting them.

Pre-flight the resolver first (values from the secret manager, never inline in
a commit or a shared log):

    curl -s -o /dev/null -w '%{http_code} verify=%{ssl_verify_result}\n' "$BV_DOH_HEALTH_URL"
    # expect: 200 verify=0   (strict TLS; do NOT use -k)

    curl -s -H "X-BV-Token: $TOKEN" "$BV_DOH_ENDPOINT?name=example.com&type=TXT"
    # expect: application/dns-json body. 401 ⇒ token mismatch.

### Deactivate / roll back

    npx wrangler secret delete BV_DOH_ENDPOINT --config .dev/wrangler.deploy.jsonc

Deleting the endpoint alone is sufficient — the token is only read when the
endpoint is set. Takes effect immediately, no deploy.

### Failure semantics (why this is safe to enable)

The secondary resolver **cannot change a result that the primary already
answered**, and it cannot turn a good result into a bad one:

| Condition | Behaviour |
| --------- | --------- |
| Primary (Cloudflare) returns typed answers | Secondary confirmation never runs. bv-dns is never contacted on the overwhelming majority of lookups. |
| bv-dns down, DNS-unresolvable, or TCP-refused | `fetchDohOutcome` catches and returns `{ kind: 'error', reason: 'network' }`. Google's answer is used. Identical to today. |
| bv-dns returns 401 (token mismatch), 5xx, or any non-2xx | `{ kind: 'error', reason: 'http' }`, logged at `warn` under `category: 'dns-transport'`. Google's answer is used. **A wrong token degrades to today's behaviour, it does not fail the scan.** |
| bv-dns returns malformed JSON | `{ kind: 'error', reason: 'parse' }`. Google's answer is used. |
| bv-dns hangs | `AbortSignal.timeout(DNS_TIMEOUT_MS)` (3 s) aborts it → `reason: 'timeout'`. Google's answer is used. |
| bv-dns AND Google both fail | `{ kind: 'unconfirmed' }` → `queryDns` returns the **primary** response unchanged. Confirmation is best-effort; it never substitutes an empty result for a primary one. |

Latency is the only real exposure, and it is bounded. The two secondaries run
under `Promise.allSettled`, which waits for **both** to settle — so on the
empty-answer path the confirmation costs `max(google, bv-dns)` rather than
`google` alone. A blackholed bv-dns (packets dropped, no RST) therefore adds up
to `DNS_TIMEOUT_MS` = **3 s** to that one lookup. That is contained by the
per-check budget (`PER_CHECK_TIMEOUT_MS`, 8 s default, clamped 2–15 s) and the
whole-scan budget (`SCAN_TIMEOUT_MS`, 15 s default, clamped 5–30 s), so the
worst case is a single check timing out — not a hung scan. If the resolver is
known-flapping, delete `BV_DOH_ENDPOINT` rather than waiting it out.

Answer precedence when several resolvers reply: the first candidate holding
answers **of the requested type** wins, evaluated bv-dns → Google. bv-dns is a
trusted first-party resolver; treat that precedence as part of its blast
radius when rotating or repointing the endpoint.

## 10. Incident quick path

1. Symptom triage: `npx wrangler tail` (live) / Workers dashboard logs.
2. Bad deploy → §2 rollback. Data damage → §3 Time Travel.
3. Cost/abuse spike → §4 levers.
4. Leaked secret → §8 rotation, then check `/internal/analytics/forensics`
   (strict bearer) for misuse windows.
5. Post-incident: note timeline + actions in the operator vault.
