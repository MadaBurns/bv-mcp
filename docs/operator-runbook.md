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

In-app levers if spend spikes: `GLOBAL_DAILY_TOOL_LIMIT` env var (wired — `parseGlobalDailyLimit()` in `src/lib/config.ts` clamps it to [10000, 5000000] and `src/mcp/execute.ts` honours it at every `tools/call`; overriding it needs a redeploy since it is a `vars` entry, not a secret), per-tool `FREE_TOOL_DAILY_LIMITS` (a code constant — code change + deploy), `SCAN_TIMEOUT_MS` (env var, clamped [5000, 30000]). Queue-heavy features degrade to `unprovisioned` if their
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

## 10. WAF interception of our own scanner (issue #638)

### Symptom

A Cloudflare-fronted zone answers the scanner's probe with a challenge or block
page instead of the resource, so the check never reaches the origin. Two checks
carry this exposure because they are the only scan-included checks that fetch
the scanned domain's own web server:

| Check | Fetches | Finding title on interception | `checkStatus` |
| ----- | ------- | ----------------------------- | ------------- |
| `check_http_security` | `HEAD https://<domain>/` (×2, plus redirect follows and a GET fallback) | `Cloudflare WAF challenge intercepted` · `Cloudflare WAF blocked external header inspection` · `Cloudflare edge challenged the HTTP security probe` | `error` |
| `check_mta_sts` | `GET https://mta-sts.<domain>/.well-known/mta-sts.txt` | `Cloudflare WAF challenge intercepted — policy accessibility inconclusive` · `Cloudflare WAF blocked policy fetch — accessibility inconclusive` · `MTA-STS policy fetch stalled — accessibility inconclusive` | `error` |

All of these are `info` severity and carry `inconclusive: true` (never
`missingControl` — see the contract note on `buildWafFinding` in
`src/lib/waf-detection.ts`). The category is EXCLUDED from scoring rather than
zeroed, so the reported score is honest about what it measured but the headline
grade rests on fewer checks than it appears to. In a `scan_domain` result:

    "checkStatuses": {"mta_sts": "error", "http_security": "error"},
    "inconclusiveCategories": ["mta_sts", "http_security"],
    "evidence": {"attempted": 19, "completed": 17, "ratio": 0.894…}

Do not confuse this with the adjacent robots.txt case — `HTTP security check
skipped (robots.txt)` means the target's own robots.txt disallows us (a
voluntary abstention, not a block), and it is not fixed by a WAF rule.

### What the scanner actually sends — and what it does not

Verified in code before writing any rule:

- **User-Agent is the only identifying signal we emit.**
  `SCANNER_USER_AGENT` in `packages/dns-checks/src/robots-gate.ts` is the single
  source of truth, stamped by `withRobotsGate` on every outbound request unless
  the call site already set one:

      BlackVeil-Security-Scanner/1.0 (+https://www.blackveilsecurity.com/bot-policy; security@blackveilsecurity.com)

- **There is no custom outbound header today.** Nothing in `src/tools/` or
  `packages/dns-checks/src/checks/` sets a proprietary request header on a scan
  fetch. (`X-BV-Token` in §9 is *inbound* auth to our own DoH resolver, not
  anything a scanned domain ever sees.) If a stronger signal is ever wanted, the
  place to add it is the `withRobotsGate` chokepoint — but see the trade-off
  below for why that only helps on zones we control.
- **Do NOT allowlist by source IP.** The scanner runs inside a Cloudflare
  Worker, so its subrequests egress from Cloudflare's shared address space —
  the same space every other customer's Workers egress from. An IP allowlist
  there is an allowlist for arbitrary third-party code, which is strictly worse
  than the User-Agent rule it would be replacing.
- Cloudflare may attach its own worker-provenance header to Worker-issued
  subrequests. That is platform behaviour we neither set nor control, and it is
  **not verified here** — if you want to use it in an expression, confirm it
  appears on a real intercepted request in Firewall Events first, and never make
  it the only condition.

### Both hostnames need coverage

`check_mta_sts` fetches a **different host** from `check_http_security` —
`mta-sts.<domain>` versus the apex (confirmed at
`src/tools/check-mta-sts.ts` and the memo comment in `src/tools/scan-domain.ts`,
which declines to share the apex robots memo for exactly this reason). A rule
scoped to the apex covers `http_security` and leaves `mta_sts` blocked.
`check_http_security` also **follows HTTPS redirects**, so if the apex redirects
to `www`, the redirect target needs coverage too.

### The rule, and the trade-off to accept before creating it

Create a **Skip** rule (skip Bot Fight Mode / the managed rulesets that fire) —
never an "Allow all", and leave rate limiting and DDoS protection ON. Scope it
by host **and** path **and** method, so it is not a zone-wide bypass:

    (http.host in {"<apex>" "www.<apex>"}
      and http.request.uri.path in {"/" "/robots.txt"}
      and http.request.method in {"GET" "HEAD"}
      and http.user_agent contains "BlackVeil-Security-Scanner")
    or (http.host eq "mta-sts.<apex>"
      and http.request.uri.path eq "/.well-known/mta-sts.txt"
      and http.request.method in {"GET" "HEAD"}
      and http.user_agent contains "BlackVeil-Security-Scanner")

**State the risk plainly: that User-Agent is trivially forgeable.** It is
published on our own public bot-policy page and it is a string constant in this
source-available repo — anyone can send it. A rule keyed on it is, functionally,
a WAF bypass token that we have already published. There is no signed or secret
component to fall back on, because no custom header exists (above).

What makes the narrow form defensible is the *scope*, not the credential: every
resource it exposes is content whose entire purpose is to be world-readable
anonymously — the site root's response headers, `/robots.txt`, and a published
MTA-STS policy file. A forger gains nothing a normal browser is not already
given. That reasoning collapses the moment the rule widens: a zone-wide
"skip security rules when the User-Agent matches" rule is a self-service bypass
for the whole site and must not be created, on our zone or anyone's. If you
cannot express the rule with an explicit path list, do not create it — take the
blind spot and report it instead.

### Verify the fix

**A `curl` probe does not verify this.** A request from an operator laptop
differs from the Worker's in source network and TLS/HTTP fingerprint, and this
fleet has already been burned by exactly that gap (a Worker→zone fetch being
challenged while `curl` got a clean 200). Verify through the scanner itself,
with the cache bypassed — the 5-minute scan cache will otherwise replay the
pre-fix result:

    SID=$(curl -si https://<worker-host>/mcp -X POST -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"waf-check","version":"0"}}}' \
      | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}' | tr -d '\r')

    curl -s https://<worker-host>/mcp -X POST -H 'content-type: application/json' \
      -H "Mcp-Session-Id: $SID" -H 'MCP-Protocol-Version: 2025-06-18' \
      -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_domain","arguments":{"domain":"<apex>","force_refresh":true,"format":"full"}}}'

Pass criteria, read off `structuredContent` (or the `STRUCTURED_RESULT`
comment):

| Field | Required value |
| ----- | -------------- |
| `checkStatuses.http_security` | `"completed"` |
| `checkStatuses.mta_sts` | `"completed"` |
| `inconclusiveCategories` | contains neither category |
| `evidence.completed` / `evidence.attempted` | equal (`ratio` = 1) |

`evidence.ratio` is the single field to watch: if it is still below 1 the rule
did not take, regardless of what the score says. Re-check it after any WAF or
Bot Fight Mode change, since a later ruleset update can silently re-block.

### Customer domains — where we cannot change the WAF

This is the commercially important half. The same wall stands in front of every
Cloudflare-fronted customer, and we have no lever on their configuration.

1. **Report the shortfall; never launder it.** The scan output is already
   honest — publish `evidence.ratio` and the `inconclusiveCategories` list
   beside any grade. A score derived from 17 of 19 checks must never be
   presented as a full-coverage result, in a report, a dashboard, or a sales
   conversation.
2. **Offer the narrow rule, never a blanket one.** Hand the customer the
   path-scoped expression above with their own hostnames, plus the forgeability
   caveat stated in full. A customer who declines has made a reasonable
   security decision, and the correct response is (1), not pressure.
3. **First establish whether the block is scanner-shaped or universal — this
   changes the finding.** Probe the same URL from an off-Cloudflare vantage with
   a neutral client, then with our User-Agent. If *both* are challenged, the
   interception is not aimed at us, and for `mta-sts.<domain>` that is a real
   defect rather than a scan artefact: sending MTAs fetch that exact URL with a
   non-browser client and cannot solve an interactive challenge, so MTA-STS is
   genuinely unenforceable for those senders. Escalate it as a true finding.
   ⚠️ **Our own wording currently prejudges this and is tracked as a defect
   (#664).** Both prose paths — `src/tools/check-mta-sts.ts:109` and `:162` —
   assert flatly that *"Real sending MTAs are not subject to the same
   interactive challenge"*. Line 109 then hedges the conclusion ("may well be
   reachable"), but the premise underneath it is stated as fact and we have
   never measured it. Until #664 is resolved, do not quote that reassurance to a
   customer; establish which case you are in first.
4. **The durable answer is a verifiable identity, not a string.** A signature-
   based bot-authentication scheme (or a platform verified-bot listing) would
   let a customer allowlist something an impersonator cannot mint, which is the
   only version of this that is safe to recommend at scale. It needs a change at
   the `withRobotsGate` chokepoint plus programme eligibility we have not
   confirmed — an operator decision, not a config edit, and out of scope for
   this runbook.
5. **Quantify it before deciding.** The interception findings carry `wafEvent` /
   `wafKind` metadata, so the affected share of a domain corpus is measurable
   with a `batch_scan` rather than guessed at.

## 11. Incident quick path

1. Symptom triage: `npx wrangler tail` (live) / Workers dashboard logs.
2. Bad deploy → §2 rollback. Data damage → §3 Time Travel.
3. Cost/abuse spike → §4 levers.
4. Leaked secret → §8 rotation, then check `/internal/analytics/forensics`
   (strict bearer) for misuse windows.
5. Post-incident: note timeline + actions in the operator vault.
