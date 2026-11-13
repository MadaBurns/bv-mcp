# Integrator Guide

For anyone building the hosted scanner into a product, a reporting pipeline or a scheduled job, as opposed to using it interactively from an editor (for that, see [client-setup.md](client-setup.md)). Each section says what the service does at this commit and what to do about it. Where a commitment would be needed (availability, response times, notice periods, data location, retention beyond the code default) this guide makes none: those are set by your commercial agreement, not by this repository.

## 1. Version stamps: store them with every score

Every `scan_domain` and `batch_scan` result carries three stamps: `scoringModelVersion`, `dnsChecksPackageVersion` and `scoringConfigHash`. What each one tracks is described in [scoring.md](scoring.md#version-stamps-and-reproducibility).

- **Persist all three alongside every score you store.** A score without its stamps cannot be explained later.
- **A score movement can be a model change, not a posture change.** When any stamp differs between two scans of the same domain, part or all of the difference may come from the scoring rules or the engine rather than from the domain. A new detection can move a result when only `dnsChecksPackageVersion` changes.
- **Compare trends only within one `scoringConfigHash`.** Treat a change in the hash as a break in the series: re-baseline, do not chart a continuous line across it.
- **You cannot pin a model version.** The caller has no way to choose which scoring model or package version scores a request; the hosted service runs whatever it is currently running. The stamps tell you after the fact which one it was.
- **The change record** is [CHANGELOG.md](../CHANGELOG.md) for the service and [packages/dns-checks/CHANGELOG.md](../packages/dns-checks/CHANGELOG.md) for the engine package. Look up a stamp change there before concluding that a domain changed.

## 2. Partial scans: read the evidence before reading the grade

A scan is graded only when enough of its checks completed. The rule is a ratio, `evidence.ratio` (completed checks over attempted checks), compared against a threshold: the constant `EVIDENCE_SUFFICIENCY_THRESHOLD` in `packages/dns-checks/src/scoring/evidence.ts`, which is `0.6` at this commit and can be overridden by the deployment's `SCORING_CONFIG`. It is a gate on whether a grade is emitted at all; it does not change what a grade means.

Fields to read on every result:

| Field | Meaning |
| --- | --- |
| `evidence` | `attempted`, `completed` and `ratio` for the scan. Present on graded and ungraded scans alike. |
| `inconclusiveCategories` | Categories that could not be measured (a probe timed out, errored, or never reached the origin). They are left out of the score and the remaining weights are renormalized. |
| `notApplicableCategories` | Categories that were measured and do not apply to this domain. Disjoint from the list above. |
| `checkStatuses` | Per category: `completed`, `timeout` or `error`. |
| `measured` | On each row of a batch result: `false` means no check contributed a measurement for that domain. |

Rules to build in:

- **A category missing from `categoryScores` was not measured. It did not fail.** Leave it out of the denominator of any coverage or failure rate. A `null` entry means not applicable, also not a failure.
- **`score: null` (and `grade: null`) means ungraded.** It is not zero and it is not an `F`. Never render it as a failing grade, never coerce it to a number, and exclude it from rankings, comparisons and policy checks.
- **Treat a result with any inconclusive category as provisional.** Before reporting a regression or opening an alert off such a result, rescan and confirm the movement survives a scan in which the category is measured.

## 3. Batch and asynchronous scanning

Two ways to scan several domains:

- **`batch_scan`** runs in the request. A call takes up to 10 domains and runs under a wall-clock budget. Which tiers may call it is a quota question (section 4); anonymous callers have no allowance for it. If the budget runs out, the domains not reached are returned with `measured: false` and the error `batch_budget_exceeded`, and the batch carries `incomplete: true` with the `unscanned` list. A caller that ignores those fields would read the dropped tail as unscored.
- **`batch_scan_start`, `batch_scan_status`, `batch_scan_findings`** run the same scan as a queued job. This path needs an authenticated caller, takes the same 10-domain limit, and needs a caller-chosen `idempotency_key` (8 to 128 characters). A deployment without the queue returns `Async batch scanning is not provisioned`.

Using the job API:

1. `batch_scan_start` returns a `jobId` and a status. Job ids belong to the credential that started them; another credential gets `Batch scan job not found`.
2. Poll `batch_scan_status` until `status` is `completed` or `failed` (the states are `queued`, `running`, `completed`, `failed`). Poll with a growing delay; there is no push notification.
3. Read the result with `batch_scan_findings` once the job is `completed`. Check `incomplete` and `unscanned` on a completed job: completed does not mean every domain was scanned.
4. A scan that throws is retried by the queue and, once its retries are used up, recorded as `failed` with an `error`. A job left `running` after its worker stopped is picked up again when the queue redelivers it. Treat `failed` as final for that attempt. If a job stays `queued` or `running` far longer than a scan should take, treat it as failed too and start a new one with a fresh key (the same key would hand you the stuck job back).
5. Job records are kept for a fixed result lifetime (seven days at this commit, in `ASYNC_BATCH_RESULT_TTL_SECONDS`). Fetch results before then.

**An idempotency key is a replay key, not a run label.** Starting a job with the same key, domain set and `force_refresh` setting as an earlier job from the same credential returns the earlier job (`src/tools/batch-scan-async.ts`), whatever state it is in other than `failed`; a failed job is started again. So a periodic rescan must send a fresh key each run, for example one that includes the run date. Reusing last week's key returns last week's results without scanning.

## 4. Quotas

Rate limits, daily quotas per tier, concurrency limits and which tools need a paid plan are documented in one place each and are not repeated here, so they cannot drift: see [Authentication and tier quotas in client-setup.md](client-setup.md#authentication) and the Pricing section of the [README](../README.md#pricing). Read the rate-limit and quota response headers and the 429 handling in section 6 rather than hard-coding a number.

## 5. Authority to scan

Most tools are passive public lookups (DNS answers through a resolver, public certificate-transparency data, registry records). Some go further, and an integrator should know which:

- **Direct queries to a domain's authoritative nameservers.** `check_authoritative_dns_infra` (and `scan_domain` with that profile) queries a domain's own nameservers over TCP/53. For callers authenticated above the free tier, it also sends a zone-transfer request to test whether the server refuses it, and reads only the first response; no zone data is retrieved. Anonymous and free-tier callers never trigger the zone-transfer test (`src/handlers/tool-registry.ts`).
- **HTTP requests to the target's own hosts.** Several checks fetch from the target's web or mail-policy hosts (the HTTP security, TLS, BIMI logo, MTA-STS policy, `llms.txt` and subdomain-takeover checks, among others, all included in `scan_domain`). They identify themselves with a declared scanner User-Agent that names a bot-policy page and a security contact, and they honour the target's `robots.txt` rules for that agent. A disallowed fetch is not made; the check reports that it abstained rather than a clean result (`packages/dns-checks/src/robots-gate.ts`). An unreachable or unreadable `robots.txt` does not block a scan.

**The service does not verify that you own or may test a domain.** Anyone can submit any domain. Scanning is intended for domains you own or have explicit permission to test (see the [responsible use paragraph in the README](../README.md#responsible-use)). A provider scanning on behalf of its own customers needs its own written authority from each domain owner; nothing in the service or its terms substitutes for that, and BlackVeil does not grant it on your behalf. Keep that authority on record for each target.

What the operator can see about your requests, including your list of target domains, is described in [What the hosted server logs about you](client-setup.md#what-the-hosted-server-logs-about-you).

## 6. Errors and retries

What the HTTP layer returns at this commit (`src/index.ts`, `src/mcp/execute.ts`):

| Status | Meaning | What to do |
| --- | --- | --- |
| `401` | A credential was sent but is missing, expired or not recognised; or the tool requires authentication and none was sent. When OAuth is enabled the response carries a `WWW-Authenticate` challenge. | Do not retry the same request. Fix or renew the credential. Sending no credential at all selects the anonymous tier, unless the deployment requires authentication. |
| `403` | The tool is not available to the caller's tier (paid-only tools), or the request's `Origin` header was refused. | Do not retry. Change plan or remove the cause. |
| `429` | A rate limit, a daily quota or the per-tier concurrency limit was hit. | Wait. Most `429` responses carry a `retry-after` header in seconds; honour it, then retry. Do not retry in a tight loop and do not fan out parallel retries. |
| `503` | The service could not answer right now. One case is a credential whose revocation or version state could not be read: that response carries `retry-after: 5`. Other `503` responses (for example a configuration fault) carry no `retry-after`. | Retry with exponential backoff and jitter, and a cap on attempts. A `503` that persists is an operator problem, not a request problem. |

General rules:

- A `retry-after` header is authoritative where it exists; otherwise back off exponentially.
- Only `429` and `503` are worth retrying. Retrying a `401` or `403` repeats the same refusal and spends your rate allowance.
- Scan results are cached on the server for a short time. `force_refresh` bypasses that cache and is limited separately, so do not set it by default on a scheduled job.
- Treat a transient failure inside a result (`checkStatuses` of `timeout` or `error`, inconclusive categories) as section 2 describes, not as an HTTP error.
