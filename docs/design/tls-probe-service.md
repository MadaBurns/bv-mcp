# Design: `BV_TLS_PROBE` service binding — negotiated-TLS-version detection

**Status:** Design (no implementation). **Author:** engineering. **Date:** 2026-05-31.
**Change class:** B (internal platform) on merge; the scoring enrichment is an
operator-only, fail-soft addition that does **not** change scores on BSL self-hosts.

---

## 1. Problem

A Cloudflare Worker's outbound `fetch()` cannot observe the **negotiated TLS
protocol version** of the connection it makes. The runtime terminates/initiates
TLS itself and exposes only the HTTP response — there is no `response.tlsVersion`,
no cipher, no handshake metadata. So `check_ssl` (and its package core
`checkSSL`) can verify HTTPS reachability, HSTS, and the HTTP→HTTPS redirect, but
**cannot detect a server that still offers TLS 1.0 / 1.1** — a real, gradeable
weakness (PCI-DSS forbids TLS ≤1.1; RFC 8996 deprecates both).

This gap is documented in the code at
`packages/dns-checks/src/checks/check-ssl.ts:44`:

> *"Certificate expiry, TLS version, and cipher suite analysis require a
> dedicated TLS scanner."*

The same limitation applies to **any** Worker — a `BV_TLS_PROBE` worker can't use
plain `fetch()` to learn the version either. The probe service must perform a
**real, version-aware handshake** (see §6). bv-mcp's job in this design is only to
*consume* that result over a service binding, fail-soft, and map it to a finding —
mirroring exactly how the recon tools consume `BV_RECON`.

## 2. Goals / non-goals

**Goals**
- Detect when a domain's HTTPS endpoint offers legacy TLS (1.0 / 1.1) and surface
  it as a **High**-severity finding that dents the SSL score.
- Fail **soft**: absent binding (every BSL self-host) → no finding, no score
  change, no thrown error — identical behaviour to today.
- **Never penalize TLS 1.2.** 1.2-only and 1.2+1.3 are both a pass.

**Non-goals**
- Full cipher-suite / certificate-chain / OCSP scanning (future work; the contract
  leaves room for cipher data but severity keys only on version).
- Changing the SSL category's weight, baseline, or its score on self-hosts.
- Making the probe part of the public BSL distribution.

## 3. Scored vs. standalone — and the integration decision

Using the `bv-mcp-add-tool` framing (scored check vs. standalone/intelligence
tool), there are three shapes. **Recommendation: Option A.**

### Option A (recommended) — enrich the existing `check_ssl` Core category

The TLS-version result is folded into the **existing `ssl` category** (Core,
weight 8). When the probe is present *and* finds TLS ≤1.1, the Worker wrapper
appends a High finding to the SSL `CheckResult`; the existing scoring engine
applies the High penalty to the SSL category. No new category, no new SSOT
surfaces, no `scan_domain` wiring changes.

This is the **same pattern already in production** for `cymru_asn`,
`check_lookalikes`, and `check_fast_flux`, which "gain optional bv-recon
enrichment when the binding is present" (CLAUDE.md, Recon tools). TLS version is
conceptually *part of* SSL/TLS posture, so it belongs in the SSL category rather
than a sibling.

**Crucial scoring-coherence rule:** the enrichment may only ever *subtract* when
weak TLS is actively detected. It must **not** set `missingControl`, must **not**
add a penalty when the probe is absent, and must **not** penalize when the probe
reports 1.2/1.3. Therefore:

- Probe **absent** (self-host) → SSL category scores **exactly as today**.
- Probe **present**, min version 1.2 or 1.3 → no finding / info → **no change**.
- Probe **present**, 1.0/1.1 offered → one High finding → SSL category penalty.

The intended asymmetry: the *same* domain may score slightly lower on
BlackVeil-production (probe present, weak TLS visible) than on a self-host (gap
invisible). That is correct — prod simply has more signal — and it mirrors the
existing `lookalikes:recon` vs `lookalikes` cache-key split.

### Option B (rejected) — new standalone `check_tls` intelligence tool

`group: 'intelligence'`, out-of-union category, no `tier`, `scanIncluded: false`,
skips all scoring. Clean separation, but **standalone tools are unscored**, so a
TLS 1.0/1.1 finding would carry **no score consequence** — defeating the whole
point (we want to penalize weak TLS, not just narrate it).

### Option C (rejected) — new *scored* `check_tls` category

A new Core/Protective category with full scoring wiring. Rejected because:
- It trips **every** SSOT surface in the `bv-mcp-add-tool` checklist (CATEGORY_TIERS,
  IMPORTANCE_WEIGHTS, all 6 profile-weight tables, scoring snapshots in two
  locations, the 7 `toHaveLength` count specs, the scan-category count, etc.).
- On BSL self-hosts the binding is absent, so the category can't be measured. A
  scored category that's structurally unmeasurable on most deploys is fragile: it
  either sits in the denominator at 0 (lowering every self-host score — the exact
  anti-pattern CLAUDE.md warns about for `scanIncluded` tools) or must thread an
  "inconclusive → excluded" path through the renormalization logic. Far more
  surface area than Option A for no scoring benefit over it.

> A `check_tls` standalone tool *could* still be added later as a **diagnostic**
> companion (operator-run, unscored, full version+cipher dump) on top of Option A's
> scored enrichment — but it is out of scope here.

## 4. How it integrates (Option A)

The package core `checkSSL` stays **runtime-agnostic and pure** — it must not gain
a Cloudflare service-binding dependency. The probe call lives in the **Worker
wrapper** `src/tools/check-ssl.ts`, exactly where the recon enrichment lives for
the lookalikes/asn wrappers:

```
src/tools/check-ssl.ts (Worker wrapper)
  ├── const result = await checkSSL(domain, fetch, { timeout });   // pure package core, unchanged
  ├── if (tlsProbeBinding) {
  │     const probe = await callTlsProbe(tlsProbeBinding, tlsProbeAuthToken, domain);  // fail-soft, null on any failure
  │     if (probe) result = mergeTlsFinding(result, probe);        // append High finding iff <=1.1; never missingControl
  │   }
  └── return result;                                               // category stays 'ssl'
```

`mergeTlsFinding` rebuilds the SSL `CheckResult` via `buildCheckResult('ssl', …)`
so the recomputed `passed`/score reflect the added finding — the same shape used
by the new `escalateDmarcForImpersonation` post-processing helper.

New file `src/lib/tls-probe-binding.ts` mirrors `src/lib/recon-binding.ts`
one-to-one: a `TlsProbeBinding` interface (`{ fetch }`), an 8 s timeout, a
`composeSignal()` that `AbortSignal.any([timeout, caller])`, a Zod
`.passthrough()` response schema, and a single `callTlsProbe()` that returns
`null` on **any** failure (binding absent, non-2xx, malformed body, network
error, timeout). Callers degrade to pre-binding behaviour.

## 5. Request / response contract

Mirror the recon `GET /osint/check` shape (query params + Bearer auth, opaque
fail-soft body).

**Request**

```
GET https://bv-tls-probe/probe?host=<validatedDomain>&port=443
Authorization: Bearer <BV_TLS_PROBE_KEY>          # omitted if token unset
```

- `host` is the **already-validated** domain (`validateDomain`/`sanitizeDomain`
  run before the tool is invoked); the probe re-validates defensively.
- `port` defaults to 443; included for future MX/SMTP-STARTTLS probing (587/465/25).

**Response** (`200`, all fields optional/lenient so unknown extras never fail
validation):

```jsonc
{
  "host": "example.com",
  "port": 443,
  "reachable": true,
  "minVersion": "TLS1.2",                 // lowest version the server accepted
  "maxVersion": "TLS1.3",                 // highest negotiated
  "supportedVersions": ["TLS1.2", "TLS1.3"],
  "cipher": { "name": "TLS_AES_128_GCM_SHA256", "bits": 128 },  // optional, if cheap
  "probedAt": "2026-05-31T00:00:00Z"
}
```

- **`minVersion` is the field severity keys on.** `supportedVersions` is
  informational/diagnostic.
- Version tokens: `"TLS1.0" | "TLS1.1" | "TLS1.2" | "TLS1.3"` (also accept
  `"SSL3.0"`/`"SSL2.0"` → treated as ≤1.1, Critical-adjacent but mapped High per
  the task's bound).
- `reachable: false` or `error` present → the probe couldn't complete a handshake
  (host down, port filtered). Treat as **no finding** (inconclusive), *not* a pass
  and *not* a penalty — consistent with the "excludes inconclusive" scoring rule.

**Non-200 / network failure** → `callTlsProbe` returns `null` → no enrichment.

### Severity mapping (the must-not-penalize-1.2 rule)

| Probe result (`minVersion`)        | Finding                                   | Severity | SSL score effect            |
| ---------------------------------- | ----------------------------------------- | -------- | --------------------------- |
| `TLS1.0` or `TLS1.1` offered       | "Legacy TLS version offered (≤ TLS 1.1)"  | **High** | High penalty on `ssl`       |
| `TLS1.2` min (1.3 may be present)  | none, or "TLS 1.2+ enforced" (info)       | info     | **none** — pass             |
| `TLS1.3` present, no ≤1.1          | none, or "Modern TLS (1.3)" (info)        | info     | **none** — pass             |
| `reachable:false` / `error` / null | none (inconclusive)                       | —        | **none** — excluded         |

The High finding text should note the probe origin and that it is operator-only,
so self-host operators understand why the same scan elsewhere lacks it (parallel
to the recon `unprovisioned` messaging).

## 6. The probe service itself (context, not in scope to build here)

Worth stating so the contract isn't mistaken for "just another Worker fetch": the
probe **cannot** learn the version via `fetch()`. Viable backends:

- **Cloudflare Workers `connect()` raw sockets** (`cloudflare:sockets`,
  `secureTransport: 'on' | 'starttls'`): open the TCP socket, attempt the TLS
  handshake. To determine the *minimum* accepted version, attempt
  version-pinned handshakes (e.g. force max = TLS 1.1; success ⇒ ≤1.1 offered).
  Exposure of negotiated version/cipher via the sockets API is limited, so this
  may require inferring acceptance from handshake success/failure rather than
  reading a field.
- **A dedicated sidecar** (small VM/container or external host) running a real TLS
  stack (OpenSSL/`testssl.sh`/sslyze-style logic) and exposing the JSON contract
  above. Most reliable for cipher detail.

Either way bv-mcp is decoupled: it speaks only the §5 contract over the binding.

## 7. Caching

TLS posture changes slowly and handshakes are expensive, so cache **longer** than
the 5 min scan TTL — model it on the `check_lookalikes` 60-min cache:

- Probe enrichment cached under a binding-aware key. In the `check_ssl` registry
  entry, vary the cache key by binding presence, exactly like the recon tools:

  ```ts
  cacheKey: (_a, ro) => (ro?.tlsProbeBinding ? 'ssl:tls-probe' : 'ssl'),
  ```

  This prevents a probe-enriched result (with the TLS finding) from being served
  to/served from a deploy where the binding is absent, and vice-versa — the same
  correctness reason `lookalikes:recon` vs `lookalikes` are split.
- Inside `scan_domain`, the SSL category's existing `cache:<domain>:check:ssl`
  entry already carries the merged findings, so no separate scan-cache plumbing is
  needed — the enrichment rides the SSL result. A dedicated longer-lived
  `cache:<domain>:tls-probe` entry (e.g. 60 min) inside `callTlsProbe` is
  optional, to avoid re-handshaking on a `force_refresh` SSL re-scan.
- `force_refresh` / `skipCache` must reach the probe path so an operator can force
  a fresh handshake.

## 8. Operator-deploy wiring (mirror `BV_RECON` exactly)

The binding is **operator-only** — wired in the gitignored
`.dev/wrangler.deploy.jsonc`, **never** in the public `wrangler.jsonc`. Every
construction/threading site that `BV_RECON` touches gets a `BV_TLS_PROBE` sibling:

1. **Env type** — add `BV_TLS_PROBE?: Fetcher;` and `BV_TLS_PROBE_KEY?: string;`
   to `BvMcpEnv` (`src/index.ts`, alongside `BV_RECON?: Fetcher;` at ~`:163`).
2. **3 construction sites in `src/index.ts`** (the same ~`:504`, `:586`, `:744`
   where `reconBinding: c.env.BV_RECON` is set) — add
   `tlsProbeBinding: c.env.BV_TLS_PROBE` and
   `tlsProbeAuthToken: c.env.BV_TLS_PROBE_KEY`. Missing any site → the field is
   `undefined` and the tool silently never enriches (the documented `BV_RECON`
   foot-gun).
3. **`ToolRuntimeOptions`** — add `tlsProbeBinding?: { fetch: typeof fetch }` and
   `tlsProbeAuthToken?: string` in **both** `src/mcp/dispatch.ts` (~`:72-75`,
   passed through at ~`:205-206`) and `src/handlers/tools.ts` (~`:183-190`).
4. **`TOOL_REGISTRY` `check_ssl` entry** (`src/handlers/tools.ts`) — thread
   `ro?.tlsProbeBinding` / `ro?.tlsProbeAuthToken` into the `execute`, and set the
   binding-aware `cacheKey` from §7.
5. **New** `src/lib/tls-probe-binding.ts` (mirrors `recon-binding.ts`).
6. **`.dev/wrangler.deploy.jsonc`** — add the `services` entry for `BV_TLS_PROBE`
   and the `BV_TLS_PROBE_KEY` secret. The inject script
   (`scripts/inject-private-config.cjs`) already enumerates `services`, so it
   carries through to `wrangler.production.jsonc`.
7. **CLAUDE.md Bindings table** — add `BV_TLS_PROBE` (Service,
   "Operator-deploy only … fail-soft when absent → no TLS-version finding") and
   `BV_TLS_PROBE_KEY` (Secret) rows, matching the `BV_RECON` / `BV_RECON_KEY`
   entries.

Because this is **enrichment of an existing tool** (not a new tool), the
tool-count SSOT surfaces (`toHaveLength(N)`, server.json "N MCP tools", README
table, generated Rust perms, chaos matrix) are **untouched** — a key advantage of
Option A.

## 9. Testing (when built)

- **Unit** (`packages/dns-checks` is untouched; tests live at root): mock the
  probe binding via the `dns-mock` style; assert `minVersion: 'TLS1.1'` → one High
  `ssl` finding; `'TLS1.2'` → no finding; `reachable:false` → no finding; binding
  absent → result byte-identical to today's `checkSSL`.
- **Scoring coherence**: a domain with otherwise-perfect SSL + probe `TLS1.1`
  scores **below** the same domain with the probe absent; `TLS1.2` scores
  **equal** to probe-absent (regression guard for "must not penalize 1.2").
- **Fail-soft**: binding throws / returns 500 / returns garbage → no throw, no
  finding (the `callReconScan` null-on-everything contract).
- **Audit**: `domain-required-ssot` and the count audits should be **unaffected**
  (no new tool) — assert that explicitly so a future refactor doesn't silently
  promote this to a tool.

## 10. Open decisions (flag for the operator)

1. **Option A vs. a future diagnostic `check_tls`** — A is recommended and
   sufficient for scoring; a standalone diagnostic tool can follow if operators
   want a full version/cipher dump.
2. **Probe backend** — Workers `connect()` (cheap, same platform, limited
   introspection) vs. a sidecar TLS scanner (richer, more infra). The §5 contract
   is backend-agnostic; pick when building the probe.
3. **STARTTLS / mail ports** — the `port` param leaves room to extend the same
   probe to SMTP 25/465/587 for `check_mx` / MTA-STS hardening later. Out of scope
   now.
