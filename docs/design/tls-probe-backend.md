# Design: `bv-tls-probe` backend — Browser-Rendering negotiated-TLS detection

**Status:** Design (no implementation). **Author:** engineering. **Date:** 2026-05-31.
**Change class:** B (internal platform) — a new operator-only Worker behind the
already-merged, fail-soft `BV_TLS_PROBE` binding. No change to BSL self-host behaviour.

**Companion to** [`tls-probe-service.md`](./tls-probe-service.md), which designed and
shipped the **consumer** side in bv-mcp (the `BV_TLS_PROBE` binding, `callTlsProbe`,
`mergeTlsFinding`, and the §5 request/response contract). That doc's §6 explicitly
deferred *the probe service itself*. **This doc designs that backend.**

---

## 1. Problem & constraint recap

bv-mcp's `check_ssl` / `scan_domain` already consume a `BV_TLS_PROBE` service over the
§5 contract and fail soft when it is absent (shipped, PR #314). We now need a backend
that actually answers `GET /probe?host=…&port=443` with a negotiated-TLS-version verdict.

The hard constraint (verified, 2026-05-31): **a Cloudflare Worker cannot learn a remote
server's TLS version through normal APIs.**

- `fetch()` exposes no TLS metadata.
- `connect()` (`cloudflare:sockets`) `SocketOptions` is only
  `secureTransport: "off"|"on"|"starttls"` + `allowHalfOpen`; `SocketInfo` exposes only
  `remoteAddress`/`localAddress`. **No version control, no version readout.**
- `node:tls` is a *partial* shim. A runtime spike (workerd, `wrangler dev`) confirmed
  `tls.connect()` connects but `getProtocol()` and `getCipher()` return **`null`** and
  `maxVersion` is **ignored** — so it can neither read nor pin the version.

## 2. Approaches considered

| # | Approach | Detects | In CF ecosystem? | Security/robustness | Verdict |
|---|----------|---------|:---:|---|---|
| A | **Browser Rendering** (`@cloudflare/puppeteer`, `securityDetails().protocol()`) | negotiated (max) version + cipher + cert | **Yes** (native) | Real Chrome TLS stack; no hand-rolled crypto | **Recommended** |
| B | `rustls`/WASM client over `connect()` | negotiated (max) version | Yes | rustls **refuses** TLS 1.0/1.1 → same blind spot as A, far more build cost | Rejected |
| C | Hand-rolled TLS `ClientHello` bytes over raw `connect()` | true **min** version (can speak ≤1.1) | Yes | Security-sensitive byte parsing; fragile; multi-day | Deferred (future, only if "1.1-alongside-1.2" detection is required) |
| D | Legacy-OpenSSL **sidecar** (VM/container) | true min version + full cipher matrix | **No** (non-Workers infra) | Most accurate; most ops | Rejected (out of ecosystem) |

**Why A wins.** It is the only option that is *both* native to Cloudflare *and* free of
hand-rolled TLS, and it reuses Chrome's hardened stack. It also yields **cipher and full
certificate chain/expiry for free** — data `tls-probe-service.md` §2 listed as future work.
Critically, B (the "robust Rust" instinct) buys **nothing** over A for this signal: rustls
only implements TLS 1.2/1.3, so like a browser it can only reveal the *negotiated max*, not
whether ≤1.1 is *also* offered. Only C/D can do that, at a cost/risk not justified by the
threat (see §6).

## 3. The detection model (and its honest boundary)

`securityDetails().protocol()` reports the **negotiated** (highest mutually-supported)
version. You **cannot** pin Chrome to offer only ≤1.1 (Chrome removed version flags; CDP
exposes none). Chrome has **required ≥ TLS 1.2 since 2020** and hard-fails ≤1.1 with
`ERR_SSL_VERSION_OR_CIPHER_MISMATCH` / `ERR_SSL_OBSOLETE_VERSION`. That failure is the signal:

| Real-world server posture | Chrome behaviour | Probe verdict |
|---|---|---|
| Supports ≥ TLS 1.2 | navigates; `protocol()` = `TLS 1.2`/`1.3` | **pass** — `minVersion = negotiated (≥1.2)` |
| **Stuck at ≤ 1.1** (no 1.2/1.3) | TLS handshake **fails**, host still answers TCP/443 | **weak** — `minVersion = "TLS1.1"` → bv-mcp High finding |
| Host down / 443 filtered | TCP connect fails too | **inconclusive** — `reachable:false` → no finding |
| Offers 1.1 **and** 1.2+ | negotiates 1.2+, hides the 1.1 offering | **pass** (false-negative — see boundary) |

**Boundary (documented, not a bug):** approach A detects servers that *cannot* do modern
TLS (max ≤1.1) — the realistic, gradeable weakness in 2026, since operators disabled ≤1.1
wholesale. It does **not** detect a server that still *offers* 1.1 alongside 1.2+. Closing
that gap requires actively speaking 1.0/1.1 (approach C/D) and is explicitly out of scope
here. The finding text must reflect this so operators understand the signal's meaning.

**Reachability disambiguation.** A Chrome TLS failure only means "legacy TLS" if the host
is otherwise up. The probe corroborates with a raw `connect()` TCP probe to `host:port`:
TCP open + Chrome TLS-version error ⇒ `minVersion:"TLS1.1"` (weak); TCP closed/timeout ⇒
`reachable:false` (inconclusive). This keeps the §5 contract's "inconclusive ≠ penalty" rule intact.

## 4. Architecture

```
bv-mcp (check-ssl.ts) ──BV_TLS_PROBE binding──▶ bv-tls-probe backend
                                                  ├── GET /probe?host=&port=  (Bearer auth)
                                                  ├── 1. TCP connect() to host:port  → reachable?
                                                  ├── 2. Browser Rendering: page.goto(https://host)
                                                  │        └─ main-response.securityDetails().protocol()/cipher/cert
                                                  ├── 3. classify → §5 response JSON
                                                  └── KV cache (60 min) keyed by host:port
```

The backend speaks the **unchanged §5 contract**, so **no bv-mcp code changes** — the merged
`callTlsProbe`/`mergeTlsFinding` already map a `minVersion ≤1.1` response to the High finding.

### 4.1 Hosting decision — DECIDED: dedicated `bv-tls-probe` worker

**Decision (2026-05-31): a dedicated `bv-tls-probe` Worker**, with its own Browser Rendering
binding, implementing the §5 `GET /probe` contract. `BV_TLS_PROBE` points at it; it matches
the `bv-recon` sibling pattern (clean isolation, independent rate/limits).

Reusing `bv-browser-renderer` (add a `/tls-probe` route, share its browser pool + `keep_alive`
to amortize per-session billing) was the *preferred* option on cost grounds, **but its source
repo is not accessible from the build environment** (deployed Worker exists in Cloudflare; no
local checkout, unresolvable via `gh`). Rather than block on that, we scaffold the dedicated
worker now. **Cost note (carried forward):** a dedicated worker holds its own
`maxConcurrentSessions` browser quota and cannot share `bv-browser-renderer`'s warm sessions,
so the §6 KV cache (60 min) and `keep_alive` reuse *within* this worker are load-bearing for
cost control. If browser-quota cost becomes material, folding `/tls-probe` into
`bv-browser-renderer` later is a clean migration (the §5 contract and `BV_TLS_PROBE` binding
target are the only things that change).

## 5. Response mapping (to the existing §5 schema)

The backend returns the §5 body verbatim; mapping from Browser Rendering:

```jsonc
// success (page navigated)
{ "host": "...", "port": 443, "reachable": true,
  "minVersion": "<normalized protocol>", "maxVersion": "<same>",
  "supportedVersions": ["<negotiated>"],
  "cipher": { "name": "<securityDetails.cipher()>" },
  "probedAt": "<iso>" }

// TCP up, Chrome TLS-version failure
{ "host":"...", "port":443, "reachable": true, "minVersion": "TLS1.1",
  "error": null, "probedAt": "<iso>" }   // → High finding via mergeTlsFinding

// TCP down / filtered
{ "host":"...", "port":443, "reachable": false, "error": "<reason>", "probedAt":"<iso>" }
```

`securityDetails.protocol()` strings (`"TLS 1.2"`, `"TLSv1.3"`) are normalized to the §5
tokens (`TLS1.2`/`TLS1.3`) by the same lenient normalizer already shipped in
`mergeTlsFinding`'s `isWeakTlsVersion` (uppercase, strip spaces, strip `V`). Non-version-class
nav failures (DNS, refused, timeout) → `reachable:false`.

## 6. Caching, cost & limits

- **Browser sessions are expensive and rate-limited.** Cache verdicts in KV **60 min** keyed
  `tls-probe:<host>:<port>` (mirrors `check_lookalikes`' 60-min posture; TLS config changes
  slowly). `force_refresh` from bv-mcp bypasses the cache.
- Reuse a browser session via `keep_alive` (up to 10 min) to amortize launch cost across a batch.
- Hard per-probe timeout (≤ 8 s, matching bv-mcp's `TLS_PROBE_TIMEOUT_MS`) so a slow target
  can't pin a browser session.
- Operator-only: never provisioned on BSL self-hosts → zero cost there (bv-mcp stays fail-soft).

## 7. Security

- **Bearer auth** on `/probe` (`BV_TLS_PROBE_KEY`), constant-time compare; reject unauth.
- **SSRF re-validation:** re-run host validation (reject private IPs/blocklist/non-public TLDs)
  *inside* the backend even though bv-mcp validates first — defence in depth, since the backend
  drives a real browser to an attacker-influenced host. Restrict navigation to `https://<host>`.
- Browser Rendering is Cloudflare-sandboxed; still set a navigation timeout and `page.close()`
  in a `finally` to avoid leaked sessions.
- No secrets in logs; never echo the bearer token. Probe target host is the only logged datum
  (hash it, consistent with bv-mcp analytics).

## 8. Testing

- **Unit (pure):** `protocol()` string → §5 token normalization; nav-error classification
  (TLS-version error vs unreachable); the TCP-up-but-TLS-fail → `minVersion:"TLS1.1"` mapping.
- **Integration:** against known fixtures — a TLS 1.3 host (→ pass), a TLS 1.2 host (→ pass),
  and `badssl.com`'s legacy endpoints (`tls-v1-1.badssl.com:1011`) which Chrome refuses
  (→ `minVersion:"TLS1.1"`, weak). An unresolvable host (→ `reachable:false`).
- **Contract:** the backend's JSON validates against bv-mcp's `TlsProbeResponseSchema`
  (the §5 lenient schema) — guards drift between the two repos.
- **bv-mcp side is already covered** (PR #314): no new bv-mcp tests needed; an end-to-end
  smoke (operator deploy) asserts a real `scan_domain` of a legacy-TLS host gains the High
  `ssl` finding when the binding is present.

## 9. Open decisions

1. ~~**Host:** reuse `bv-browser-renderer` vs dedicated worker.~~ **RESOLVED (§4.1): dedicated
   `bv-tls-probe` worker** — reuse repo was inaccessible; revisit folding into
   `bv-browser-renderer` only if browser-quota cost becomes material.
2. **`minVersion`-true detection (1.1-alongside-1.2):** defer (approach C hand-rolled
   ClientHello) — revisit only if a customer requires PCI-grade "is ≤1.1 *offered*" beyond
   "is the server stuck at ≤1.1". Flag in the finding text that the current signal is the latter.
3. **Cipher/cert enrichment:** Browser Rendering hands us cipher + cert expiry/issuer for free.
   Out of scope to *grade* here, but worth capturing into the §5 `cipher` field now and grading
   later (would extend `mergeTlsFinding`, a separate bv-mcp change).
4. **STARTTLS / mail ports (25/465/587):** Browser Rendering is HTTPS-only, so mail-port TLS
   probing would need approach C/D. Out of scope; the `port` param remains for a future backend.
