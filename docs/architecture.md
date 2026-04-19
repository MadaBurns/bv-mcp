# Architecture Diagrams

> Auto-generated reference for AI agents and contributors.
> All PII, secrets, and internal infrastructure details have been stripped.

## System Overview

```mermaid
graph TB
    subgraph Clients["MCP Clients"]
        CLI["CLI (stdio)"]
        IDE["IDE Extensions<br/>(VS Code, Cursor, Windsurf)"]
        WEB["Web App<br/>(Service Binding)"]
        API["HTTP Clients<br/>(Streamable HTTP)"]
    end

    subgraph Transports["Transport Layer"]
        STDIO["src/stdio.ts<br/>Native stdio JSON-RPC"]
        HTTP["src/index.ts<br/>Hono HTTP + SSE"]
        INTERNAL["src/internal.ts<br/>Service Binding Routes"]
    end

    CLI --> STDIO
    IDE --> HTTP
    API --> HTTP
    WEB --> INTERNAL

    subgraph Middleware["Middleware (Public Only)"]
        CORS["CORS / Origin Check"]
        AUTH["Auth (Bearer Token)"]
        RL["Rate Limiting"]
        SESS["Session Management"]
        BODY["Body Parse + Validate"]
    end

    HTTP --> CORS --> AUTH --> RL --> SESS --> BODY

    subgraph MCP["MCP Protocol Layer"]
        EXEC["mcp/execute.ts<br/>Transport-neutral executor"]
        DISPATCH["mcp/dispatch.ts<br/>JSON-RPC method router"]
        GATES["mcp/route-gates.ts<br/>Pre-dispatch guards"]
        REQ["mcp/request.ts<br/>Body parse + validation"]
    end

    BODY --> EXEC
    STDIO --> EXEC
    EXEC --> GATES --> DISPATCH

    subgraph Handlers["Method Handlers"]
        INIT["initialize"]
        TLIST["tools/list"]
        TCALL["tools/call"]
        RLIST["resources/list"]
        RREAD["resources/read"]
        PLIST["prompts/list"]
        PGET["prompts/get"]
    end

    DISPATCH --> INIT
    DISPATCH --> TLIST
    DISPATCH --> TCALL
    DISPATCH --> RLIST
    DISPATCH --> RREAD
    DISPATCH --> PLIST
    DISPATCH --> PGET

    subgraph Tools["Tool Layer (src/tools/)"]
        SCAN["scan_domain<br/>Parallel orchestrator"]
        CHECKS["16 DNS Checks<br/>(SPF, DMARC, DKIM, etc.)"]
        ANALYSIS["Analysis Tools<br/>(explain, compare, generate)"]
        INTEL["Intelligence Tools<br/>(benchmark, provider insights)"]
    end

    TCALL --> SCAN
    TCALL --> CHECKS
    TCALL --> ANALYSIS
    TCALL --> INTEL
    SCAN --> CHECKS

    INTERNAL --> TCALL

    subgraph Infra["Infrastructure (src/lib/)"]
        DNS["dns.ts<br/>DNS-over-HTTPS"]
        CACHE["cache.ts<br/>KV + In-memory TTL<br/>+ sentinel dedup"]
        SCORING["scoring.ts<br/>Three-tier scoring"]
        SANITIZE["sanitize.ts<br/>Domain + SSRF protection"]
        ANALYTICS["analytics.ts<br/>Telemetry (fail-open)"]
        CB["circuit-breaker.ts<br/>DO failure isolation"]
        SEM["semaphore.ts<br/>DNS concurrency control"]
    end

    CHECKS --> DNS
    CHECKS --> CACHE
    CHECKS --> SCORING
    CHECKS --> SANITIZE
    SCAN --> CACHE
    SCAN --> SCORING
    DNS --> SEM
    RL --> CB

    subgraph External["External Services"]
        DOH["DNS-over-HTTPS<br/>(Primary + Fallback)"]
        CTLOG["CT Log / crt.sh"]
    end

    DNS --> DOH
    Tools --> CTLOG

    subgraph Bindings["Cloudflare Bindings"]
        KV_RL["KV: RATE_LIMIT"]
        KV_CACHE["KV: SCAN_CACHE"]
        KV_SESS["KV: SESSION_STORE"]
        DO_QUOTA["DO: QuotaCoordinator"]
        DO_PROFILE["DO: ProfileAccumulator"]
        AE["Analytics Engine"]
    end

    RL --> KV_RL
    RL --> DO_QUOTA
    CACHE --> KV_CACHE
    SESS --> KV_SESS
    ANALYTICS --> AE
    SCAN -.-> DO_PROFILE
```

## Request Flow — Streamable HTTP

```mermaid
sequenceDiagram
    participant C as MCP Client
    participant W as Cloudflare Worker
    participant MW as Middleware
    participant EX as mcp/execute.ts
    participant DI as mcp/dispatch.ts
    participant TH as handlers/tools.ts
    participant TL as src/tools/*
    participant DNS as DoH Resolver
    participant KV as KV Cache

    C->>W: POST /mcp (JSON-RPC 2.0)
    W->>MW: Origin + Auth + Rate Limit
    MW-->>W: 403/429 (if denied)
    MW->>MW: Session validate + Body parse
    MW->>EX: executeMcpRequest()
    EX->>EX: JSON-RPC validate
    EX->>DI: dispatchMcpMethod()

    alt initialize
        DI->>DI: Create session
        DI-->>C: serverInfo + capabilities + Mcp-Session-Id
    else tools/call
        DI->>TH: handleToolsCall()
        TH->>TH: Zod validate args + domain sanitize
        TH->>KV: cacheGet(domain:check:name)
        alt Cache hit
            KV-->>TH: Cached CheckResult
        else Cache miss
            TH->>TL: Execute check function
            TL->>DNS: DNS-over-HTTPS query
            DNS-->>TL: DNS records
            TL-->>TH: CheckResult
            TH->>KV: cacheSet (5 min TTL)
        end
        TH->>TH: Format response (compact/full)
        TH-->>C: MCP text content
    else tools/list
        DI-->>C: TOOLS array (51 tools)
    end
```

## Request Flow — Native stdio (CLI)

```mermaid
sequenceDiagram
    participant STDIN as stdin
    participant SRV as src/stdio.ts
    participant EX as mcp/execute.ts
    participant DI as mcp/dispatch.ts
    participant TH as handlers/tools.ts
    participant STDOUT as stdout

    STDIN->>SRV: JSON-RPC line
    SRV->>SRV: Parse + validate
    SRV->>EX: executeMcpRequest()
    EX->>DI: dispatchMcpMethod()
    DI->>TH: Route to handler
    TH-->>DI: Result
    DI-->>EX: JSON-RPC response
    EX-->>SRV: Payload
    SRV->>STDOUT: JSON-RPC line
```

## Request Flow — Internal Service Binding

```mermaid
sequenceDiagram
    participant BW as Consumer Worker
    participant INT as src/internal.ts
    participant TH as handlers/tools.ts
    participant TL as src/tools/*
    participant DNS as DoH Resolver

    BW->>INT: POST /internal/tools/call
    Note over INT: No CORS, Auth, Rate Limit,<br/>Sessions, or JSON-RPC framing
    INT->>INT: Guard: reject if cf-connecting-ip present
    INT->>INT: Zod validate request body
    INT->>TH: handleToolsCall()
    TH->>TL: Execute tool
    TL->>DNS: DNS queries
    DNS-->>TL: Records
    TL-->>TH: CheckResult
    TH-->>INT: MCP content
    INT-->>BW: JSON response

    Note over BW,INT: Batch: POST /internal/tools/batch<br/>runs same tool across N domains<br/>with controlled concurrency (max 50)
```

## scan_domain Orchestration

```mermaid
graph TB
    START["scan_domain(domain)"] --> CACHE_CHECK{"Scan-level<br/>cache hit?"}
    CACHE_CHECK -->|Yes| RETURN["Return cached result"]
    CACHE_CHECK -->|No| PARALLEL

    subgraph PARALLEL["Promise.allSettled — 16 Checks (12s timeout)"]
        direction LR
        SPF["check_spf"]
        DMARC["check_dmarc"]
        DKIM["check_dkim"]
        DNSSEC["check_dnssec"]
        SSL["check_ssl"]
        MX["check_mx"]
        NS["check_ns"]
        CAA["check_caa"]
        BIMI["check_bimi"]
        TLSRPT["check_tlsrpt"]
        MTA["check_mta_sts"]
        HTTP["check_http_security"]
        DANE["check_dane"]
        SVCB["check_svcb_https"]
        LOOK["check_lookalikes"]
        SHADOW["check_shadow_domains"]
    end

    PARALLEL --> POSTPROC

    subgraph POSTPROC["Post-Processing"]
        NM["Non-mail adjustment<br/>(no MX → downgrade email findings)"]
        NS_ADJ["No-send adjustment<br/>(SPF -all → downgrade DKIM/MTA-STS)"]
        INTERACT["Category interaction penalties"]
        MATURITY["Compute maturity stage (0-4)"]
    end

    POSTPROC --> SCORE["computeScanScore()<br/>Three-tier weighted scoring"]
    SCORE --> GRADE["scoreToGrade()<br/>A+ through F"]
    GRADE --> FORMAT["formatScanReport()"]
    FORMAT --> CACHE_SET["cacheSet (5 min TTL)"]
    CACHE_SET --> DONE["Return ScanScore + report"]
```

## Scoring Model

```mermaid
graph LR
    subgraph Core["Core (70%)"]
        DMARC["DMARC (16)"]
        DKIM["DKIM (10)"]
        SPF["SPF (10)"]
        DNSSEC["DNSSEC (8)"]
        SSL["SSL (8)"]
    end

    subgraph Protective["Protective (20%)"]
        SUB["Subdomain Takeover (4)"]
        HTTP_S["HTTP Security (3)"]
        MTA_S["MTA-STS (3)"]
        MX_S["MX (2)"]
        CAA_S["CAA (2)"]
        NS_S["NS (2)"]
        LOOK_S["Lookalikes (2)"]
        SHADOW_S["Shadow Domains (2)"]
    end

    subgraph Hardening["Hardening (10%) — Bonus Only"]
        DANE_S["DANE"]
        BIMI_S["BIMI"]
        TLSRPT_S["TLS-RPT"]
        TXT_S["TXT Hygiene"]
        MXREP_S["MX Reputation"]
        SRV_S["SRV"]
        ZONE_S["Zone Hygiene"]
    end

    Core --> CALC["computeScanScore()"]
    Protective --> CALC
    Hardening --> CALC
    CALC --> GRADE["Grade: A+ to F"]

    style Core fill:#dc3545,color:#fff
    style Protective fill:#fd7e14,color:#fff
    style Hardening fill:#28a745,color:#fff
```

## Monorepo Structure

```mermaid
graph TB
    subgraph Root["Root — Cloudflare Worker"]
        INDEX["src/index.ts<br/>Hono HTTP entrypoint"]
        STDIO_E["src/stdio.ts<br/>CLI entrypoint"]
        PKG["src/package.ts<br/>npm package entrypoint"]
        SCHED["src/scheduled.ts<br/>Cron Trigger alerting"]
        INTL["src/internal.ts<br/>Service binding routes"]

        subgraph SrcMCP["src/mcp/"]
            EXEC_M["execute.ts"]
            DISP_M["dispatch.ts"]
            REQ_M["request.ts"]
            GATE_M["route-gates.ts"]
        end

        subgraph SrcHandlers["src/handlers/"]
            TOOLS_H["tools.ts"]
            RES_H["resources.ts"]
            PROMPT_H["prompts.ts"]
            SCHEMAS_H["tool-schemas.ts"]
            ARGS_H["tool-args.ts"]
            FMT_H["tool-formatters.ts"]
        end

        subgraph SrcTools["src/tools/"]
            SCAN_T["scan-domain.ts"]
            CHECK_T["check-*.ts (16+)"]
            ANALYSIS_T["*-analysis.ts"]
            INTEL_T["intelligence.ts"]
        end

        subgraph SrcLib["src/lib/"]
            DNS_L["dns.ts"]
            CACHE_L["cache.ts"]
            SCORE_L["scoring.ts"]
            SANIT_L["sanitize.ts"]
            RATE_L["rate-limiter.ts<br/>+ concurrency limits"]
            AUTH_L["auth.ts"]
            SESS_L["session.ts"]
            CB_L["circuit-breaker.ts"]
            SEM_L["semaphore.ts"]
            ANAL_L["analytics.ts"]
        end

        subgraph SrcSchemas["src/schemas/"]
            PRIM_S["primitives.ts"]
            TARGS_S["tool-args.ts"]
            TDEFS_S["tool-definitions.ts"]
            JSONRPC_S["json-rpc.ts"]
        end
    end

    subgraph Packages["packages/dns-checks/ — Runtime Agnostic"]
        SCORE_P["scoring/ — Generic engine"]
        CHECKS_P["checks/ — Core check impls"]
        SCHEMAS_P["schemas/ — Zod schemas"]
    end

    subgraph WASM["crates/bv-wasm-core/"]
        WASM_P["Rust WASM<br/>Permission checks + token estimation"]
    end

    SrcTools --> Packages
    INDEX --> WASM
```

## Security Layers

```mermaid
graph TB
    REQ["Inbound Request"] --> ORIGIN["Origin Validation<br/>(MCP spec-compliant)"]
    ORIGIN --> AUTH["Bearer Token Auth<br/>(constant-time XOR)"]
    AUTH --> TIER["Tier Resolution<br/>(KV cache → service binding → fallback)"]
    TIER --> RATE["Rate Limiting<br/>(per-IP + per-tier daily quotas<br/>+ per-tier concurrency limits)"]
    RATE --> SESS_V["Session Validation<br/>(64-char hex, KV + in-memory)"]
    SESS_V --> BODY_V["Body Validation<br/>(10 KB limit, Content-Type check)"]
    BODY_V --> JSONRPC["JSON-RPC Validation<br/>(Zod schema)"]
    JSONRPC --> TOOL_V["Tool Arg Validation<br/>(Zod per-tool schemas)"]
    TOOL_V --> DOMAIN_V["Domain Sanitization<br/>(SSRF + blocklist protection)"]
    DOMAIN_V --> EXEC_T["Tool Execution"]
    EXEC_T --> OUT_S["Output Sanitization<br/>(HTML/markdown strip, SVG escape)"]
    OUT_S --> ERR_S["Error Sanitization<br/>(safe-prefix allowlist only)"]
    ERR_S --> RESP["Response"]

    style REQ fill:#6c757d,color:#fff
    style RESP fill:#28a745,color:#fff
```
