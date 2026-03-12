# Adaptive Scoring Profiles — Design Spec

**Date:** 2026-03-12
**Status:** Approved
**Scope:** bv-mcp (Blackveil DNS MCP server)

---

## Summary

Evolve the static scoring profiles (`mail_enabled`, `enterprise_mail`, `non_mail`, `web_only`, `minimal`) into self-tuning profiles that adjust importance weights based on cross-scan finding distributions. The system accumulates telemetry from `scan_domain` results, computes adaptive weights via exponential moving averages, and blends them with static baselines proportional to data confidence.

### Goals

- Weights adapt to real-world failure patterns without manual tuning
- Two levels: per-profile global (L1) and per-profile+provider (L2)
- Active by default once data accumulates — confidence-based blending from static to adaptive
- Bounded weights with Analytics Engine alerts on persistent bound hits
- Plain-english scoring notes when adaptive weights meaningfully change a score
- No hard dependency on bv-web or any external project

### Non-Goals

- Real-time weight updates during a single scan
- Machine learning or external scoring services
- Breaking changes to existing MCP tool interfaces
- Requiring Durable Objects for basic functionality (graceful fallback to static weights)

---

## Architecture

### Storage: ProfileAccumulator Durable Object

A new `ProfileAccumulator` DO class with SQLite storage. Single global instance (routed by name `"global"`). Two RPC-style endpoints via `fetch`:

- **`POST /ingest`** — Receives scan telemetry, updates EMA rows. Fire-and-forget via `ctx.waitUntil()`.
- **`GET /weights?profile=X&provider=Y`** — Returns computed adaptive weights with blend factor applied. Optional `provider` param enables L2 overlay.

Category keys are `string` (not the narrow `CheckCategory` union) so the DO is scanner-agnostic. bv-mcp sends 13 categories; other consumers could send more without type conflicts.

**Binding (optional — absent = static weights):**

```jsonc
"durable_objects": {
  "bindings": [
    { "name": "QUOTA_COORDINATOR", "class_name": "QuotaCoordinator" },
    { "name": "PROFILE_ACCUMULATOR", "class_name": "ProfileAccumulator" }
  ]
},
"migrations": [
  { "tag": "v1", "new_sqlite_classes": ["QuotaCoordinator"] },
  { "tag": "v2", "new_sqlite_classes": ["ProfileAccumulator"] }
]
```

### SQLite Schema

**`profile_stats`** — L1 per-profile accumulation:

```sql
CREATE TABLE profile_stats (
  profile          TEXT NOT NULL,
  category         TEXT NOT NULL,
  sample_count     INTEGER DEFAULT 0,
  ema_failure_rate REAL DEFAULT 0.0,
  ema_avg_score    REAL DEFAULT 0.0,
  last_updated     INTEGER DEFAULT 0,
  PRIMARY KEY (profile, category)
);
```

**`provider_stats`** — L2 per-profile+provider:

```sql
CREATE TABLE provider_stats (
  profile          TEXT NOT NULL,
  provider         TEXT NOT NULL,
  category         TEXT NOT NULL,
  sample_count     INTEGER DEFAULT 0,
  ema_failure_rate REAL DEFAULT 0.0,
  ema_avg_score    REAL DEFAULT 0.0,
  last_updated     INTEGER DEFAULT 0,
  PRIMARY KEY (profile, provider, category)
);
```

No raw scan rows stored. EMA approach means bounded storage regardless of scan volume: 65 rows for L1 (5 profiles x 13 categories), plus provider variants for L2.

### Telemetry Payload

```typescript
interface ScanTelemetry {
  profile: string;
  provider: string | null;
  categoryFindings: {
    category: string;
    score: number;
    passed: boolean;
  }[];
  timestamp: number;
}
```

Sent after each `scan_domain` completes via `ctx.waitUntil()`. Minimal payload — no severity counts, just score and passed.

---

## Weight Computation

### EMA Update (on ingest)

```
alpha = 2 / (span + 1)     // span = 200
new_failure = passed ? 0.0 : 1.0
ema_failure_rate = alpha * new_failure + (1 - alpha) * ema_failure_rate
ema_avg_score = alpha * score + (1 - alpha) * ema_avg_score
sample_count += 1
```

One SQL transaction per ingest, batching all category rows.

### Adaptive Weight Adjustment

```
deviation = ema_failure_rate - baseline_failure_rate
raw_adjustment = deviation * sensitivity * static_weight
adaptive_weight = static_weight + raw_adjustment
clamped_weight = clamp(adaptive_weight, min_bound, max_bound)
```

- `baseline_failure_rate` — hardcoded per category from public internet measurement data
- `sensitivity` — 0.5 (single global constant)
- Adjustment is proportional to `static_weight`: high-importance categories respond more strongly

### Seed Baselines

Hardcoded in source, documented, open for community contribution:

```typescript
const BASELINE_FAILURE_RATES: Record<string, number> = {
  dmarc: 0.40,
  spf: 0.25,
  dkim: 0.35,
  ssl: 0.08,
  mta_sts: 0.85,
  dnssec: 0.80,
  mx: 0.05,
  caa: 0.70,
  ns: 0.03,
  bimi: 0.95,
  tlsrpt: 0.90,
  subdomain_takeover: 0.10,
  lookalikes: 0.00,
};
```

### Confidence-Based Blending

```
blend_factor = min(1.0, sample_count / 200)
effective_weight = (1 - blend_factor) * static_weight + blend_factor * clamped_weight
```

- At 0 samples: 100% static (identical to today)
- At 50 samples: 75% static, 25% adaptive
- At 200+ samples: fully adaptive
- Blend computed per profile (L1) and per profile+provider (L2) independently

### Provider Overlay (L2)

```
provider_modifier = (provider_ema_failure_rate - profile_ema_failure_rate) * 0.3 * static_weight
final_weight = clamp(effective_weight + provider_modifier, min_bound, max_bound)
```

Applied only when a provider is detected in MX findings and provider stats exist.

### Weight Bounds

Derived from static weights, defined as a constant map in source:

```typescript
function defaultBounds(staticWeight: number, isCriticalMail: boolean) {
  return {
    min: isCriticalMail ? Math.max(5, Math.floor(staticWeight * 0.5)) : Math.max(0, Math.floor(staticWeight * 0.5)),
    max: Math.ceil(staticWeight * 2) + 3,
  };
}
```

- Critical mail categories (DMARC, SPF, DKIM, SSL) have a floor of 5 for mail profiles
- Zero-weight categories bounded 0-3 (can gain slight weight, never dominant)

### Bound-Hit Detection

The DO returns `boundHits: string[]` — category names where clamping fired. Emitted to Analytics Engine via existing `emitToolEvent`. No pressure counters, no new event types. Persistent bound hits are spotted in the AE dashboard and trigger manual baseline revision.

### DO Response Shape

```typescript
interface AdaptiveWeightsResponse {
  profile: string;
  provider: string | null;
  sampleCount: number;
  blendFactor: number;
  weights: Record<string, number>;
  boundHits: string[];
}
```

---

## Integration with scan_domain

### Flow

```
1. Run all checks in parallel (unchanged)
2. detectDomainContext (unchanged)
3. Fetch adaptive weights:
   - env.PROFILE_ACCUMULATOR.get("global").fetch("/weights?profile=X&provider=Y")
   - 50ms timeout, fallback to static PROFILE_WEIGHTS
4. Replace DomainContext.weights with adaptive weights
5. computeScanScore (unchanged — already uses context.weights)
6. Compare score against static-weighted score → generate scoringNote if delta >= 3
7. ctx.waitUntil: POST telemetry to DO
```

### Fallback Chain

1. DO available + enough samples → adaptive weights (blended)
2. DO available + few samples → mostly static (blend factor near 0)
3. DO unavailable (timeout/error) → pure static weights
4. `PROFILE_ACCUMULATOR` binding absent → pure static weights

Step 4 ensures open source users deploying without Durable Objects get today's exact behavior. Zero regression.

### Phase 1 → Phase 2 Transition

Currently `auto` mode uses `mail_enabled` weights and only explicit profiles activate different weights. With this change, `auto` mode activates the detected profile's adaptive weights (blended). At 0 samples the blend factor is 0, so the transition is invisible — behavior changes gradually as data accumulates.

### Cache Key Impact

No change. Adaptive weights affect scoring computation, not cache keys. The same scan result is cached regardless of weight source. This is correct because the underlying check results (DNS queries) are identical — only the scoring interpretation changes, and that's recomputed on cache miss.

---

## Scoring Note (Plain English)

### When It Appears

Only when the adaptive-weighted score differs from the static-weighted score by 3+ points. Computed by running `computeScanScore` twice — once with adaptive weights, once with static.

### Templates

```typescript
const SCORING_NOTE_TEMPLATES = {
  weight_increased: '{category} carried more weight in this scan because it is a common issue across similar domains.',
  weight_increased_provider: '{category} carried more weight because domains using {provider} frequently have issues in this area.',
  weight_decreased: '{category} carried less weight because similar domains rarely have issues there.',
  multi_category: 'Several checks were weighted differently based on patterns seen across similar domains. The biggest shift was in {category}.',
};
```

Template selected based on: largest absolute weight delta from static, whether provider data was used, and whether multiple categories shifted significantly.

### Output

- **Text report** (first MCP content block): appended as a final line after maturity stage
- **Structured JSON** (second MCP content block): `scoringNote: string | null` plus `adaptiveWeightDeltas: Record<string, number>`

One sentence, rule-based, consistent with bv-web's `getPlainEnglishExplanation()` voice.

---

## Cross-Project Consistency

### Shared Conventions (not code)

- String-based category keys in the DO (accepts any scanner's categories)
- Same `ScanTelemetry` payload shape (simple enough to reimplement independently)
- Same baseline failure rates and weight formulas (documented in bv-mcp source)
- Same 5 profile names, same static base weights for overlapping checks

### No Hard Dependencies

- bv-mcp's `ProfileAccumulator` is self-contained — accumulates from its own scans
- bv-web is unaffected by this change and requires no modifications
- If bv-web later wants to feed telemetry into a `ProfileAccumulator`, it can deploy its own instance
- Operationally, a shared DO instance is possible but never required

### Open Source Considerations

- Algorithm is fully transparent and auditable in the repo
- Seed baselines are hardcoded from public internet measurement data
- Open source users get the same adaptive system, self-tuning from their traffic
- Production deployments with higher volume naturally get better-tuned weights (operational advantage, not code advantage)

---

## Files to Create/Modify

### New Files

- `src/lib/adaptive-weights.ts` — `BASELINE_FAILURE_RATES`, `WEIGHT_BOUNDS`, `computeAdaptiveWeight()`, `blendWeights()`, `ScanTelemetry` type, scoring note templates and generator
- `src/lib/profile-accumulator.ts` — `ProfileAccumulator` DO class (SQLite init, `/ingest`, `/weights` handlers, EMA logic)

### Modified Files

- `src/tools/scan-domain.ts` — fetch adaptive weights (step 3), generate scoring note (step 6), POST telemetry (step 7)
- `src/tools/scan/format-report.ts` — append scoring note to text report, add `scoringNote` and `adaptiveWeightDeltas` to structured result
- `src/lib/context-profiles.ts` — export `PROFILE_WEIGHTS` keys for bounds derivation (minor)
- `src/lib/analytics.ts` — emit bound-hit data via existing `emitToolEvent`
- `src/index.ts` — export `ProfileAccumulator` class for DO binding
- `wrangler.jsonc` — add `PROFILE_ACCUMULATOR` binding and `v2` migration
- `CLAUDE.md` — document adaptive scoring system

### Test Files

- `test/profile-accumulator.spec.ts` — DO ingest/weights endpoints, EMA math, blending, bounds
- `test/adaptive-weights.spec.ts` — weight computation, blending, bounds clamping, scoring note generation
- `test/scan-domain.spec.ts` — update existing tests for adaptive weight integration, fallback behavior
