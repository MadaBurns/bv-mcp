# ProfileAccumulator write-sharding (R10) — design + flip runbook

Status: **DORMANT — landed default-OFF. This document does NOT authorize flipping
the flag.** Flipping `PROFILE_ACCUMULATOR_SHARDING='profile'` in production is a
SEPARATE, separately-reviewed change (see "Phase 2 — flip" below).

## Problem

The `ProfileAccumulator` Durable Object is a second global singleton (alongside
`QuotaCoordinator`). Every scan's `waitUntil`'d `/ingest` POST routes to a single
DO instance named `global`, so all adaptive-weight write traffic serializes through
one DO input gate. This is off the response hot path (`waitUntil`), so DO overload
degrades adaptive-weight **freshness**, not request success — but at high scan
throughput the single gate caps write throughput and can stall trend/benchmark
convergence.

## Mechanism (loss-free by construction)

Shard key = **profile**. Every persisted table is PRIMARY-KEYed with `profile`
(`profile_stats`, `provider_stats`, `score_histogram`, `provider_cohort_summary`,
`trend_snapshots`) and every read endpoint (`/weights`, `/benchmark`,
`/provider-insights`, `/trends`) is parameterized by a single `profile`. There is
no cross-profile aggregation inside the DO, so partitioning by profile is loss-free:
a given profile's reads and writes both route to the same shard, and no shard ever
needs another shard's rows. With 6 fixed profiles this yields ~6× the write-gate
throughput with zero counter-reconciliation.

`resolveAccumulatorShardName(profile, mode)` is the single pure routing function.
`mode` comes from `resolveAccumulatorShardModeFromEnv(env.PROFILE_ACCUMULATOR_SHARDING)`:
default-OFF — only the exact string `'profile'` enables sharding; any other value
(including unset) returns `'global'` and the runtime is byte-for-byte identical to
the legacy single-instance topology.

### All seams co-route (no split-brain)

The mode is threaded into `ToolRuntimeOptions.profileAccumulatorShardMode` at every
construction site (`index.ts`, `internal.ts`, `tenants/routes.ts`,
`tenants/queue-consumer.ts`) and used at ALL of:

- `/ingest` write — `scan-domain.ts`
- `/weights` read — `scan-domain.ts` (`fetchAdaptiveWeights`)
- `/benchmark` + `/trends` read — `intelligence.ts` `getBenchmark` (the trends
  sub-fetch reuses the same shard stub)
- `/provider-insights` read — `intelligence.ts` `getProviderInsights`

So `get_benchmark` / `get_provider_insights` read the SAME shard the writes for
that profile landed in. Without this, flipping the flag would point reads at a
write-starved `global` instance and customer-facing benchmark/percentile data would
silently go blank.

### Profile-set consistency (latent bug fixed)

`SHARDABLE_PROFILES` (the routing set) and `VALID_PROFILES` (what the DO accepts at
`/ingest`) MUST stay consistent. `VALID_PROFILES` historically omitted
`authoritative_dns_infra` — a latent bug: an `authoritative_dns_infra` scan's
`/ingest` POST hit `VALID_PROFILES.has(...) === false` → 400 `Invalid profile`, and
because ingest is `waitUntil`'d and the telemetry promise swallows errors, the write
was dropped SILENTLY (on the `global` instance too, sharded or not). Fixed by adding
`authoritative_dns_infra` to `VALID_PROFILES`. `WEIGHT_BOUNDS` / `PROFILE_WEIGHTS`
already cover all 6 profiles. The relationship `VALID_PROFILES ⊇ SHARDABLE_PROFILES`
is now enforced by `test/profile-accumulator-sharding.spec.ts` so the two sets can't
drift again.

## Cold-start: the accepted data gap (must-fix #2)

On flip, every per-profile shard starts with `sampleCount = 0`. The legacy `global`
DO holds a fully-converged history that is **not** migrated.

**Chosen answer: accept the cold-start gap.** No dual-read and no backfill are
implemented. Rationale:

- The degradation is bounded and self-healing: adaptive weights fall back to the
  static per-profile weights (`blendFactor = sampleCount / MATURITY_THRESHOLD = 0`),
  and benchmarks report `insufficient_data` until each profile re-clears
  `MIN_BENCHMARK_SCANS = 100`. Scores stay correct (static weights are the
  conservative baseline); only the adaptive UPLIFT and the benchmark/percentile
  data product are temporarily degraded.
- It is **observable**: a `degradation` analytics event
  (`shard_below_benchmark_floor`, `component = profile_accumulator:<shard>`) is
  emitted on every scan whose shard is below the floor, so an operator can watch the
  warm-up drain per profile after a flip.
- Rollback is **instant and lossless**: set the var back to `'global'`. The dormant
  phase never depopulates `global`, so reads/writes return to the fully-converged
  legacy shard with no data loss.

Low-volume profiles (`minimal`, `authoritative_dns_infra`) may take days/weeks to
re-clear the floor. That window is acceptable ONLY because the maintainer has
explicitly accepted it here; if that ever changes, implement a one-time dual-read
(read shard, fall back to `global` until shard `sampleCount >= threshold`) or a
`global`→shard backfill pass before flipping.

## Phase 1 — land dormant (this branch)

Ship-flag-OFF. `PROFILE_ACCUMULATOR_SHARDING` unset → `global` everywhere → prod
runtime is byte-for-byte identical to `main`. Verified by the spec's "default-off
routes ingest AND all read seams to 'global'" block. No version bump strictly
required (no behavior change); if cutting a release, treat as a PATCH.

## Phase 2 — flip (SEPARATE, separately-reviewed change)

Only when there is an actual throughput reason (none today).

1. Set `PROFILE_ACCUMULATOR_SHARDING='profile'` at a low-traffic window.
2. Each of the 6 shards starts empty and re-accumulates; adaptive weights fall back
   to static per-profile until `MIN_BENCHMARK_SCANS = 100` /
   `MATURITY_THRESHOLD = 200` are re-crossed.
3. Watch the `shard_below_benchmark_floor` degradation signal drain to zero per
   shard.
4. Verify `get_benchmark` / `get_provider_insights` return data per profile (proves
   the read seams co-route).
5. Rollback = set the var back to `'global'` (reads/writes return to the populated
   legacy shard instantly; no data loss).
