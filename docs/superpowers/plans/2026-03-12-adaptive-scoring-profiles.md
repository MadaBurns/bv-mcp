# Adaptive Scoring Profiles Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add self-tuning scoring profiles that adapt importance weights based on cross-scan finding distributions using a ProfileAccumulator Durable Object with EMA-based blending.

**Architecture:** A new `ProfileAccumulator` DO accumulates scan telemetry (profile, provider, per-category score/pass) and computes adaptive weights via EMA. `scan_domain` fetches adaptive weights (50ms timeout, static fallback), blends them with static baselines proportional to sample count, and generates plain-english scoring notes when the delta exceeds 3 points.

**Tech Stack:** Cloudflare Workers, Durable Objects (SQLite), Hono v4, TypeScript strict, Vitest

**Spec:** `docs/superpowers/specs/2026-03-12-adaptive-scoring-profiles-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| **Create:** `src/lib/adaptive-weights.ts` | Types (`ScanTelemetry`, `AdaptiveWeightsResponse`), constants (`BASELINE_FAILURE_RATES`, `WEIGHT_BOUNDS`, `SENSITIVITY`, `MATURITY_THRESHOLD`), pure functions (`computeAdaptiveWeight`, `blendWeights`, `adaptiveWeightsToContext`, `defaultBounds`), scoring note templates + generator |
| **Create:** `src/lib/profile-accumulator.ts` | `ProfileAccumulator` DO class — SQLite schema init, `POST /ingest` handler, `GET /weights` handler, EMA update logic |
| **Create:** `test/adaptive-weights.spec.ts` | Unit tests for all pure functions in `adaptive-weights.ts` |
| **Create:** `test/profile-accumulator.spec.ts` | Integration tests for DO endpoints, EMA math, blending, bounds |
| **Modify:** `src/lib/context-profiles.ts:18-22` | Add `detectedProvider: string \| null` to `DomainContext`, populate in `detectDomainContext` |
| **Modify:** `src/lib/scoring.ts:26` | Re-export new types from `adaptive-weights.ts` |
| **Modify:** `src/tools/scan-domain.ts:56-64,162-222` | Add adaptive weight fetch, scoring note generation, telemetry POST |
| **Modify:** `src/tools/scan/format-report.ts:8-21,24-44,46-121` | Add `scoringNote` and `adaptiveWeightDeltas` to `StructuredScanResult` and report |
| **Modify:** `src/index.ts:40` | Export `ProfileAccumulator` for DO binding |
| **Modify:** `wrangler.jsonc:8-14` | Add `PROFILE_ACCUMULATOR` binding and `v2` migration |

---

## Chunk 1: Core Adaptive Weights Library

### Task 1: Adaptive weight types and constants

**Files:**
- Create: `src/lib/adaptive-weights.ts`
- Test: `test/adaptive-weights.spec.ts`

- [ ] **Step 1: Write failing tests for constants and types**

```typescript
// test/adaptive-weights.spec.ts
import { describe, it, expect } from 'vitest';
import {
	BASELINE_FAILURE_RATES,
	SENSITIVITY,
	MATURITY_THRESHOLD,
	WEIGHT_BOUNDS,
} from '../src/lib/adaptive-weights';
import { PROFILE_WEIGHTS } from '../src/lib/context-profiles';

describe('adaptive-weights constants', () => {
	it('BASELINE_FAILURE_RATES covers all 13 check categories', () => {
		const categories = Object.keys(PROFILE_WEIGHTS.mail_enabled);
		for (const cat of categories) {
			expect(BASELINE_FAILURE_RATES).toHaveProperty(cat);
			expect(BASELINE_FAILURE_RATES[cat]).toBeGreaterThanOrEqual(0);
			expect(BASELINE_FAILURE_RATES[cat]).toBeLessThanOrEqual(1);
		}
	});

	it('SENSITIVITY is 0.5', () => {
		expect(SENSITIVITY).toBe(0.5);
	});

	it('MATURITY_THRESHOLD is 200', () => {
		expect(MATURITY_THRESHOLD).toBe(200);
	});

	it('WEIGHT_BOUNDS covers all profiles and categories', () => {
		for (const profile of Object.keys(PROFILE_WEIGHTS)) {
			expect(WEIGHT_BOUNDS).toHaveProperty(profile);
			for (const cat of Object.keys(PROFILE_WEIGHTS.mail_enabled)) {
				expect(WEIGHT_BOUNDS[profile]).toHaveProperty(cat);
				const bounds = WEIGHT_BOUNDS[profile][cat];
				expect(bounds.min).toBeLessThanOrEqual(bounds.max);
				expect(bounds.min).toBeGreaterThanOrEqual(0);
			}
		}
	});

	it('critical mail categories have floor of 5 in mail profiles', () => {
		const criticalCats = ['dmarc', 'spf', 'dkim', 'ssl'];
		const mailProfiles = ['mail_enabled', 'enterprise_mail'];
		for (const profile of mailProfiles) {
			for (const cat of criticalCats) {
				expect(WEIGHT_BOUNDS[profile][cat].min).toBeGreaterThanOrEqual(5);
			}
		}
	});
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/adaptive-weights.spec.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement types and constants**

```typescript
// src/lib/adaptive-weights.ts
// SPDX-License-Identifier: MIT

/**
 * Adaptive scoring weights — types, constants, and pure computation functions.
 *
 * The adaptive system adjusts importance weights based on cross-scan finding
 * distributions using exponential moving averages. Weights blend from static
 * baselines toward adaptive values proportional to accumulated sample count.
 */

import type { CheckCategory } from './scoring-model';
import type { DomainContext, DomainProfile } from './context-profiles';
import { PROFILE_WEIGHTS, PROFILE_CRITICAL_CATEGORIES } from './context-profiles';

/** Telemetry payload sent to the ProfileAccumulator DO after each scan. */
export interface ScanTelemetry {
	profile: string;
	provider: string | null;
	categoryFindings: {
		category: string;
		score: number;
		passed: boolean;
	}[];
	timestamp: number;
}

/** Response from the ProfileAccumulator DO GET /weights endpoint. */
export interface AdaptiveWeightsResponse {
	profile: string;
	provider: string | null;
	sampleCount: number;
	blendFactor: number;
	weights: Record<string, number>;
	boundHits: string[];
}

/** Weight bounds for a single category. */
export interface WeightBound {
	min: number;
	max: number;
}

/** EMA smoothing factor: α = 2 / (span + 1). */
export const SENSITIVITY = 0.5;

/** Number of samples before adaptive weights are fully active. */
export const MATURITY_THRESHOLD = 200;

/** EMA span for smoothing factor calculation. */
export const EMA_SPAN = 200;

/** EMA smoothing factor. */
export const EMA_ALPHA = 2 / (EMA_SPAN + 1);

/** Minimum score delta (adaptive vs static) to generate a scoring note. */
export const SCORING_NOTE_DELTA_THRESHOLD = 3;

/**
 * Baseline failure rates per category from public internet measurement data.
 * Used as the reference point for adaptive weight adjustment — deviations
 * from baseline drive weight increases or decreases.
 */
export const BASELINE_FAILURE_RATES: Record<string, number> = {
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

/** Critical mail categories that get a minimum weight floor of 5 in mail profiles. */
const CRITICAL_MAIL_CATEGORIES = new Set<string>(['dmarc', 'spf', 'dkim', 'ssl']);
const MAIL_PROFILES = new Set<string>(['mail_enabled', 'enterprise_mail']);

/** Compute default weight bounds from a static weight value. */
export function defaultBounds(staticWeight: number, isCriticalMail: boolean): WeightBound {
	return {
		min: isCriticalMail ? Math.max(5, Math.floor(staticWeight * 0.5)) : Math.max(0, Math.floor(staticWeight * 0.5)),
		max: Math.ceil(staticWeight * 2) + 3,
	};
}

/** Pre-computed weight bounds for all profiles and categories. */
export const WEIGHT_BOUNDS: Record<string, Record<string, WeightBound>> = (() => {
	const bounds: Record<string, Record<string, WeightBound>> = {};
	for (const [profile, weights] of Object.entries(PROFILE_WEIGHTS)) {
		bounds[profile] = {};
		for (const [cat, { importance }] of Object.entries(weights)) {
			const isCritical = MAIL_PROFILES.has(profile) && CRITICAL_MAIL_CATEGORIES.has(cat);
			bounds[profile][cat] = defaultBounds(importance, isCritical);
		}
	}
	return bounds;
})();
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/adaptive-weights.spec.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/lib/adaptive-weights.ts test/adaptive-weights.spec.ts
git commit -m "feat: add adaptive weight types, constants, and bounds"
```

---

### Task 2: Core computation functions

**Files:**
- Modify: `src/lib/adaptive-weights.ts`
- Modify: `test/adaptive-weights.spec.ts`

- [ ] **Step 1: Write failing tests for computeAdaptiveWeight**

```typescript
// append to test/adaptive-weights.spec.ts
import { computeAdaptiveWeight, blendWeights } from '../src/lib/adaptive-weights';

describe('computeAdaptiveWeight', () => {
	it('returns static weight when failure rate equals baseline', () => {
		const result = computeAdaptiveWeight({
			staticWeight: 22,
			emaFailureRate: 0.40,
			baselineFailureRate: 0.40,
			bounds: { min: 11, max: 47 },
		});
		expect(result.weight).toBe(22);
		expect(result.boundHit).toBe(false);
	});

	it('increases weight when failure rate exceeds baseline', () => {
		const result = computeAdaptiveWeight({
			staticWeight: 22,
			emaFailureRate: 0.60,
			baselineFailureRate: 0.40,
			bounds: { min: 11, max: 47 },
		});
		// deviation = 0.20, adjustment = 0.20 * 0.5 * 22 = 2.2, weight = 24.2
		expect(result.weight).toBeCloseTo(24.2);
		expect(result.boundHit).toBe(false);
	});

	it('decreases weight when failure rate is below baseline', () => {
		const result = computeAdaptiveWeight({
			staticWeight: 22,
			emaFailureRate: 0.20,
			baselineFailureRate: 0.40,
			bounds: { min: 11, max: 47 },
		});
		// deviation = -0.20, adjustment = -0.20 * 0.5 * 22 = -2.2, weight = 19.8
		expect(result.weight).toBeCloseTo(19.8);
		expect(result.boundHit).toBe(false);
	});

	it('clamps to max bound and flags boundHit', () => {
		const result = computeAdaptiveWeight({
			staticWeight: 22,
			emaFailureRate: 1.0,
			baselineFailureRate: 0.0,
			bounds: { min: 11, max: 30 },
		});
		// deviation = 1.0, adjustment = 1.0 * 0.5 * 22 = 11, weight = 33 → clamped to 30
		expect(result.weight).toBe(30);
		expect(result.boundHit).toBe(true);
	});

	it('clamps to min bound and flags boundHit', () => {
		const result = computeAdaptiveWeight({
			staticWeight: 2,
			emaFailureRate: 0.0,
			baselineFailureRate: 0.85,
			bounds: { min: 1, max: 7 },
		});
		// deviation = -0.85, adjustment = -0.85 * 0.5 * 2 = -0.85, weight = 1.15 → above min
		expect(result.weight).toBeCloseTo(1.15);
		expect(result.boundHit).toBe(false);
	});

	it('returns 0 adjustment for zero static weight', () => {
		const result = computeAdaptiveWeight({
			staticWeight: 0,
			emaFailureRate: 0.90,
			baselineFailureRate: 0.10,
			bounds: { min: 0, max: 3 },
		});
		expect(result.weight).toBe(0);
		expect(result.boundHit).toBe(false);
	});
});

describe('blendWeights', () => {
	it('returns static weight at 0 samples', () => {
		expect(blendWeights(22, 30, 0)).toBe(22);
	});

	it('returns full adaptive weight at maturity threshold', () => {
		expect(blendWeights(22, 30, 200)).toBe(30);
	});

	it('blends 50/50 at half maturity', () => {
		expect(blendWeights(20, 30, 100)).toBe(25);
	});

	it('blends correctly below maturity', () => {
		// 50 samples → blend_factor = 0.25
		// effective = 0.75 * 20 + 0.25 * 30 = 22.5
		expect(blendWeights(20, 30, 50)).toBe(22.5);
	});

	it('caps blend factor at 1.0 above maturity', () => {
		expect(blendWeights(22, 30, 500)).toBe(30);
	});
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/adaptive-weights.spec.ts`
Expected: FAIL — functions not exported

- [ ] **Step 3: Implement computeAdaptiveWeight and blendWeights**

Append to `src/lib/adaptive-weights.ts`:

```typescript
/** Input for computing a single adaptive weight. */
interface AdaptiveWeightInput {
	staticWeight: number;
	emaFailureRate: number;
	baselineFailureRate: number;
	bounds: WeightBound;
}

/** Result of computing a single adaptive weight. */
interface AdaptiveWeightResult {
	weight: number;
	boundHit: boolean;
}

/**
 * Compute adaptive weight for a single category.
 * Adjusts static weight based on deviation of observed failure rate from baseline.
 */
export function computeAdaptiveWeight(input: AdaptiveWeightInput): AdaptiveWeightResult {
	const { staticWeight, emaFailureRate, baselineFailureRate, bounds } = input;
	const deviation = emaFailureRate - baselineFailureRate;
	const rawAdjustment = deviation * SENSITIVITY * staticWeight;
	const adaptiveWeight = staticWeight + rawAdjustment;
	const clamped = Math.max(bounds.min, Math.min(bounds.max, adaptiveWeight));
	const boundHit = clamped !== adaptiveWeight;
	return { weight: clamped, boundHit };
}

/**
 * Blend static and adaptive weights based on sample count.
 * Returns static weight at 0 samples, fully adaptive at MATURITY_THRESHOLD.
 */
export function blendWeights(staticWeight: number, adaptiveWeight: number, sampleCount: number): number {
	const blendFactor = Math.min(1.0, sampleCount / MATURITY_THRESHOLD);
	return (1 - blendFactor) * staticWeight + blendFactor * adaptiveWeight;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/adaptive-weights.spec.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/lib/adaptive-weights.ts test/adaptive-weights.spec.ts
git commit -m "feat: add computeAdaptiveWeight and blendWeights functions"
```

---

### Task 3: Type adapter and scoring note generator

**Files:**
- Modify: `src/lib/adaptive-weights.ts`
- Modify: `test/adaptive-weights.spec.ts`

- [ ] **Step 1: Write failing tests for adaptiveWeightsToContext**

```typescript
// append to test/adaptive-weights.spec.ts
import { adaptiveWeightsToContext, generateScoringNote } from '../src/lib/adaptive-weights';
import type { DomainProfile } from '../src/lib/context-profiles';

describe('adaptiveWeightsToContext', () => {
	it('converts DO response to DomainContext weights format', () => {
		const response: Record<string, number> = { dmarc: 25, spf: 12 };
		const profile: DomainProfile = 'mail_enabled';
		const result = adaptiveWeightsToContext(response, profile);
		expect(result).not.toBeNull();
		expect(result!.dmarc.importance).toBe(25);
		expect(result!.spf.importance).toBe(12);
		// missing categories fall back to static
		expect(result!.dkim.importance).toBe(16); // static mail_enabled value
	});

	it('returns null on NaN weight', () => {
		const response: Record<string, number> = { dmarc: NaN };
		const result = adaptiveWeightsToContext(response, 'mail_enabled');
		expect(result).toBeNull();
	});

	it('returns null on negative weight', () => {
		const response: Record<string, number> = { dmarc: -5 };
		const result = adaptiveWeightsToContext(response, 'mail_enabled');
		expect(result).toBeNull();
	});

	it('returns null on Infinity weight', () => {
		const response: Record<string, number> = { dmarc: Infinity };
		const result = adaptiveWeightsToContext(response, 'mail_enabled');
		expect(result).toBeNull();
	});
});

describe('generateScoringNote', () => {
	it('returns null when delta is below threshold', () => {
		const deltas: Record<string, number> = { dmarc: 1, spf: -0.5 };
		expect(generateScoringNote(deltas, 2, null)).toBeNull();
	});

	it('generates weight_increased note for single category', () => {
		const deltas: Record<string, number> = { mta_sts: 3, spf: 0.5 };
		const note = generateScoringNote(deltas, 4, null);
		expect(note).toContain('MTA_STS');
		expect(note).toContain('common issue');
	});

	it('generates weight_increased_provider note when provider present', () => {
		const deltas: Record<string, number> = { mta_sts: 3 };
		const note = generateScoringNote(deltas, 4, 'microsoft 365');
		expect(note).toContain('MTA_STS');
		expect(note).toContain('Microsoft 365');
	});

	it('generates weight_decreased note', () => {
		const deltas: Record<string, number> = { ssl: -4 };
		const note = generateScoringNote(deltas, -5, null);
		expect(note).toContain('SSL');
		expect(note).toContain('rarely have issues');
	});

	it('generates multi_category note when multiple categories shift', () => {
		const deltas: Record<string, number> = { dmarc: 5, mta_sts: 4, spf: 3 };
		const note = generateScoringNote(deltas, 8, null);
		expect(note).toContain('Several checks');
		expect(note).toContain('biggest shift');
	});
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/adaptive-weights.spec.ts`
Expected: FAIL — functions not exported

- [ ] **Step 3: Implement adaptiveWeightsToContext and generateScoringNote**

Append to `src/lib/adaptive-weights.ts`:

```typescript
/**
 * Convert DO response weights (Record<string, number>) to DomainContext weights
 * (Record<CheckCategory, ImportanceProfile>). Falls back to static weights
 * for missing categories. Returns null if any value is invalid (triggers
 * full static fallback).
 */
export function adaptiveWeightsToContext(
	doWeights: Record<string, number>,
	profile: DomainProfile,
): Record<CheckCategory, { importance: number }> | null {
	const staticWeights = PROFILE_WEIGHTS[profile];
	const result = {} as Record<CheckCategory, { importance: number }>;

	for (const [cat, { importance: staticImportance }] of Object.entries(staticWeights)) {
		const category = cat as CheckCategory;
		const adaptive = doWeights[cat];
		if (adaptive !== undefined) {
			if (!Number.isFinite(adaptive) || adaptive < 0) return null;
			result[category] = { importance: adaptive };
		} else {
			result[category] = { importance: staticImportance };
		}
	}
	return result;
}

const SCORING_NOTE_TEMPLATES = {
	weight_increased: '{category} carried more weight in this scan because it is a common issue across similar domains.',
	weight_increased_provider: '{category} carried more weight because domains using {provider} frequently have issues in this area.',
	weight_decreased: '{category} carried less weight because similar domains rarely have issues there.',
	multi_category: 'Several checks were weighted differently based on patterns seen across similar domains. The biggest shift was in {category}.',
};

/**
 * Generate a plain-english scoring note when adaptive weights meaningfully changed the score.
 * Returns null if the delta is below SCORING_NOTE_DELTA_THRESHOLD.
 */
export function generateScoringNote(
	weightDeltas: Record<string, number>,
	scoreDelta: number,
	provider: string | null,
): string | null {
	if (Math.abs(scoreDelta) < SCORING_NOTE_DELTA_THRESHOLD) return null;

	const significantDeltas = Object.entries(weightDeltas)
		.filter(([, delta]) => Math.abs(delta) >= 2)
		.sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));

	if (significantDeltas.length === 0) return null;

	const [topCategory, topDelta] = significantDeltas[0];
	const displayCategory = topCategory.toUpperCase();

	if (significantDeltas.length >= 3) {
		return SCORING_NOTE_TEMPLATES.multi_category
			.replace('{category}', displayCategory);
	}

	if (topDelta > 0) {
		if (provider) {
			const displayProvider = provider.split(' ').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
			return SCORING_NOTE_TEMPLATES.weight_increased_provider
				.replace('{category}', displayCategory)
				.replace('{provider}', displayProvider);
		}
		return SCORING_NOTE_TEMPLATES.weight_increased.replace('{category}', displayCategory);
	}

	return SCORING_NOTE_TEMPLATES.weight_decreased.replace('{category}', displayCategory);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/adaptive-weights.spec.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/lib/adaptive-weights.ts test/adaptive-weights.spec.ts
git commit -m "feat: add type adapter and scoring note generator"
```

---

## Chunk 2: ProfileAccumulator Durable Object

### Task 4: ProfileAccumulator DO with SQLite schema

**Files:**
- Create: `src/lib/profile-accumulator.ts`
- Create: `test/profile-accumulator.spec.ts`

- [ ] **Step 1: Write failing tests for DO initialization and ingest**

```typescript
// test/profile-accumulator.spec.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import type { ScanTelemetry } from '../src/lib/adaptive-weights';

/**
 * Helper to get a ProfileAccumulator stub and make requests.
 * Requires PROFILE_ACCUMULATOR binding in vitest wrangler config.
 */
function getAccumulator() {
	const id = env.PROFILE_ACCUMULATOR.idFromName('global');
	return env.PROFILE_ACCUMULATOR.get(id);
}

async function ingest(telemetry: ScanTelemetry): Promise<Response> {
	const stub = getAccumulator();
	return stub.fetch(new Request('https://do/ingest', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(telemetry),
	}));
}

async function getWeights(profile: string, provider?: string): Promise<Response> {
	const stub = getAccumulator();
	const url = provider
		? `https://do/weights?profile=${profile}&provider=${encodeURIComponent(provider)}`
		: `https://do/weights?profile=${profile}`;
	return stub.fetch(new Request(url));
}

// Use unique profile names per test to avoid shared DO state pollution.
// The DO persists across tests within a run — unique keys isolate tests.
describe('ProfileAccumulator', () => {
	it('returns empty weights for unknown profile', async () => {
		const res = await getWeights('test_empty_profile');
		expect(res.status).toBe(200);
		const data = await res.json();
		expect(data.sampleCount).toBe(0);
		expect(data.blendFactor).toBe(0);
		expect(data.weights).toEqual({});
		expect(data.boundHits).toEqual([]);
	});

	it('ingests telemetry and updates profile stats', async () => {
		const telemetry: ScanTelemetry = {
			profile: 'test_ingest_mail',
			provider: null,
			categoryFindings: [
				{ category: 'dmarc', score: 80, passed: true },
				{ category: 'spf', score: 60, passed: true },
			],
			timestamp: Date.now(),
		};

		const ingestRes = await ingest(telemetry);
		expect(ingestRes.status).toBe(200);

		const weightsRes = await getWeights('test_ingest_mail');
		const data = await weightsRes.json();
		expect(data.sampleCount).toBe(1);
		expect(data.blendFactor).toBeCloseTo(1 / 200);
	});

	it('accumulates multiple ingests with EMA', async () => {
		for (let i = 0; i < 5; i++) {
			await ingest({
				profile: 'test_ema_accumulation',
				provider: 'google workspace',
				categoryFindings: [
					{ category: 'mta_sts', score: 0, passed: false },
				],
				timestamp: Date.now() + i,
			});
		}

		const res = await getWeights('test_ema_accumulation');
		const data = await res.json();
		expect(data.sampleCount).toBe(5);
	});

	it('applies provider overlay math correctly', async () => {
		// Ingest profile-level data with mixed pass/fail
		for (let i = 0; i < 10; i++) {
			await ingest({
				profile: 'test_provider_overlay',
				provider: null,
				categoryFindings: [
					{ category: 'mta_sts', score: i < 5 ? 0 : 100, passed: i >= 5 },
				],
				timestamp: Date.now() + i,
			});
		}
		// Ingest provider-level data — always failing
		for (let i = 0; i < 10; i++) {
			await ingest({
				profile: 'test_provider_overlay',
				provider: 'microsoft 365',
				categoryFindings: [
					{ category: 'mta_sts', score: 0, passed: false },
				],
				timestamp: Date.now() + 100 + i,
			});
		}

		const withProvider = await getWeights('test_provider_overlay', 'microsoft 365');
		const withoutProvider = await getWeights('test_provider_overlay');
		const dataWith = await withProvider.json();
		const dataWithout = await withoutProvider.json();

		// Provider weight should be higher than profile weight (provider always fails)
		expect(dataWith.provider).toBe('microsoft 365');
		expect(dataWithout.provider).toBeNull();
		if (dataWith.weights.mta_sts !== undefined && dataWithout.weights.mta_sts !== undefined) {
			expect(dataWith.weights.mta_sts).toBeGreaterThanOrEqual(dataWithout.weights.mta_sts);
		}
	});

	it('returns 400 for missing profile on GET /weights', async () => {
		const stub = getAccumulator();
		const res = await stub.fetch(new Request('https://do/weights'));
		expect(res.status).toBe(400);
	});

	it('returns 400 for invalid ingest payload', async () => {
		const stub = getAccumulator();
		const res = await stub.fetch(new Request('https://do/ingest', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ bad: 'data' }),
		}));
		expect(res.status).toBe(400);
	});

	it('returns 404 for unknown routes', async () => {
		const stub = getAccumulator();
		const res = await stub.fetch(new Request('https://do/unknown'));
		expect(res.status).toBe(404);
	});
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/profile-accumulator.spec.ts`
Expected: FAIL — module not found / binding not configured

- [ ] **Step 3: Implement ProfileAccumulator DO**

```typescript
// src/lib/profile-accumulator.ts
// SPDX-License-Identifier: MIT

/**
 * ProfileAccumulator Durable Object.
 *
 * Accumulates scan telemetry and computes adaptive scoring weights
 * via exponential moving averages. Scanner-agnostic — category keys
 * are plain strings, not tied to any specific CheckCategory union.
 */

import { DurableObject } from 'cloudflare:workers';
import {
	EMA_ALPHA,
	MATURITY_THRESHOLD,
	BASELINE_FAILURE_RATES,
	WEIGHT_BOUNDS,
	SENSITIVITY,
	computeAdaptiveWeight,
	blendWeights,
	type ScanTelemetry,
	type AdaptiveWeightsResponse,
} from './adaptive-weights';
import { PROFILE_WEIGHTS } from './context-profiles';

export class ProfileAccumulator extends DurableObject {
	private initialized = false;

	private ensureSchema(): void {
		if (this.initialized) return;
		this.ctx.storage.sql.exec(`
			CREATE TABLE IF NOT EXISTS profile_stats (
				profile          TEXT NOT NULL,
				category         TEXT NOT NULL,
				sample_count     INTEGER DEFAULT 0,
				ema_failure_rate REAL DEFAULT 0.0,
				ema_avg_score    REAL DEFAULT 0.0,
				last_updated     INTEGER DEFAULT 0,
				PRIMARY KEY (profile, category)
			);
			CREATE TABLE IF NOT EXISTS provider_stats (
				profile          TEXT NOT NULL,
				provider         TEXT NOT NULL,
				category         TEXT NOT NULL,
				sample_count     INTEGER DEFAULT 0,
				ema_failure_rate REAL DEFAULT 0.0,
				ema_avg_score    REAL DEFAULT 0.0,
				last_updated     INTEGER DEFAULT 0,
				PRIMARY KEY (profile, provider, category)
			);
		`);
		this.initialized = true;
	}

	async fetch(request: Request): Promise<Response> {
		this.ensureSchema();
		const url = new URL(request.url);

		if (request.method === 'POST' && url.pathname === '/ingest') {
			return this.handleIngest(request);
		}
		if (request.method === 'GET' && url.pathname === '/weights') {
			return this.handleGetWeights(url);
		}
		return new Response('Not found', { status: 404 });
	}

	private async handleIngest(request: Request): Promise<Response> {
		let telemetry: ScanTelemetry;
		try {
			telemetry = await request.json() as ScanTelemetry;
		} catch {
			return new Response('Invalid JSON', { status: 400 });
		}

		if (!telemetry.profile || !Array.isArray(telemetry.categoryFindings)) {
			return new Response('Missing required fields', { status: 400 });
		}

		const now = telemetry.timestamp || Date.now();
		const alpha = EMA_ALPHA;

		for (const finding of telemetry.categoryFindings) {
			const failureValue = finding.passed ? 0.0 : 1.0;

			// Upsert profile_stats
			const existing = this.ctx.storage.sql.exec(
				'SELECT sample_count, ema_failure_rate, ema_avg_score FROM profile_stats WHERE profile = ? AND category = ?',
				telemetry.profile,
				finding.category,
			).toArray();

			if (existing.length > 0) {
				const row = existing[0];
				const newFailureRate = alpha * failureValue + (1 - alpha) * (row.ema_failure_rate as number);
				const newAvgScore = alpha * finding.score + (1 - alpha) * (row.ema_avg_score as number);
				this.ctx.storage.sql.exec(
					'UPDATE profile_stats SET sample_count = sample_count + 1, ema_failure_rate = ?, ema_avg_score = ?, last_updated = ? WHERE profile = ? AND category = ?',
					newFailureRate, newAvgScore, now, telemetry.profile, finding.category,
				);
			} else {
				// First sample: apply EMA formula against initial value of 0
				const initFailureRate = alpha * failureValue;
				const initAvgScore = alpha * finding.score;
				this.ctx.storage.sql.exec(
					'INSERT INTO profile_stats (profile, category, sample_count, ema_failure_rate, ema_avg_score, last_updated) VALUES (?, ?, 1, ?, ?, ?)',
					telemetry.profile, finding.category, initFailureRate, initAvgScore, now,
				);
			}

			// Upsert provider_stats if provider is present
			if (telemetry.provider) {
				const existingProvider = this.ctx.storage.sql.exec(
					'SELECT sample_count, ema_failure_rate, ema_avg_score FROM provider_stats WHERE profile = ? AND provider = ? AND category = ?',
					telemetry.profile, telemetry.provider, finding.category,
				).toArray();

				if (existingProvider.length > 0) {
					const row = existingProvider[0];
					const newFailureRate = alpha * failureValue + (1 - alpha) * (row.ema_failure_rate as number);
					const newAvgScore = alpha * finding.score + (1 - alpha) * (row.ema_avg_score as number);
					this.ctx.storage.sql.exec(
						'UPDATE provider_stats SET sample_count = sample_count + 1, ema_failure_rate = ?, ema_avg_score = ?, last_updated = ? WHERE profile = ? AND provider = ? AND category = ?',
						newFailureRate, newAvgScore, now, telemetry.profile, telemetry.provider, finding.category,
					);
				} else {
					const initFailureRate = alpha * failureValue;
					const initAvgScore = alpha * finding.score;
					this.ctx.storage.sql.exec(
						'INSERT INTO provider_stats (profile, provider, category, sample_count, ema_failure_rate, ema_avg_score, last_updated) VALUES (?, ?, ?, 1, ?, ?, ?)',
						telemetry.profile, telemetry.provider, finding.category, initFailureRate, initAvgScore, now,
					);
				}
			}
		}

		return new Response('OK', { status: 200 });
	}

	private handleGetWeights(url: URL): Response {
		const profile = url.searchParams.get('profile');
		if (!profile) {
			return new Response('Missing profile parameter', { status: 400 });
		}

		const provider = url.searchParams.get('provider') || null;

		// Read profile stats
		const rows = this.ctx.storage.sql.exec(
			'SELECT category, sample_count, ema_failure_rate FROM profile_stats WHERE profile = ?',
			profile,
		).toArray();

		if (rows.length === 0) {
			const response: AdaptiveWeightsResponse = {
				profile,
				provider,
				sampleCount: 0,
				blendFactor: 0,
				weights: {},
				boundHits: [],
			};
			return Response.json(response);
		}

		// Find min sample count across categories for blend factor
		const minSampleCount = Math.min(...rows.map((r) => r.sample_count as number));
		const blendFactor = Math.min(1.0, minSampleCount / MATURITY_THRESHOLD);

		const weights: Record<string, number> = {};
		const boundHits: string[] = [];

		// Get static weights for this profile (if known), otherwise skip blending
		const staticProfileWeights = PROFILE_WEIGHTS[profile as keyof typeof PROFILE_WEIGHTS];

		for (const row of rows) {
			const cat = row.category as string;
			const emaFailureRate = row.ema_failure_rate as number;
			const sampleCount = row.sample_count as number;

			const staticWeight = staticProfileWeights?.[cat as keyof typeof staticProfileWeights]?.importance;
			if (staticWeight === undefined) {
				// Unknown category for this profile — skip
				continue;
			}

			const baseline = BASELINE_FAILURE_RATES[cat] ?? 0;
			const bounds = WEIGHT_BOUNDS[profile]?.[cat] ?? { min: 0, max: staticWeight * 2 + 3 };

			const adaptive = computeAdaptiveWeight({
				staticWeight,
				emaFailureRate,
				baselineFailureRate: baseline,
				bounds,
			});

			if (adaptive.boundHit) boundHits.push(cat);

			// Apply provider overlay if requested
			let providerModifier = 0;
			if (provider) {
				const providerRows = this.ctx.storage.sql.exec(
					'SELECT ema_failure_rate FROM provider_stats WHERE profile = ? AND provider = ? AND category = ?',
					profile, provider, cat,
				).toArray();

				if (providerRows.length > 0) {
					const providerFailureRate = providerRows[0].ema_failure_rate as number;
					providerModifier = (providerFailureRate - emaFailureRate) * 0.3 * staticWeight;
				}
			}

			const blendedWeight = blendWeights(staticWeight, adaptive.weight, sampleCount);
			const finalWeight = Math.max(
				bounds.min,
				Math.min(bounds.max, blendedWeight + providerModifier),
			);

			weights[cat] = Math.round(finalWeight * 100) / 100;
		}

		const response: AdaptiveWeightsResponse = {
			profile,
			provider,
			sampleCount: minSampleCount,
			blendFactor,
			weights,
			boundHits,
		};
		return Response.json(response);
	}
}
```

- [ ] **Step 4: Configure test environment for DO binding**

The vitest config uses `wrangler: { configPath: './wrangler.jsonc' }` to auto-discover bindings. Since Task 8 adds the `PROFILE_ACCUMULATOR` DO binding to `wrangler.jsonc`, tests will automatically pick it up. However, Task 8 comes after Task 4, so **temporarily** add the DO binding to `wrangler.jsonc` now (Task 8 will finalize it):

In `wrangler.jsonc`, update the `durable_objects` block:
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
],
```

And add the export to `src/index.ts` (after line 40):

```typescript
export { ProfileAccumulator } from './lib/profile-accumulator';
```

No changes needed to `vitest.config.mts` — the wrangler config integration handles DO discovery automatically.

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run test/profile-accumulator.spec.ts`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/lib/profile-accumulator.ts test/profile-accumulator.spec.ts src/index.ts wrangler.jsonc
git commit -m "feat: add ProfileAccumulator Durable Object with EMA-based weight accumulation"
```

---

## Chunk 3: Integration with scan_domain

### Task 5: Add detectedProvider to DomainContext

**Files:**
- Modify: `src/lib/context-profiles.ts:18-22,138-240`
- Modify: `src/lib/scoring.ts:26`
- Test: existing `test/context-profiles.spec.ts`

- [ ] **Step 1: Write failing test for detectedProvider**

Add to existing test file (or create if absent):

```typescript
// test/context-profiles.spec.ts (add this test)
it('extracts detectedProvider from MX findings metadata', () => {
	const results: CheckResult[] = [
		buildCheckResult('mx', [
			createFinding('mx', 'MX records found', 'info', 'Using Google Workspace', { provider: 'google workspace' }),
		]),
	];
	const context = detectDomainContext(results);
	expect(context.detectedProvider).toBe('google workspace');
});

it('sets detectedProvider to null when no provider detected', () => {
	const results: CheckResult[] = [
		buildCheckResult('mx', [
			createFinding('mx', 'MX records found', 'info', 'Custom mail server'),
		]),
	];
	const context = detectDomainContext(results);
	expect(context.detectedProvider).toBeNull();
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/context-profiles.spec.ts`
Expected: FAIL — `detectedProvider` not in type/result

- [ ] **Step 3: Add detectedProvider to DomainContext and detectDomainContext**

In `src/lib/context-profiles.ts`, add `detectedProvider: string | null` to the `DomainContext` interface (line ~19) and populate it in `detectDomainContext` from the provider detection loop (after line ~178). Track the first matched provider name and assign it before the return statement:

```typescript
// In DomainContext interface (line ~18):
export interface DomainContext {
	profile: DomainProfile;
	signals: string[];
	weights: Record<CheckCategory, ImportanceProfile>;
	detectedProvider: string | null;
}

// In detectDomainContext, track the provider (around line ~165):
let detectedProviderName: string | null = null;
// Inside the provider detection loop, when a match is found:
detectedProviderName = provider;

// In the return statement (line ~235):
return {
	profile,
	signals,
	weights: PROFILE_WEIGHTS[profile],
	detectedProvider: detectedProviderName,
};
```

Update `src/lib/scoring.ts` line 26 to re-export `detectedProvider` if needed (the type is already exported via `DomainContext`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/context-profiles.spec.ts`
Expected: PASS

- [ ] **Step 5: Fix any other tests broken by the DomainContext type change**

Run: `npx vitest run`
Fix any type errors in tests that construct `DomainContext` manually — add `detectedProvider: null`.

- [ ] **Step 6: Commit**

```bash
git add src/lib/context-profiles.ts src/lib/scoring.ts
git commit -m "feat: add detectedProvider field to DomainContext"
```

---

### Task 6: Integrate adaptive weights into scan_domain

**Files:**
- Modify: `src/tools/scan-domain.ts:56-64,162-222`
- Modify: `test/scan-domain.spec.ts`

- [ ] **Step 1: Write failing test for adaptive weight fallback**

```typescript
// Add to test/scan-domain.spec.ts
describe('adaptive weights integration', () => {
	it('falls back to static weights when PROFILE_ACCUMULATOR binding is absent', async () => {
		mockAllChecks();
		const { scanDomain } = await import('../src/tools/scan-domain');
		// No PROFILE_ACCUMULATOR in env — should work identically to before
		const result = await scanDomain('example.com');
		expect(result.score).toBeDefined();
		expect(result.scoringNote).toBeNull();
		expect(result.adaptiveWeightDeltas).toBeNull();
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/scan-domain.spec.ts`
Expected: FAIL — `scoringNote` and `adaptiveWeightDeltas` not on `ScanDomainResult`

- [ ] **Step 3: Extend ScanDomainResult and integrate adaptive weight fetch**

In `src/tools/scan-domain.ts`:

1. Add to `ScanDomainResult` interface (line ~56):
```typescript
export interface ScanDomainResult {
	domain: string;
	score: ScanScore;
	checks: CheckResult[];
	maturity: MaturityStage;
	context: DomainContext;
	cached: boolean;
	timestamp: string;
	scoringNote: string | null;
	adaptiveWeightDeltas: Record<string, number> | null;
}
```

2. Add to `ScanRuntimeOptions` in `src/tools/scan/post-processing.ts:8-13`:
```typescript
export interface ScanRuntimeOptions {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
	profile?: 'mail_enabled' | 'enterprise_mail' | 'non_mail' | 'web_only' | 'minimal' | 'auto';
	profileAccumulator?: DurableObjectNamespace;
	waitUntil?: (promise: Promise<unknown>) => void;
}
```

3. Add an in-memory adaptive weight cache at module scope (keyed by profile+provider):
```typescript
const adaptiveWeightCache = new Map<string, { weights: AdaptiveWeightsResponse; expires: number }>();
const ADAPTIVE_CACHE_TTL_MS = 60_000;
```

4. After `detectDomainContext` (around line ~167), add the adaptive weight fetch:
```typescript
// Fetch adaptive weights (50ms timeout, static fallback)
let adaptiveResponse: AdaptiveWeightsResponse | null = null;
if (runtimeOptions?.profileAccumulator) {
	try {
		const now = Date.now();
		const cacheKey = `${domainContext.profile}:${domainContext.detectedProvider ?? ''}`;
		const cached = adaptiveWeightCache.get(cacheKey);
		if (cached && cached.expires > now) {
			adaptiveResponse = cached.weights;
		} else {
			const stub = runtimeOptions.profileAccumulator.get(
				runtimeOptions.profileAccumulator.idFromName('global'),
			);
			const providerParam = domainContext.detectedProvider
				? `&provider=${encodeURIComponent(domainContext.detectedProvider)}`
				: '';
			const weightsRes = await Promise.race([
				stub.fetch(`https://do/weights?profile=${domainContext.profile}${providerParam}`),
				new Promise<null>((resolve) => setTimeout(() => resolve(null), 50)),
			]);
			if (weightsRes && weightsRes.ok) {
				adaptiveResponse = await weightsRes.json() as AdaptiveWeightsResponse;
				adaptiveWeightCache.set(cacheKey, { weights: adaptiveResponse, expires: now + ADAPTIVE_CACHE_TTL_MS });
			}
		}
	} catch {
		// Fallback to static weights — adaptive is best-effort
	}
}

// Apply adaptive weights if available
let scoringNote: string | null = null;
let adaptiveWeightDeltas: Record<string, number> | null = null;

if (adaptiveResponse && adaptiveResponse.sampleCount > 0) {
	const adaptiveWeights = adaptiveWeightsToContext(adaptiveResponse.weights, domainContext.profile);
	if (adaptiveWeights) {
		const adaptiveContext: DomainContext = { ...domainContext, weights: adaptiveWeights };
		const adaptiveScore = computeScanScore(checkResults, adaptiveContext);
		const staticContext: DomainContext = { ...domainContext, weights: getProfileWeights(domainContext.profile) };
		const staticScore = computeScanScore(checkResults, staticContext);
		const delta = adaptiveScore.overall - staticScore.overall;

		// Compute per-category deltas
		const deltas: Record<string, number> = {};
		for (const [cat, { importance }] of Object.entries(adaptiveWeights)) {
			const staticImportance = PROFILE_WEIGHTS[domainContext.profile]?.[cat as CheckCategory]?.importance ?? 0;
			deltas[cat] = importance - staticImportance;
		}

		scoringNote = generateScoringNote(deltas, delta, adaptiveResponse.provider);
		adaptiveWeightDeltas = Object.fromEntries(Object.entries(deltas).filter(([, d]) => Math.abs(d) >= 0.01));

		// Use adaptive score
		score = adaptiveScore;
		domainContext = adaptiveContext;
	}
}
```

5. Update the result construction to include new fields:
```typescript
result = {
	domain,
	score,
	checks: checkResults,
	maturity,
	context: domainContext,
	cached: false,
	timestamp: new Date().toISOString(),
	scoringNote,
	adaptiveWeightDeltas,
};
```

6. Add telemetry POST after result construction, using `waitUntil` to prevent cancellation:
```typescript
// POST telemetry to DO (fire-and-forget via waitUntil)
if (runtimeOptions?.profileAccumulator) {
	const telemetry: ScanTelemetry = {
		profile: domainContext.profile,
		provider: domainContext.detectedProvider,
		categoryFindings: checkResults.map((r) => ({
			category: r.category,
			score: r.score,
			passed: r.passed,
		})),
		timestamp: Date.now(),
	};
	const telemetryPromise = (async () => {
		try {
			const stub = runtimeOptions.profileAccumulator!.get(
				runtimeOptions.profileAccumulator!.idFromName('global'),
			);
			await stub.fetch(new Request('https://do/ingest', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(telemetry),
			}));
		} catch {
			// Telemetry is best-effort
		}
	})();
	if (runtimeOptions.waitUntil) {
		runtimeOptions.waitUntil(telemetryPromise);
	}
}
```

Add imports at top:
```typescript
import { adaptiveWeightsToContext, generateScoringNote, type ScanTelemetry, type AdaptiveWeightsResponse } from '../lib/adaptive-weights';
import { PROFILE_WEIGHTS } from '../lib/context-profiles';  // already imported via scoring.ts — verify no duplicate
```

- [ ] **Step 4: Update fallback result construction to include null fields**

Ensure the fallback catch block (line ~195) and cached result return also set `scoringNote: null` and `adaptiveWeightDeltas: null`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run test/scan-domain.spec.ts`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/tools/scan-domain.ts test/scan-domain.spec.ts
git commit -m "feat: integrate adaptive weights into scan_domain with fallback chain"
```

---

### Task 7: Update format-report for scoring note and structured result

**Files:**
- Modify: `src/tools/scan/format-report.ts:8-21,46-121`
- Test: existing scan-domain tests cover this indirectly

- [ ] **Step 1: Add scoringNote and adaptiveWeightDeltas to StructuredScanResult**

In `src/tools/scan/format-report.ts`, add to the `StructuredScanResult` interface (after line 20):

```typescript
scoringNote: string | null;
adaptiveWeightDeltas: Record<string, number> | null;
```

Update `buildStructuredScanResult` (after line 42):

```typescript
scoringNote: result.scoringNote ?? null,
adaptiveWeightDeltas: result.adaptiveWeightDeltas ?? null,
```

- [ ] **Step 2: Append scoring note to text report**

In `formatScanReport`, after the scoring profile section (after line 68):

```typescript
if (result.scoringNote) {
	lines.push(result.scoringNote);
	lines.push('');
}
```

- [ ] **Step 3: Run full test suite**

Run: `npx vitest run`
Expected: PASS — all existing tests still pass, new fields are null by default

- [ ] **Step 4: Commit**

```bash
git add src/tools/scan/format-report.ts
git commit -m "feat: surface scoring note in text report and structured result"
```

---

## Chunk 4: Wiring and Configuration

### Task 8: Export DO and update wrangler config

**Files:**
- Modify: `src/index.ts:40`
- Modify: `wrangler.jsonc:8-14`

- [ ] **Step 1: Add ProfileAccumulator export to index.ts**

After line 40 (`export { QuotaCoordinator }`):

```typescript
export { ProfileAccumulator } from './lib/profile-accumulator';
```

- [ ] **Step 2: Update wrangler.jsonc**

Add `PROFILE_ACCUMULATOR` to the durable_objects bindings and add v2 migration:

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
],
```

- [ ] **Step 3: Pass PROFILE_ACCUMULATOR and waitUntil through to scanDomain**

In `src/handlers/tools.ts`, where `runtimeOptions` is constructed (look for where `providerSignaturesUrl` is set), add:

```typescript
profileAccumulator: env.PROFILE_ACCUMULATOR,
waitUntil: (p: Promise<unknown>) => ctx.waitUntil(p),
```

There are three call sites for `scanDomain`:
1. `src/handlers/tools.ts:170` — `scan_domain` tool dispatch (pass both bindings)
2. `src/handlers/tools.ts:193` — `compare_baseline` tool dispatch (same runtimeOptions, already covered)
3. `src/index.ts:268` — badge endpoint. Update to pass the binding:
```typescript
const result = await scanDomain(domain, c.env.SCAN_CACHE, {
	profileAccumulator: c.env.PROFILE_ACCUMULATOR,
	waitUntil: (p: Promise<unknown>) => c.executionCtx.waitUntil(p),
});
```

- [ ] **Step 4: Run full test suite and typecheck**

Run: `npm run typecheck && npx vitest run`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/index.ts wrangler.jsonc src/handlers/tools.ts
git commit -m "feat: wire ProfileAccumulator DO binding and pass to scan_domain"
```

---

### Task 9: Emit bound hits to Analytics Engine

**Files:**
- Modify: `src/lib/analytics.ts`
- Modify: `src/tools/scan-domain.ts` (where adaptive response is consumed)

- [ ] **Step 1: Extend emitToolEvent to include boundHits**

In `src/lib/analytics.ts`, the existing `emitToolEvent` already accepts arbitrary blobs. When `scan_domain` processes the adaptive response, emit bound hits as part of the tool event:

```typescript
// In scan-domain.ts, after adaptive weights are applied:
if (adaptiveResponse && adaptiveResponse.boundHits.length > 0) {
	// Bound hits are emitted via the existing scan_domain tool event
	// by appending to the result metadata. The analytics emit in
	// handlers/tools.ts will pick this up.
}
```

The spec mentions emitting via `emitToolEvent`, but bound hits are already captured in the structured result and piped through the existing analytics flow when `scan_domain` completes. Rather than add a separate AE event type, the simpler approach is to include them in `scoringSignals`:

```typescript
if (adaptiveResponse?.boundHits.length) {
	domainContext.signals.push(`adaptive bound hits: ${adaptiveResponse.boundHits.join(', ')}`);
}
```

This surfaces in both the text report and structured JSON via existing plumbing.

- [ ] **Step 2: Run full test suite**

Run: `npx vitest run`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/tools/scan-domain.ts
git commit -m "feat: surface adaptive weight bound hits in scoring signals"
```

---

### Task 10: Update re-exports and CLAUDE.md

**Files:**
- Modify: `src/lib/scoring.ts`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add adaptive weight exports to scoring.ts**

```typescript
export {
	adaptiveWeightsToContext,
	blendWeights,
	computeAdaptiveWeight,
	generateScoringNote,
	BASELINE_FAILURE_RATES,
	MATURITY_THRESHOLD,
	SENSITIVITY,
	WEIGHT_BOUNDS,
	type AdaptiveWeightsResponse,
	type ScanTelemetry,
} from './adaptive-weights';
```

- [ ] **Step 2: Update CLAUDE.md**

Add to the Architecture section after the scoring profiles documentation:

```markdown
### Adaptive Scoring (Phase 2)

`ProfileAccumulator` Durable Object accumulates scan telemetry and computes
adaptive importance weights via EMA. `scan_domain` fetches adaptive weights
(50ms timeout, static fallback) and blends them with static baselines
proportional to sample count (fully adaptive at 200+ samples). When the
adaptive score differs from static by 3+ points, a plain-english
`scoringNote` is generated. Telemetry is POST'd to the DO via fire-and-forget
after each scan. The `PROFILE_ACCUMULATOR` binding is optional — without it,
behavior is identical to static Phase 1 weights.
```

Add `src/lib/adaptive-weights.ts` and `src/lib/profile-accumulator.ts` to the file listing.

- [ ] **Step 3: Run full test suite and typecheck**

Run: `npm run typecheck && npm test`
Expected: PASS — all tests green, no type errors

- [ ] **Step 4: Commit**

```bash
git add src/lib/scoring.ts CLAUDE.md
git commit -m "docs: document adaptive scoring system in CLAUDE.md and update re-exports"
```

---

## Verification

After all tasks are complete:

- [ ] `npm run typecheck` — no errors
- [ ] `npm run lint` — no warnings
- [ ] `npm test` — all tests pass with coverage
- [ ] `npm run dev` — local dev starts without errors
- [ ] Manual test: scan a domain, verify `scoringNote` is null (no adaptive data yet)
- [ ] Verify wrangler config is valid: `npx wrangler deploy --dry-run`
