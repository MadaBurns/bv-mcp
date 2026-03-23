# Scoring v2: Three-Tier Category Model — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the flat weighted-average scoring system with a three-tier model (Core 70% / Protective 20% / Hardening 10%) that scores actual security risk rather than aspirational hardening completeness.

**Architecture:** Categories are classified into Core (direct risk), Protective (active defenses), and Hardening (bonus-only defense-in-depth). Each tier has its own scoring mechanic. A confidence gate on `scoreIndicatesMissingControl()` prevents heuristic findings from zeroing categories. Provider-informed DKIM detection cross-references MX/SPF provider signals with DKIM selector probing results.

**Tech Stack:** TypeScript, Vitest, Cloudflare Workers runtime

**Spec:** `docs/superpowers/specs/2026-03-23-scoring-v2-three-tier-design.md`

---

## Task 1: Add CategoryTier type and tier classification to scoring-model.ts

**Files:**
- Modify: `src/lib/scoring-model.ts:5-75`
- Test: `test/scoring-model.spec.ts`

- [ ] **Step 1: Write the failing test**

In `test/scoring-model.spec.ts`, add:

```typescript
import { CATEGORY_TIERS, type CategoryTier } from '../src/lib/scoring-model';

describe('CATEGORY_TIERS', () => {
	it('classifies all 20 categories into tiers', () => {
		expect(Object.keys(CATEGORY_TIERS)).toHaveLength(20);
	});

	it('has 5 core categories', () => {
		const core = Object.entries(CATEGORY_TIERS).filter(([, t]) => t === 'core');
		expect(core.map(([k]) => k).sort()).toEqual(['dkim', 'dmarc', 'dnssec', 'spf', 'ssl']);
	});

	it('has 8 protective categories', () => {
		const protective = Object.entries(CATEGORY_TIERS).filter(([, t]) => t === 'protective');
		expect(protective).toHaveLength(8);
	});

	it('has 7 hardening categories', () => {
		const hardening = Object.entries(CATEGORY_TIERS).filter(([, t]) => t === 'hardening');
		expect(hardening).toHaveLength(7);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/scoring-model.spec.ts --reporter=verbose`
Expected: FAIL — `CATEGORY_TIERS` not exported

- [ ] **Step 3: Implement CategoryTier type and CATEGORY_TIERS map**

In `src/lib/scoring-model.ts`, after the `CheckCategory` type (line 28), add:

```typescript
export type CategoryTier = 'core' | 'protective' | 'hardening';

export const CATEGORY_TIERS: Record<CheckCategory, CategoryTier> = {
	spf: 'core',
	dmarc: 'core',
	dkim: 'core',
	dnssec: 'core',
	ssl: 'core',
	subdomain_takeover: 'protective',
	http_security: 'protective',
	mta_sts: 'protective',
	mx: 'protective',
	caa: 'protective',
	ns: 'protective',
	lookalikes: 'protective',
	shadow_domains: 'protective',
	dane: 'hardening',
	bimi: 'hardening',
	tlsrpt: 'hardening',
	txt_hygiene: 'hardening',
	mx_reputation: 'hardening',
	srv: 'hardening',
	zone_hygiene: 'hardening',
};
```

- [ ] **Step 4: Export from facade**

In `src/lib/scoring.ts`, add `CATEGORY_TIERS` and `CategoryTier` to the scoring-model re-exports.

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run test/scoring-model.spec.ts --reporter=verbose`
Expected: PASS

- [ ] **Step 6: Commit**

```
git add src/lib/scoring-model.ts src/lib/scoring.ts test/scoring-model.spec.ts
git commit -m "feat(scoring-v2): add CategoryTier type and CATEGORY_TIERS classification"
```

---

## Task 2: Update ScoringConfig with tier-aware fields and migration

**Files:**
- Modify: `src/lib/scoring-config.ts:19-222`
- Test: `test/scoring-config.spec.ts`

- [ ] **Step 1: Write the failing tests**

In `test/scoring-config.spec.ts`, add:

```typescript
describe('scoring v2 config', () => {
	it('DEFAULT_SCORING_CONFIG has tierSplit summing to 100', () => {
		const { tierSplit } = DEFAULT_SCORING_CONFIG;
		expect(tierSplit.core + tierSplit.protective + tierSplit.hardening).toBe(100);
	});

	it('DEFAULT_SCORING_CONFIG has coreWeights', () => {
		expect(DEFAULT_SCORING_CONFIG.coreWeights).toEqual({
			dmarc: 22, dkim: 16, spf: 10, dnssec: 7, ssl: 5,
		});
	});

	it('DEFAULT_SCORING_CONFIG has protectiveWeights', () => {
		expect(DEFAULT_SCORING_CONFIG.protectiveWeights.subdomain_takeover).toBe(4);
		expect(Object.values(DEFAULT_SCORING_CONFIG.protectiveWeights).reduce((a, b) => a + b, 0)).toBe(20);
	});

	it('DEFAULT_SCORING_CONFIG has emailBonusFull/Mid/Partial', () => {
		expect(DEFAULT_SCORING_CONFIG.thresholds.emailBonusFull).toBe(5);
		expect(DEFAULT_SCORING_CONFIG.thresholds.emailBonusMid).toBe(3);
		expect(DEFAULT_SCORING_CONFIG.thresholds.emailBonusPartial).toBe(2);
	});

	it('DEFAULT_SCORING_CONFIG has no E grade', () => {
		expect(DEFAULT_SCORING_CONFIG.grades).not.toHaveProperty('e');
	});

	it('parseScoringConfig migrates legacy weights to coreWeights/protectiveWeights', () => {
		const legacy = JSON.stringify({ weights: { dmarc: 30, spf: 15 } });
		const config = parseScoringConfig(legacy);
		expect(config.coreWeights.dmarc).toBe(30);
		expect(config.coreWeights.spf).toBe(15);
	});

	it('parseScoringConfig migrates emailBonusImportance to three fields', () => {
		const legacy = JSON.stringify({ thresholds: { emailBonusImportance: 10 } });
		const config = parseScoringConfig(legacy);
		expect(config.thresholds.emailBonusFull).toBe(10);
		expect(config.thresholds.emailBonusMid).toBe(6);
		expect(config.thresholds.emailBonusPartial).toBe(4);
	});

	it('parseScoringConfig rejects tierSplit not summing to 100', () => {
		const bad = JSON.stringify({ tierSplit: { core: 80, protective: 20, hardening: 10 } });
		const config = parseScoringConfig(bad);
		// Falls back to default
		expect(config.tierSplit.core).toBe(70);
	});
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/scoring-config.spec.ts --reporter=verbose`
Expected: FAIL — missing fields

- [ ] **Step 3: Update ScoringConfig type**

In `src/lib/scoring-config.ts`, update the `ScoringConfig` interface to add:
- `tierSplit: { core: number; protective: number; hardening: number }`
- `coreWeights: Record<string, number>` (5 Core categories)
- `protectiveWeights: Record<string, number>` (8 Protective categories)
- `thresholds.emailBonusFull`, `thresholds.emailBonusMid`, `thresholds.emailBonusPartial`
- Remove `grades.e`

Add `providerDkimConfidence: Record<string, number>` with defaults: `{ amazonses: 0.8, sendgrid: 0.8, mailgun: 0.8, postmark: 0.8, google: 0.9, microsoft365: 0.9, proofpoint: 0.6, mimecast: 0.6 }`.

Update `DEFAULT_SCORING_CONFIG` with the new default values. Keep the legacy `weights` field populated for backward compat but mark with a `@deprecated` JSDoc.

- [ ] **Step 4: Update parseScoringConfig() with migration logic**

Add migration paths in `parseScoringConfig()`:
- If `weights` present and `coreWeights` absent → partition using `CATEGORY_TIERS` import
- If `emailBonusImportance` present without new fields → derive `emailBonusFull/Mid/Partial`
- If `tierSplit` present but doesn't sum to 100 → fall back to defaults
- If `grades.e` present → silently ignore

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run test/scoring-config.spec.ts --reporter=verbose`
Expected: PASS

- [ ] **Step 6: Commit**

```
git add src/lib/scoring-config.ts test/scoring-config.spec.ts
git commit -m "feat(scoring-v2): add tier-aware ScoringConfig fields with legacy migration"
```

---

## Task 3: Restructure profile weights per tier in context-profiles.ts

**Files:**
- Modify: `src/lib/context-profiles.ts:30-159`
- Test: `test/scoring-profiles.spec.ts`

- [ ] **Step 1: Write the failing tests**

In `test/scoring-profiles.spec.ts`, add tests for tier-structured profile weights:

```typescript
describe('scoring v2 profile weights', () => {
	it('mail_enabled core weights sum to 60', () => {
		const core = PROFILE_WEIGHTS.mail_enabled;
		const coreSum = ['spf', 'dmarc', 'dkim', 'dnssec', 'ssl']
			.reduce((sum, k) => sum + core[k as CheckCategory].importance, 0);
		expect(coreSum).toBe(60);
	});

	it('enterprise_mail core weights sum to 68', () => {
		const core = PROFILE_WEIGHTS.enterprise_mail;
		const coreSum = ['spf', 'dmarc', 'dkim', 'dnssec', 'ssl']
			.reduce((sum, k) => sum + core[k as CheckCategory].importance, 0);
		expect(coreSum).toBe(68);
	});

	it('web_only zeroes email auth core weights', () => {
		const p = PROFILE_WEIGHTS.web_only;
		expect(p.spf.importance).toBe(0);
		expect(p.dmarc.importance).toBe(0);
		expect(p.dkim.importance).toBe(0);
	});

	it('PROFILE_CRITICAL_CATEGORIES excludes DNSSEC and subdomain_takeover for mail profiles', () => {
		expect(PROFILE_CRITICAL_CATEGORIES.mail_enabled).not.toContain('dnssec');
		expect(PROFILE_CRITICAL_CATEGORIES.enterprise_mail).not.toContain('dnssec');
		expect(PROFILE_CRITICAL_CATEGORIES.mail_enabled).not.toContain('subdomain_takeover');
		expect(PROFILE_CRITICAL_CATEGORIES.mail_enabled).toEqual(
			expect.arrayContaining(['spf', 'dmarc', 'dkim', 'ssl'])
		);
	});

	it('non_mail/web_only ceiling triggers include http_security', () => {
		expect(PROFILE_CRITICAL_CATEGORIES.non_mail).toContain('http_security');
		expect(PROFILE_CRITICAL_CATEGORIES.web_only).toContain('http_security');
	});
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/scoring-profiles.spec.ts --reporter=verbose`
Expected: FAIL — weight values don't match new expectations

- [ ] **Step 3: Update PROFILE_WEIGHTS with tier-structured values**

Update all 5 profiles in `PROFILE_WEIGHTS` (lines 30–141) with the complete weight tables from the spec. All Hardening categories get `importance: 0` across all profiles (they're bonus-only).

Update `PROFILE_CRITICAL_CATEGORIES` (lines 144–150):
- `mail_enabled` / `enterprise_mail`: `['spf', 'dmarc', 'dkim', 'ssl']` (remove `subdomain_takeover`, keep DNSSEC exempt)
- `non_mail` / `web_only`: `['ssl', 'http_security', 'subdomain_takeover']`
- `minimal`: `['ssl']`

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/scoring-profiles.spec.ts --reporter=verbose`
Expected: PASS

- [ ] **Step 5: Commit**

```
git add src/lib/context-profiles.ts test/scoring-profiles.spec.ts
git commit -m "feat(scoring-v2): restructure profile weights for three-tier model"
```

---

## Task 4: Implement three-tier computeScanScore() and confidence gate

**Files:**
- Modify: `src/lib/scoring-engine.ts:24-223`
- Test: `test/scoring-engine.spec.ts`

This is the core task — the largest change. It rewrites `computeScanScore()` and `scoreIndicatesMissingControl()`.

- [ ] **Step 1: Write the failing tests for confidence gate**

In `test/scoring-engine.spec.ts`, add:

```typescript
describe('confidence gate', () => {
	it('scoreIndicatesMissingControl ignores heuristic high findings', () => {
		const findings = [createFinding('dkim', 'No DKIM records found among tested selectors', 'high',
			'No DKIM records were found', { confidence: 'heuristic' })];
		// Internal function — test through computeScanScore behavior
		const dkimResult = buildCheckResult('dkim', findings);
		const results = [dkimResult];
		const score = computeScanScore(results);
		// DKIM should NOT be zeroed out — it contributes its computed score (75)
		expect(score.categoryScores.dkim).toBe(75);
		expect(score.overall).toBeGreaterThan(60); // Would be much lower if zeroed
	});

	it('scoreIndicatesMissingControl fires on deterministic high findings', () => {
		const findings = [createFinding('spf', 'No SPF record found', 'high',
			'No SPF record found for example.com', { confidence: 'deterministic' })];
		const spfResult = buildCheckResult('spf', findings);
		const results = [spfResult];
		const score = computeScanScore(results);
		// SPF should be zeroed — deterministic missing control
		expect(score.overall).toBeLessThan(65); // Ceiling fires
	});
});
```

- [ ] **Step 2: Write the failing tests for three-tier formula**

```typescript
describe('three-tier scoring', () => {
	it('perfect core + default protective yields ~90', () => {
		// All core categories at 100, no protective or hardening results
		// Absent categories with weight > 0 default to score 100 (consistent with v1)
		const results = ['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'].map(cat =>
			buildCheckResult(cat as CheckCategory, [
				createFinding(cat as CheckCategory, `${cat} configured`, 'info', 'All good'),
			])
		);
		const score = computeScanScore(results);
		// Core = 70 (all perfect), Protective = 20 (absent defaults to 100), Hardening = 0
		expect(score.overall).toBeGreaterThanOrEqual(88);
		expect(score.overall).toBeLessThanOrEqual(92);
	});

	it('perfect core + failing protective yields ~70', () => {
		// All core at 100, all protective explicitly at 0
		const coreResults = ['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'].map(cat =>
			buildCheckResult(cat as CheckCategory, [
				createFinding(cat as CheckCategory, `${cat} ok`, 'info', 'fine'),
			])
		);
		const protResults = ['subdomain_takeover', 'http_security', 'mta_sts', 'mx', 'caa', 'ns', 'lookalikes', 'shadow_domains'].map(cat =>
			buildCheckResult(cat as CheckCategory, [
				createFinding(cat as CheckCategory, `${cat} critical`, 'critical', 'very bad'),
				createFinding(cat as CheckCategory, `${cat} critical2`, 'critical', 'very bad 2'),
				createFinding(cat as CheckCategory, `${cat} high`, 'high', 'bad'),
			])
		);
		const score = computeScanScore([...coreResults, ...protResults]);
		// Core = 70, Protective ≈ 0, Hardening = 0
		expect(score.overall).toBeGreaterThanOrEqual(68);
		expect(score.overall).toBeLessThanOrEqual(75);
	});

	it('hardening categories can only add points, never subtract', () => {
		const coreResults = ['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'].map(cat =>
			buildCheckResult(cat as CheckCategory, [
				createFinding(cat as CheckCategory, `${cat} ok`, 'info', 'fine'),
			])
		);
		const scoreWithout = computeScanScore(coreResults);
		const hardeningResult = buildCheckResult('dane', [
			createFinding('dane', 'No DANE', 'high', 'No TLSA records found'),
		]);
		const scoreWith = computeScanScore([...coreResults, hardeningResult]);
		// Failed hardening should not reduce score — 0 bonus instead of positive
		expect(scoreWith.overall).toBeGreaterThanOrEqual(scoreWithout.overall);
	});

	it('E grade no longer exists', () => {
		expect(scoreToGrade(52)).toBe('D');
		expect(scoreToGrade(49)).toBe('F');
	});

	it('new grade boundaries apply', () => {
		expect(scoreToGrade(92)).toBe('A+');
		expect(scoreToGrade(91)).toBe('A');
		expect(scoreToGrade(87)).toBe('A');
		expect(scoreToGrade(86)).toBe('B+');
		expect(scoreToGrade(76)).toBe('B');
		expect(scoreToGrade(75)).toBe('C+');
	});
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `npx vitest run test/scoring-engine.spec.ts --reporter=verbose`
Expected: FAIL

- [ ] **Step 4: Update scoreIndicatesMissingControl() with confidence gate**

In `src/lib/scoring-engine.ts`, first extract the existing inline regex (from inside `scoreIndicatesMissingControl`, lines 47–53) to a named module-scope constant:

```typescript
const MISSING_CONTROL_REGEX = /(no\s+.+\s+record|missing|required|not\s+found)/i;
```

Then rewrite the function:

```typescript
function scoreIndicatesMissingControl(findings: Finding[]): boolean {
	return findings.some((f) => {
		const isMissingPattern = MISSING_CONTROL_REGEX.test(f.detail) || MISSING_CONTROL_REGEX.test(f.title);
		const confidence = (f.metadata?.confidence as string) ?? inferFindingConfidence(f);
		return (
			isMissingPattern &&
			(f.severity === 'critical' || f.severity === 'high') &&
			(confidence === 'deterministic' || confidence === 'verified')
		);
	});
}
```

- [ ] **Step 5: Add CORE_WEIGHTS, PROTECTIVE_WEIGHTS exports**

Replace `IMPORTANCE_WEIGHTS` (lines 24–45) with:

```typescript
/** @deprecated Use CORE_WEIGHTS and PROTECTIVE_WEIGHTS instead */
export const LEGACY_IMPORTANCE_WEIGHTS = { /* old values */ };

export const CORE_WEIGHTS: Record<string, number> = {
	dmarc: 22, dkim: 16, spf: 10, dnssec: 7, ssl: 5,
};

export const PROTECTIVE_WEIGHTS: Record<string, number> = {
	subdomain_takeover: 4, http_security: 3, mta_sts: 3, mx: 2,
	caa: 2, ns: 2, lookalikes: 2, shadow_domains: 2,
};
```

- [ ] **Step 6: Rewrite computeScanScore() with three-tier formula**

Replace the body of `computeScanScore()` (lines 104–223) with the three-tier implementation:
1. Seed all category scores to 100 — categories with no `CheckResult` entry default to score 100 (consistent with v1 behavior: absent = no findings = perfect)
2. Populate from results (override seeded defaults with actual scores)
3. Compute `core_earned` / `core_max` using profile weights (or `CORE_WEIGHTS` default). `core_max = sum(profile core weights)`, computed dynamically
4. Apply `scoreIndicatesMissingControl()` only to Core categories
5. Compute `protective_earned` / `protective_max` — no missing-control override
6. Compute `hardening_pts` = count of passed hardening categories / total hardening count × 10
7. `base = core_pct × tierSplit.core + protective_pct × tierSplit.protective + hardening_pts`
8. Apply email bonus (new three-field config), provider modifier, critical penalty
9. Apply critical gap ceiling (only Core categories, only deterministic/verified)

- [ ] **Step 7: Update scoreToGrade() — remove E, adjust boundaries**

Update `scoreToGrade()` (lines 77–89) with new boundaries from spec: A+ ≥ 92, A ≥ 87, B+ ≥ 82, B ≥ 76, C+ ≥ 70, C ≥ 63, D+ ≥ 56, D ≥ 50, F < 50.

- [ ] **Step 8: Update scoring.ts facade exports**

In `src/lib/scoring.ts`, add exports for `CORE_WEIGHTS`, `PROTECTIVE_WEIGHTS`, `LEGACY_IMPORTANCE_WEIGHTS`. Remove or alias `IMPORTANCE_WEIGHTS`.

- [ ] **Step 9: Run tests and fix remaining failures**

Run: `npx vitest run test/scoring-engine.spec.ts --reporter=verbose`
Fix any existing test expectations that broke due to new score values and grade boundaries.

- [ ] **Step 10: Run full test suite**

Run: `npm test`
Note failures in other test files — these will be fixed in subsequent tasks.

- [ ] **Step 11: Commit**

```
git add src/lib/scoring-engine.ts src/lib/scoring.ts test/scoring-engine.spec.ts
git commit -m "feat(scoring-v2): implement three-tier computeScanScore with confidence gate"
```

---

## Task 5: Replace interaction rule for DNSSEC

**Files:**
- Modify: `src/lib/category-interactions.ts:64-71`
- Test: `test/category-interactions.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
it('weak_dnssec_enforcing_dmarc fires when DNSSEC <= 40 and DMARC >= 80', () => {
	const score = buildMockScanScore({ dmarc: 90, dnssec: 35 });
	const { effects } = applyInteractionPenalties(score);
	const rule = effects.find((e) => e.ruleId === 'weak_dnssec_enforcing_dmarc');
	expect(rule).toBeDefined();
	expect(rule!.penalty).toBe(-3);
});

it('old strong_auth_no_dnssec rule no longer exists', () => {
	const score = buildMockScanScore({ dmarc: 90, dnssec: 0 });
	const { effects } = applyInteractionPenalties(score);
	expect(effects.find((e) => e.ruleId === 'strong_auth_no_dnssec')).toBeUndefined();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/category-interactions.spec.ts --reporter=verbose`

- [ ] **Step 3: Replace the rule**

In `src/lib/category-interactions.ts`, replace the `strong_auth_no_dnssec` rule (lines 64–71) with:

```typescript
{
	id: 'weak_dnssec_enforcing_dmarc',
	conditions: [
		{ category: 'dmarc', minScore: 80 },
		{ category: 'dnssec', maxScore: 40 },
	],
	overallPenalty: 3,
	narrative: 'Strong email authentication is in place but DNSSEC is weak or absent — DNS tampering could undermine authentication records.',
},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/category-interactions.spec.ts --reporter=verbose`
Expected: PASS

- [ ] **Step 5: Commit**

```
git add src/lib/category-interactions.ts test/category-interactions.spec.ts
git commit -m "feat(scoring-v2): replace strong_auth_no_dnssec with weak_dnssec_enforcing_dmarc"
```

---

## Task 6: Consolidate DNSSEC findings

**Files:**
- Modify: `src/tools/check-dnssec.ts:21-97`
- Test: `test/check-dnssec.spec.ts`

- [ ] **Step 1: Write the failing tests**

```typescript
describe('DNSSEC finding consolidation', () => {
	it('emits single MEDIUM finding when DNSSEC is not enabled', async () => {
		// Mock: no AD flag, no DNSKEY, no DS
		const result = await checkDnssec('example.com');
		const findings = result.findings.filter((f) => f.severity !== 'info');
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('medium');
		expect(findings[0].title).toBe('DNSSEC not enabled');
	});

	it('emits HIGH when DNSKEY present but DS missing (broken chain)', async () => {
		// Mock: DNSKEY present, no DS, no AD
		const result = await checkDnssec('example.com');
		expect(result.findings.some((f) => f.title === 'DNSSEC chain of trust incomplete' && f.severity === 'high')).toBe(true);
	});
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/check-dnssec.spec.ts --reporter=verbose`

- [ ] **Step 3: Refactor check-dnssec.ts**

Restructure `src/tools/check-dnssec.ts` so both DNSKEY and DS queries complete before the consolidated finding logic runs. The current code has each query in its own try/catch — refactor to initialize empty arrays and populate in try/catch blocks:

```typescript
export async function checkDnssec(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];

	// Step 1: Query AD flag (existing logic, unchanged)
	const adFlag = await queryAdFlag(domain, dnsOptions);

	// Step 2: Query DNSKEY and DS records — both must complete before consolidated logic
	let dnskeyRecords: string[] = [];
	let dsRecords: string[] = [];

	try {
		dnskeyRecords = await queryDnskeyRecords(domain, dnsOptions);
	} catch {
		// DNSKEY query failed — treat as empty (DNSSEC not configured)
	}

	try {
		dsRecords = await queryDsRecords(domain, dnsOptions);
	} catch {
		// DS query failed — treat as empty
	}

	// Step 3: Consolidated finding logic
	if (!adFlag && dnskeyRecords.length === 0 && dsRecords.length === 0) {
		// Fully absent — single MEDIUM finding
		findings.push(createFinding('dnssec', 'DNSSEC not enabled', 'medium',
			`DNSSEC is not configured for ${domain}. Without DNSSEC, DNS responses are not cryptographically verified, leaving SPF, DMARC, and DKIM records vulnerable to DNS-level manipulation.`));
	} else if (dnskeyRecords.length > 0 && dsRecords.length === 0) {
		// Broken chain — HIGH
		findings.push(createFinding('dnssec', 'DNSSEC chain of trust incomplete', 'high',
			`DNSKEY records are published for ${domain} but no DS records exist in the parent zone. The chain of trust is broken — DNSSEC validation will fail.`));
	} else if (dnskeyRecords.length > 0 && dsRecords.length > 0 && !adFlag) {
		// Deployed but failing — HIGH
		findings.push(createFinding('dnssec', 'DNSSEC validation failing', 'high',
			`DNSKEY and DS records are present for ${domain} but the AD flag is not set. DNSSEC is deployed but validation is failing — this is worse than not having DNSSEC.`));
	}

	// Step 4: Algorithm/digest audits (existing logic, moved AFTER consolidated block)
	if (dnskeyRecords.length > 0) {
		findings.push(...auditDnskeyAlgorithms(domain, dnskeyRecords));
	}
	if (dsRecords.length > 0) {
		findings.push(...auditDsDigestTypes(domain, dsRecords));
	}

	// Step 5: Positive finding if no issues (existing logic)
	if (findings.length === 0) {
		findings.push(createFinding('dnssec', 'DNSSEC enabled and validated', 'info', ...));
	}

	return buildCheckResult('dnssec', findings);
}
```

This restructuring ensures both `dnskeyRecords` and `dsRecords` are in scope for the consolidated if/else chain, and the algorithm/digest audits run after the consolidated logic.

- [ ] **Step 4: Run tests and fix**

Run: `npx vitest run test/check-dnssec.spec.ts --reporter=verbose`
Update existing test expectations that assumed 3 separate findings for the "not enabled" case.

- [ ] **Step 5: Commit**

```
git add src/tools/check-dnssec.ts test/check-dnssec.spec.ts
git commit -m "feat(scoring-v2): consolidate DNSSEC findings — single MEDIUM for not-enabled"
```

---

## Task 7: Provider-informed DKIM detection

**Files:**
- Modify: `src/tools/check-dkim.ts:213-227`
- Modify: `src/tools/scan-domain.ts` (pass provider info)
- Test: `test/check-dkim.spec.ts`

- [ ] **Step 1: Write the failing tests**

```typescript
describe('provider-informed DKIM', () => {
	it('downgrades to medium when high-confidence provider detected', async () => {
		// Setup: no DKIM selectors found, but provider = 'amazonses'
		const result = await checkDkim('example.com', undefined, undefined, { detectedProvider: 'amazonses' });
		const notFound = result.findings.find((f) => /selector not discovered/i.test(f.title));
		expect(notFound).toBeDefined();
		expect(notFound!.severity).toBe('medium');
		expect(notFound!.metadata?.confidence).toBe('heuristic');
	});

	it('keeps high finding with heuristic confidence when no provider', async () => {
		const result = await checkDkim('example.com');
		const notFound = result.findings.find((f) => /No DKIM records found/i.test(f.title));
		expect(notFound).toBeDefined();
		expect(notFound!.severity).toBe('high');
		expect(notFound!.metadata?.confidence).toBe('heuristic');
	});
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/check-dkim.spec.ts --reporter=verbose`

- [ ] **Step 3: Add provider parameter to checkDkim()**

Add an optional parameter to `checkDkim()`:

```typescript
export async function checkDkim(
	domain: string,
	selector?: string,
	dnsOptions?: QueryDnsOptions,
	providerContext?: { detectedProvider: string | null },
): Promise<CheckResult> {
```

- [ ] **Step 4: Implement provider-informed DKIM logic**

In the `foundSelectors.length === 0` block (lines 213–227), add provider cross-reference:

```typescript
const HIGH_CONFIDENCE_DKIM_PROVIDERS = new Set(['amazonses', 'sendgrid', 'mailgun', 'postmark', 'google', 'microsoft365']);
const MEDIUM_CONFIDENCE_DKIM_PROVIDERS = new Set(['proofpoint', 'mimecast']);

if (foundSelectors.length === 0) {
	const provider = providerContext?.detectedProvider?.toLowerCase() ?? null;

	if (provider && HIGH_CONFIDENCE_DKIM_PROVIDERS.has(provider)) {
		findings.push(createFinding('dkim', 'DKIM selector not discovered', 'medium',
			`No DKIM selectors were found among the tested set, but ${provider} is detected as the email provider. ${provider} signs outbound mail by default — DKIM is likely present with a custom selector.`,
			{ confidence: 'heuristic', detectionMethod: 'provider-implied', provider, selectorsChecked }));
	} else if (provider && MEDIUM_CONFIDENCE_DKIM_PROVIDERS.has(provider)) {
		findings.push(createFinding('dkim', 'DKIM selector not discovered', 'medium',
			`No DKIM selectors were found among the tested set. ${provider} is detected as the email provider and typically signs outbound mail.`,
			{ confidence: 'heuristic', detectionMethod: 'provider-implied', provider, selectorsChecked }));
		findings.push(createFinding('dkim', 'DKIM provider signing unverified', 'low',
			`${provider} signing policy varies by configuration — DKIM presence cannot be confirmed without selector discovery.`,
			{ confidence: 'heuristic' }));
	} else {
		// Original behavior with explicit confidence
		findings.push(createFinding('dkim', 'No DKIM records found among tested selectors', 'high',
			`No DKIM records were found for ${domain} among the tested selector set (${selectorsChecked.join(', ')}). This may indicate DKIM is not configured, or uses a custom selector not in the tested set.`,
			{ signalType: 'dkim', detectionMethod: 'selector-probing', selectorsChecked, selectorsFound: [], confidence: 'heuristic' }));
	}
}
```

- [ ] **Step 5: Apply provider-informed DKIM as a post-processing step in scan-domain.ts**

**Important**: `scan_domain` runs MX and DKIM in parallel via `Promise.allSettled` — the MX provider result is NOT available when DKIM starts. Do NOT try to thread provider context into the parallel batch.

Instead, apply provider-informed DKIM as a **post-processing step** after all parallel checks complete:

```typescript
// In scanDomain(), after Promise.allSettled completes and results are collected:

// 1. Extract provider from MX/SPF results (already done for detectDomainContext)
const detectedProvider = domainContext?.detectedProvider ?? null;

// 2. If DKIM check returned "No DKIM records found" and a provider is detected,
//    re-evaluate the DKIM result with provider context
if (detectedProvider && dkimResult) {
	const hasNoDkimFinding = dkimResult.findings.some(
		(f) => /No DKIM records found/i.test(f.title) && f.severity === 'high'
	);
	if (hasNoDkimFinding) {
		// Re-run checkDkim with provider context (uses cached DNS results, fast)
		const revisedDkim = await checkDkim(domain, undefined, scanDnsOptions, { detectedProvider });
		// Replace DKIM result in the results array
		replaceCheckResult(results, 'dkim', revisedDkim);
	}
}
```

This approach re-runs DKIM only when needed (provider detected AND DKIM "not found"), using cached DNS lookups so the re-run is near-instant. The `handlers/tools.ts` standalone `check_dkim` tool does NOT get provider context — this is by design, since standalone calls have no MX context. Document this in a code comment.

Alternatively, extract the provider-informed finding adjustment into a pure function that modifies findings in-place without re-querying DNS:

```typescript
function applyProviderDkimContext(dkimResult: CheckResult, provider: string): CheckResult {
	// Replace the HIGH "not found" finding with a MEDIUM "not discovered" finding
	// Recompute category score
	// Return updated CheckResult
}
```

This avoids the re-run entirely and is the preferred approach.

- [ ] **Step 6: Run tests**

Run: `npx vitest run test/check-dkim.spec.ts --reporter=verbose`
Expected: PASS

- [ ] **Step 7: Commit**

```
git add src/tools/check-dkim.ts src/tools/scan-domain.ts test/check-dkim.spec.ts
git commit -m "feat(scoring-v2): provider-informed DKIM detection with confidence metadata"
```

---

## Task 8: Redesign maturity staging

**Files:**
- Modify: `src/tools/scan/maturity-staging.ts:22-124`
- Test: `test/maturity-staging.spec.ts`

- [ ] **Step 1: Write the failing tests**

```typescript
describe('maturity staging v2', () => {
	it('Stage 3 does not require DKIM discovery', () => {
		const checks = buildChecks({ hasSpf: true, hasDmarc: true, dmarcPolicy: 'reject', hasDkim: false });
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(3);
		expect(stage.label).toBe('Enforcing');
	});

	it('Stage 1 is specifically DMARC p=none without rua', () => {
		const checks = buildChecks({ hasSpf: true, hasDmarc: true, dmarcPolicy: 'none', hasRua: false });
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(1);
	});

	it('Stage 4 accepts CAA as hardening signal', () => {
		const checks = buildChecks({
			hasSpf: true, hasDmarc: true, dmarcPolicy: 'reject',
			hasDnssec: true, hasCaa: true,
		});
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(4);
	});

	it('Stage 4 accepts DKIM discovered as hardening signal', () => {
		const checks = buildChecks({
			hasSpf: true, hasDmarc: true, dmarcPolicy: 'reject',
			hasDkim: true, hasMtaSts: true,
		});
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(4);
	});
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/maturity-staging.spec.ts --reporter=verbose`

- [ ] **Step 3: Update computeMaturityStage()**

In `src/tools/scan/maturity-staging.ts`:

1. Remove `hasDkim` from the `isEnforcing` check (line 75): `const isEnforcing = hasSpf && hasDmarc && (dmarcPolicyReject || dmarcPolicyQuarantine);`
2. **Update `hasDkim` detection** to use metadata instead of fragile title regex. After Task 7, the "not found" finding title varies (`'No DKIM records found among tested selectors'` vs `'DKIM selector not discovered'`). The spec requires provider-implied DKIM NOT count as "discovered". Use metadata:
   ```typescript
   // "Discovered" = at least one selector physically found (not provider-implied)
   const hasDkimDiscovered = dkimCheck != null && dkimCheck.findings.some(
       (f) => f.metadata?.detectionMethod === 'selector-probing' && (f.metadata?.selectorsFound as string[])?.length > 0
   );
   ```
   Alternatively, check that NO finding has `detectionMethod: 'provider-implied'` AND no "not found/not discovered" high/medium finding exists.
3. Add `hasCaa` and `hasDkimDiscovered` to the hardening signals: `const hardeningCount = [hasMtaSts, hasDnssec, hasBimi, hasDane, hasCaa, hasDkimDiscovered].filter(Boolean).length;`
4. Detect `hasCaa` from CAA check results: `const hasCaa = caaCheck != null && caaCheck.passed;`
5. Update Stage 1 to be `hasSpf && hasDmarc && dmarcPolicyNone && !hasRua` (narrowed)

- [ ] **Step 4: Run tests and fix**

Run: `npx vitest run test/maturity-staging.spec.ts --reporter=verbose`
Update existing test expectations that assumed DKIM was required for Stage 3.

- [ ] **Step 5: Commit**

```
git add src/tools/scan/maturity-staging.ts test/maturity-staging.spec.ts
git commit -m "feat(scoring-v2): redesign maturity staging — DKIM not required for Stage 3"
```

---

## Task 9: Fix remaining test failures across the suite

**Files:**
- Modify: `test/scan-domain.spec.ts`, `test/index.spec.ts`, and any other failing test files

- [ ] **Step 1: Run full test suite and catalog failures**

Run: `npm test 2>&1 | grep -E "FAIL|×|failed" | head -30`

- [ ] **Step 2: Fix each failing test file**

For each failing test, update score expectations to match the new three-tier formula output. Key areas:
- `test/scan-domain.spec.ts` — scan score expectations change
- `test/index.spec.ts` — any integration tests with score/grade assertions
- Any test that asserts specific grade values or references the E grade

- [ ] **Step 3: Run full suite until green**

Run: `npm test`
Expected: All tests pass

- [ ] **Step 4: Commit**

```
git add test/
git commit -m "test(scoring-v2): update all test expectations for three-tier scoring"
```

---

## Task 10: Update documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`
- Modify: `docs/scoring.md`
- Modify: `src/handlers/tool-schemas.ts`
- Modify: `src/lib/server-version.ts`
- Modify: `package.json`

- [ ] **Step 1: Update CLAUDE.md scoring section**

Replace the Scoring section with:
- Three-tier model explanation (Core/Protective/Hardening)
- New weight tables per tier
- New grade boundaries (no E grade)
- Updated maturity staging criteria
- Confidence gate explanation
- Provider-informed DKIM explanation

- [ ] **Step 2: Update README.md**

- Remove E grade from any grade tables
- Update the Security section to mention three-tier scoring

- [ ] **Step 3: Update docs/scoring.md**

Full scoring v2 documentation with the complete formula, tier assignments, profile weights, grade boundaries.

- [ ] **Step 4: Update tool-schemas.ts**

Remove any references to E grade in tool description strings.

- [ ] **Step 5: Version bump**

Update `src/lib/server-version.ts` and `package.json` version to `2.0.0`.

- [ ] **Step 6: Final verification**

```bash
npm run typecheck && npm run lint && npm test
```

- [ ] **Step 7: Commit**

```
git add CLAUDE.md README.md docs/scoring.md src/handlers/tool-schemas.ts src/lib/server-version.ts package.json
git commit -m "docs: update all documentation for scoring v2 three-tier model

BREAKING CHANGE: scoring formula, grade boundaries, and maturity staging
criteria have changed. All domain scores will shift. E grade removed."
```
