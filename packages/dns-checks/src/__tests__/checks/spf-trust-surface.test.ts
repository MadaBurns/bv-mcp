// SPDX-License-Identifier: BUSL-1.1

/**
 * Core SPF trust-surface catalog coverage.
 *
 * The worker layer (`src/tools/spf-trust-surface.ts`) carries its own copy of this
 * catalog, so a platform recognized there is NOT automatically recognized here —
 * and DIRECT consumers of the vendored core (bv-web-prod calls `checkSPF` from
 * the published package, not the bv-mcp worker wrapper) see only this file's
 * catalog. Issue #572 was exactly that drift: Mailjet was added worker-side in
 * PR #570 and left out of the core, so bv-web-prod under-counted the trust surface.
 *
 * These cases pin the core half of that parity.
 */

import { describe, expect, it } from 'vitest';
import { analyzeTrustSurface } from '../../checks/spf-trust-surface';
import { buildCheckResult } from '../../check-utils';

describe('core SPF trust-surface catalog — Mailjet (#572)', () => {
	it('recognizes the canonical spf.mailjet.com include', () => {
		const findings = analyzeTrustSurface('v=spf1 include:spf.mailjet.com -all');

		expect(findings).toHaveLength(1);
		expect(findings[0].metadata?.platform).toBe('Mailjet');
		expect(findings[0].metadata?.trustSurface).toBe(true);
		expect(findings[0].metadata?.includeDomain).toBe('spf.mailjet.com');
	});

	it('matches Mailjet sub-hosts via the registrable-key suffix rule', () => {
		const findings = analyzeTrustSurface('v=spf1 include:eu.spf.mailjet.com -all');

		expect(findings).toHaveLength(1);
		expect(findings[0].metadata?.platform).toBe('Mailjet');
		expect(findings[0].metadata?.includeDomain).toBe('eu.spf.mailjet.com');
	});

	it('counts Mailjet toward the multi-platform trust-surface summary', () => {
		const findings = analyzeTrustSurface('v=spf1 include:_spf.google.com include:spf.mailjet.com -all');

		// 2 per-platform findings + 1 summary.
		expect(findings).toHaveLength(3);
		const summary = findings.find((f) => f.metadata?.platformCount !== undefined);
		expect(summary).toBeDefined();
		expect(summary!.metadata?.platformCount).toBe(2);
		expect(summary!.title).toContain('2 shared platforms');
	});
});

/**
 * Wording regression, mirrored from the worker copy's spec (`test/spf-trust-surface.spec.ts`).
 *
 * An ENFORCING DMARC policy must never be described as "weak DMARC enforcement": the same
 * scan_domain response lists "DMARC enforcing" in its scoring signals for `p=quarantine`
 * (which is also this product's BIMI eligibility bar), so the old blanket suffix made one
 * report contradict itself. When the policy enforces, the corroborating signal is the
 * relaxed alignment (or a partial `pct=`), and the prose must say so.
 *
 * These cases pin the CORE half — direct package consumers (bv-web-prod) read this copy.
 */
describe('core SPF trust-surface corroboration prose matches the DMARC metadata', () => {
	it('does not claim weak enforcement for p=quarantine — cites relaxed alignment instead', () => {
		const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
			corroboratedByWeakDmarc: true,
			dmarcPolicy: 'quarantine',
			dmarcAlignmentMode: 'relaxed',
		});

		expect(findings).toHaveLength(1);
		expect(findings[0].detail).not.toMatch(/weak DMARC enforcement/i);
		expect(findings[0].detail).not.toMatch(/not enforcing/i);
		expect(findings[0].detail).toMatch(/alignment is relaxed/i);
		expect(findings[0].detail).toMatch(/p=quarantine/);
	});

	it('does not claim weak enforcement for p=reject', () => {
		const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
			corroboratedByWeakDmarc: true,
			dmarcPolicy: 'reject',
			dmarcAlignmentMode: 'relaxed',
		});

		expect(findings[0].detail).not.toMatch(/weak DMARC enforcement/i);
		expect(findings[0].detail).toMatch(/alignment is relaxed/i);
		expect(findings[0].detail).toMatch(/p=reject/);
	});

	it('does cite non-enforcement for p=none', () => {
		const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
			corroboratedByWeakDmarc: true,
			dmarcPolicy: 'none',
			dmarcAlignmentMode: 'relaxed',
		});

		expect(findings[0].detail).toMatch(/monitor-only \(p=none\) and is not enforcing/i);
	});

	it('does cite an absent DMARC record when there is none', () => {
		const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
			corroboratedByWeakDmarc: true,
			dmarcPolicy: 'missing',
			dmarcAlignmentMode: 'missing',
		});

		expect(findings[0].detail).toMatch(/No DMARC record is published/i);
		expect(findings[0].detail).not.toMatch(/weak DMARC enforcement/i);
	});

	it('cites partial application, not weak enforcement, for an enforcing pct<100 policy', () => {
		const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
			corroboratedByWeakDmarc: true,
			dmarcPolicy: 'reject; pct=50',
			dmarcAlignmentMode: 'strict',
		});

		expect(findings[0].detail).toMatch(/enforces \(p=reject\) on only 50% of mail/i);
		expect(findings[0].detail).not.toMatch(/weak DMARC enforcement/i);
	});

	it('leaves the uncorroborated (info) wording and severity untouched', () => {
		const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
			corroboratedByWeakDmarc: false,
			dmarcPolicy: 'reject',
			dmarcAlignmentMode: 'strict',
		});

		expect(findings[0].severity).toBe('info');
		expect(findings[0].detail).toMatch(/not inherently a misconfiguration/i);
	});

	/**
	 * #637 — INVERTED, not deleted.
	 *
	 * This case used to read "keeps the corroborated severities unchanged (medium per-platform,
	 * high summary)" and assert 2 × `medium` + 1 × `high`. That pinned the DOUBLE-COUNT: the
	 * aggregate "N shared platforms" finding and the per-platform findings describe the SAME
	 * condition, so a −15 was charged per platform ON TOP of the aggregate's −25. github.com
	 * (6 platforms) paid −90 + −25 and its valid, working SPF record scored 0 — indistinguishable
	 * from publishing no SPF at all. A test that pins the double-count is pinning the bug, so the
	 * assertion is inverted here and kept as the tripwire against reintroducing it.
	 */
	it('scores the trust surface ONCE — per-platform findings are info, only the aggregate is scored (#637)', () => {
		const findings = analyzeTrustSurface('v=spf1 include:_spf.google.com include:sendgrid.net -all', {
			corroboratedByWeakDmarc: true,
			dmarcPolicy: 'quarantine',
			dmarcAlignmentMode: 'relaxed',
		});

		const perPlatform = findings.filter((f) => f.metadata?.platformCount === undefined);
		const aggregate = findings.filter((f) => f.metadata?.platformCount !== undefined);

		expect(perPlatform).toHaveLength(2);
		expect(perPlatform.every((f) => f.severity === 'info')).toBe(true);
		expect(aggregate).toHaveLength(1);
		// The aggregate is unchanged: still the one scored signal, still escalating to `high`
		// under corroboration and still naming the platform count.
		expect(aggregate[0].severity).toBe('high');
		expect(findings.filter((f) => f.severity !== 'info'), 'exactly ONE scored finding for the whole trust surface').toHaveLength(1);

		// The per-platform findings stay fully detailed — same corroboration prose, same
		// metadata — so a customer can still see which platforms are authorized and why.
		expect(perPlatform[0].detail).toMatch(/alignment is relaxed/i);
		expect(perPlatform[0].metadata?.dmarcCorroborated).toBe(true);
		expect(perPlatform[0].metadata?.dmarcPolicy).toBe('quarantine');
	});

	/**
	 * The SCORE consequence of #637, pinned as a number rather than as severity labels.
	 *
	 * github.com's shape: six cataloged platforms under a corroborating DMARC. Before the fix
	 * this cost 6 × −15 (per-platform `medium`) PLUS −25 (the aggregate `high`) = −115, which
	 * clamps the `spf` category to 0 — the same score a domain with no SPF record at all
	 * receives. After: one −25 for the whole trust surface, so the category reads 75 and the
	 * check can once again discriminate between a complex sender profile and a missing control.
	 *
	 * The category score is asserted HERE, against the package source, because the worker
	 * wrapper (`src/tools/check-spf.ts`) never recomputes it — it passes through this package's
	 * score unchanged.
	 */
	it('charges the trust surface ONE penalty regardless of platform count (#637)', () => {
		const record = [
			'v=spf1',
			'include:spf.protection.outlook.com',
			'include:mail.zendesk.com',
			'include:_spf.salesforce.com',
			'include:servers.mcsv.net',
			'include:mktomail.com',
			'include:sendgrid.net',
			'~all',
		].join(' ');
		const context = { corroboratedByWeakDmarc: true, dmarcPolicy: 'quarantine', dmarcAlignmentMode: 'relaxed' };

		const findings = analyzeTrustSurface(record, context);
		expect(findings.filter((f) => f.metadata?.platformCount === undefined)).toHaveLength(6);
		expect(findings.filter((f) => f.severity !== 'info')).toHaveLength(1);

		// 100 − 25 (the single aggregate `high`), NOT 100 − 25 − 6 × 15 clamped to 0.
		expect(buildCheckResult('spf', findings).score).toBe(75);

		// And the count is what scales, not the number of penalties: two platforms cost the same
		// as six. A per-platform penalty reappearing would break this equality immediately.
		const twoPlatform = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com include:sendgrid.net ~all', context);
		expect(buildCheckResult('spf', twoPlatform).score).toBe(75);
	});
});

/**
 * #572 part 2 — the core now COUNTS unrecognized-but-broad shared senders.
 *
 * Previously the core recognised only cataloged platforms and emitted the aggregate at
 * `matchedPlatforms.length > 1`, while the worker copy (`src/tools/spf-trust-surface.ts`)
 * ALSO counted hosts matched by the generic `spf`/`_spf` heuristic. That split meant the
 * two copies disagreed on the ONE number that is actually scored — `platformCount`, and
 * whether the scored aggregate is emitted at all — so a domain delegating to one cataloged
 * ESP plus one uncataloged one was a 2-platform trust surface to the worker's output and a
 * 1-platform, un-aggregated one to every direct consumer of the published package
 * (bv-web-prod calls `checkSPF`, never the worker wrapper). The core adopts the heuristic
 * here, which is a SCORING change: the threshold-crossing case below starts emitting a
 * scored finding that the core did not emit before.
 *
 * These cases pin the counting semantics, not the prose: what counts, what does not, and
 * the exact point where the aggregate begins to fire.
 */
describe('core SPF trust-surface — unrecognized shared senders count (#572 part 2)', () => {
	it('emits a trust-surface finding for an uncataloged host carrying an spf label', () => {
		const findings = analyzeTrustSurface('v=spf1 include:spf.some-unknown-esp.example -all');

		expect(findings).toHaveLength(1);
		expect(findings[0].metadata?.trustSurface).toBe(true);
		// Named as the include host, never as a brand — the catalog is what names platforms.
		expect(findings[0].metadata?.platform).toBe('unrecognized shared sender');
		expect(findings[0].metadata?.recognized).toBe(false);
		expect(findings[0].metadata?.includeDomain).toBe('spf.some-unknown-esp.example');
		expect(findings[0].title).toContain('spf.some-unknown-esp.example');
		// A single delegation is never the scored aggregate.
		expect(findings[0].severity).toBe('info');
		expect(findings.some((f) => f.metadata?.platformCount !== undefined)).toBe(false);
	});

	it('matches the `_spf` and `spfNN` label forms, and the label anywhere in the host', () => {
		for (const host of ['_spf.some-esp.example', 'spf2.some-esp.example', 'eu._spf.some-esp.example']) {
			const findings = analyzeTrustSurface(`v=spf1 include:${host} -all`);
			expect(findings.map((f) => f.metadata?.includeDomain), `expected ${host} to be counted`).toEqual([host]);
		}
	});

	it('does NOT count a first-party sending host — the heuristic must not flag self-hosted mail', () => {
		// The whole point of keying on an `spf` label rather than "any external include":
		// `mail.mycompany.com` is the domain's own infrastructure, not a shared platform.
		const findings = analyzeTrustSurface('v=spf1 include:mail.mycompany.example include:relay.mycompany.example -all');

		expect(findings).toEqual([]);
	});

	/**
	 * THE THRESHOLD-CROSSING CASE, and the reason this change owes a
	 * `SCORING_MODEL_VERSION` bump.
	 *
	 * One cataloged platform + one uncataloged shared sender. Before part 2 the core saw
	 * `matchedPlatforms.length === 1` and emitted NO aggregate; now `delegated.length === 2`
	 * and the aggregate — the single scored trust-surface signal — fires. Under a
	 * corroborating DMARC posture that is a `high` (−25), so the `spf` category moves 100 → 75
	 * for this domain shape. This is the population that starts being charged.
	 */
	it('crosses the aggregate threshold on 1 recognized + 1 unrecognized sender', () => {
		const record = 'v=spf1 include:_spf.google.com include:spf.some-unknown-esp.example -all';

		const uncorroborated = analyzeTrustSurface(record);
		const aggregate = uncorroborated.find((f) => f.metadata?.platformCount !== undefined);
		expect(aggregate, 'the aggregate must now fire at one cataloged + one uncataloged sender').toBeDefined();
		expect(aggregate!.metadata?.platformCount).toBe(2);
		expect(aggregate!.title).toContain('2 shared platforms');
		// The uncataloged member is identified by host, with an explicit marker — a reader must
		// not be told the trust surface contains two NAMED platforms when one is anonymous.
		expect(aggregate!.metadata?.platforms).toBe('Google Workspace, spf.some-unknown-esp.example (unrecognized)');
		expect(aggregate!.detail).toContain('spf.some-unknown-esp.example (unrecognized)');

		// Severity/scoring consequence: info while nothing corroborates, `high` (−25) when
		// weak DMARC does — identical treatment to two cataloged platforms.
		expect(aggregate!.severity).toBe('info');
		expect(buildCheckResult('spf', uncorroborated).score).toBe(100);

		const corroborated = analyzeTrustSurface(record, {
			corroboratedByWeakDmarc: true,
			dmarcPolicy: 'none',
			dmarcAlignmentMode: 'relaxed',
		});
		expect(corroborated.find((f) => f.metadata?.platformCount !== undefined)!.severity).toBe('high');
		expect(buildCheckResult('spf', corroborated).score).toBe(75);
	});

	it('crosses the threshold on two unrecognized senders alone', () => {
		const findings = analyzeTrustSurface('v=spf1 include:spf.esp-one.example include:_spf.esp-two.example -all', {
			corroboratedByWeakDmarc: true,
			dmarcPolicy: 'none',
			dmarcAlignmentMode: 'relaxed',
		});

		const aggregate = findings.find((f) => f.metadata?.platformCount !== undefined);
		expect(aggregate!.metadata?.platformCount).toBe(2);
		expect(aggregate!.severity).toBe('high');
		// Still exactly ONE scored finding for the whole surface — #637's no-double-count rule
		// applies to unrecognized members too.
		expect(findings.filter((f) => f.severity !== 'info')).toHaveLength(1);
		expect(buildCheckResult('spf', findings).score).toBe(75);
	});

	it('counts a redirect= target, not just include:', () => {
		const findings = analyzeTrustSurface('v=spf1 include:_spf.google.com redirect=spf.some-unknown-esp.example');

		const aggregate = findings.find((f) => f.metadata?.platformCount !== undefined);
		expect(aggregate!.metadata?.platformCount).toBe(2);
	});

	it('prefers the catalog over the heuristic — a cataloged spf-labelled host is still NAMED', () => {
		// `_spf.google.com` matches the generic heuristic too. If the branch order ever
		// inverted, every spf-labelled catalog entry would silently degrade to the anonymous
		// sentinel while the counts stayed identical — invisible to a count-only assertion.
		const findings = analyzeTrustSurface('v=spf1 include:_spf.google.com -all');

		expect(findings).toHaveLength(1);
		expect(findings[0].metadata?.platform).toBe('Google Workspace');
		expect(findings[0].metadata?.recognized).toBeUndefined();
	});
});
