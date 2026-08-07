import { describe, it, expect } from 'vitest';
import { computeMaturityStage, capMaturityStage, type MaturityStage } from '../src/tools/scan/maturity-staging';
import { buildCheckResult, createFinding } from '../src/lib/scoring';
import type { CheckResult } from '../src/lib/scoring';

describe('computeMaturityStage', () => {
	it('returns Stage 0 when no SPF and no DMARC', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'No SPF record found', 'critical', 'Missing SPF')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'No DMARC record found', 'critical', 'Missing DMARC')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(0);
		expect(stage.label).toBe('Unprotected');
		expect(stage.nextStep).toContain('Publish SPF');
	});

	it('returns Stage 1 when SPF exists and DMARC p=none with no rua=', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [
				createFinding('dmarc', 'DMARC policy set to none', 'high', 'Policy is none'),
				createFinding('dmarc', 'No aggregate reporting', 'medium', 'No rua='),
			]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(1);
		expect(stage.label).toBe('Basic');
		expect(stage.nextStep).toContain('aggregate reporting');
	});

	it('returns Stage 2 when SPF exists and DMARC p=none with rua=', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy set to none', 'high', 'Policy is none')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(2);
		expect(stage.label).toBe('Monitoring');
		expect(stage.nextStep).toContain('p=quarantine');
	});

	it('returns Stage 3 when SPF + DKIM + DMARC p=reject', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'Found selectors')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(3);
		expect(stage.label).toBe('Enforcing');
		expect(stage.nextStep).toContain('MTA-STS');
	});

	it('returns Stage 4 when SPF + DKIM + DMARC p=reject + MTA-STS + DNSSEC', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'Found selectors')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
			buildCheckResult('mta_sts', [createFinding('mta_sts', 'MTA-STS configured', 'info', 'ok')]),
			buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(4);
		expect(stage.label).toBe('Hardened');
		expect(stage.nextStep).toBe('');
	});

	it('returns Stage 4 when SPF + DKIM + DMARC p=quarantine + BIMI + DNSSEC', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'Found selectors')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy set to quarantine', 'low', 'Policy is quarantine')]),
			buildCheckResult('bimi', [createFinding('bimi', 'BIMI record configured', 'info', 'BIMI valid')]),
			buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(4);
		expect(stage.label).toBe('Hardened');
	});

	it('returns Stage 2 when DMARC p=none with rua= (DKIM absence does not block Stage 2)', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'No DKIM records found among tested selectors', 'high', 'Missing DKIM')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy set to none', 'high', 'Policy is none')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(2);
		expect(stage.label).toBe('Monitoring');
	});

	it('returns Stage 0 when checks array is empty', () => {
		const stage = computeMaturityStage([]);
		expect(stage.stage).toBe(0);
		expect(stage.label).toBe('Unprotected');
	});

	it('returns Unprotected for non-mail domain without DNSSEC', () => {
		const checks: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'Domain has no MX')]),
			buildCheckResult('spf', [createFinding('spf', 'No SPF record found', 'critical', 'Missing SPF')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'No DMARC record found', 'critical', 'Missing DMARC')]),
			{ category: 'dnssec', passed: false, score: 0, findings: [createFinding('dnssec', 'No DNSKEY records', 'high', 'No DNSSEC')] },
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(0);
		expect(stage.label).toBe('Unprotected');
		expect(stage.description).toContain('does not accept email');
		expect(stage.nextStep).toContain('DNSSEC');
	});

	it('returns DNS-Only for non-mail domain with DNSSEC', () => {
		const checks: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'Domain has no MX')]),
			buildCheckResult('spf', [createFinding('spf', 'No SPF record found', 'critical', 'Missing SPF')]),
			buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(1);
		expect(stage.label).toBe('DNS-Only');
		expect(stage.description).toContain('does not accept email');
		expect(stage.description).toContain('DNSSEC');
		expect(stage.nextStep).toBe('');
	});

	it('does not short-circuit to non-mail path when MX records exist', () => {
		const checks: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX records')]),
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'Found selectors')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(3);
		expect(stage.label).toBe('Enforcing');
	});
});

describe('maturity staging v2', () => {
	it('Stage 3 does not require DKIM discovery', () => {
		// SPF + DMARC p=reject, but DKIM not found — should still be Stage 3
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'No DKIM records found among tested selectors', 'high', 'No DKIM')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(3);
		expect(stage.label).toBe('Enforcing');
	});

	it('Stage 1 is specifically DMARC p=none without rua', () => {
		// SPF present, DMARC p=none, no rua — Stage 1
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [
				createFinding('dmarc', 'DMARC policy set to none', 'high', 'Policy is none'),
				createFinding('dmarc', 'No aggregate reporting', 'medium', 'No rua='),
			]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(1);
		expect(stage.label).toBe('Basic');
	});

	it('SPF + DMARC p=none without rua= falls to Stage 1 (not Stage 2)', () => {
		// Stage 2 requires p=none WITH rua=; without rua= it falls to Stage 1
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [
				createFinding('dmarc', 'DMARC policy set to none', 'high', 'Policy is none'),
				createFinding('dmarc', 'No aggregate reporting', 'medium', 'No rua='),
			]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(1);
		expect(stage.label).toBe('Basic');
	});

	it('Stage 4 accepts CAA as hardening signal', () => {
		// SPF + DMARC p=reject + DNSSEC + CAA passed — 2 hardening signals
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
			buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')]),
			{ category: 'caa', passed: true, score: 100, findings: [createFinding('caa', 'CAA records found', 'info', 'ok')] },
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(4);
		expect(stage.label).toBe('Hardened');
	});

	it('Stage 4 accepts DKIM discovered as hardening signal', () => {
		// SPF + DMARC p=reject + DKIM found (selectorsFound) + MTA-STS — 2 hardening signals
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM configured', 'info', 'Found selectors', { selectorsFound: ['google', 'selector2'] }),
			]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
			buildCheckResult('mta_sts', [createFinding('mta_sts', 'MTA-STS configured', 'info', 'ok')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(4);
		expect(stage.label).toBe('Hardened');
	});

	it('provider-implied DKIM does NOT count as discovered for Stage 4', () => {
		// SPF + DMARC p=reject + provider-implied DKIM + MTA-STS
		// provider-implied DKIM is only 1 real hardening signal (MTA-STS), need 2 for Stage 4
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM selector not discovered', 'medium', 'Provider-implied', { detectionMethod: 'provider-implied' }),
			]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
			buildCheckResult('mta_sts', [createFinding('mta_sts', 'MTA-STS configured', 'info', 'ok')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(3); // Only 1 hardening signal (MTA-STS), need 2
	});
});

describe('capMaturityStage', () => {
	const stage4: MaturityStage = {
		stage: 4,
		label: 'Hardened',
		description: 'Comprehensive email and DNS security posture with defense in depth.',
		nextStep: '',
	};

	const stage3: MaturityStage = {
		stage: 3,
		label: 'Enforcing',
		description: 'Email authentication is actively enforcing — spoofed emails are blocked or quarantined.',
		nextStep: 'Add MTA-STS, DNSSEC, and BIMI to reach full hardening.',
	};

	const stage2: MaturityStage = {
		stage: 2,
		label: 'Monitoring',
		description: 'Email authentication is published and being monitored but not enforcing.',
		nextStep: 'After reviewing DMARC reports, move to p=quarantine and ensure DKIM is active.',
	};

	const stage1: MaturityStage = {
		stage: 1,
		label: 'Basic',
		description: 'Basic email records exist but are not enforcing or monitoring.',
		nextStep: 'Add DMARC aggregate reporting (rua=) and monitor for 2-4 weeks before enforcing.',
	};

	it('caps Stage 4 to Stage 2 when the displayed grade is F (score 49)', () => {
		const result = capMaturityStage(stage4, 49);
		expect(result.stage).toBe(2);
		expect(result.label).not.toBe('Hardened');
		expect(result.nextStep).toBeTruthy(); // should have guidance
	});

	it('caps Stage 3 to Stage 2 when the displayed grade is F (score 30)', () => {
		const result = capMaturityStage(stage3, 30);
		expect(result.stage).toBe(2);
		expect(result.label).not.toBe('Enforcing');
	});

	// #640: 55 displays as NIST F (the canonical 9-band would call it D). The cap
	// follows the DISPLAYED band, so this is stage 2, not stage 3.
	it('caps Stage 4 to Stage 2 when score is 55 (NIST F, canonical D)', () => {
		const result = capMaturityStage(stage4, 55);
		expect(result.stage).toBe(2);
		expect(result.label).not.toBe('Hardened');
		expect(result.nextStep).toBeTruthy();
	});

	it('caps Stage 4 to Stage 2 when score is exactly 50 (NIST F)', () => {
		const result = capMaturityStage(stage4, 50);
		expect(result.stage).toBe(2);
		expect(result.label).not.toBe('Hardened');
	});

	it('caps Stage 4 to Stage 3 at the bottom of the displayed D band (score 60)', () => {
		const result = capMaturityStage(stage4, 60);
		expect(result.stage).toBe(3);
		expect(result.label).toBe('Enforcing (score-capped)');
	});

	// #640 regression, verbatim from the issue: github.com scored 67 → displayed
	// grade D, yet the canonical 9-band read C so no cap fired and the report
	// printed "D" next to "Stage 4 — Hardened".
	it('#640 caps Stage 4 to Stage 3 at score 67 (github.com — NIST D, canonical C)', () => {
		const result = capMaturityStage(stage4, 67);
		expect(result.stage).toBe(3);
		expect(result.label).toBe('Enforcing (score-capped)');
		expect(result.label).not.toContain('Hardened');
	});

	it('does NOT cap Stage 4 at score 70 (first displayed C)', () => {
		const result = capMaturityStage(stage4, 70);
		expect(result.stage).toBe(4);
		expect(result.label).toBe('Hardened');
	});

	it('does NOT cap Stage 4 when score is high', () => {
		const result = capMaturityStage(stage4, 92);
		expect(result.stage).toBe(4);
		expect(result.label).toBe('Hardened');
	});

	it('does not modify Stage 2 when the displayed grade is F (already at cap)', () => {
		const result = capMaturityStage(stage2, 40);
		expect(result.stage).toBe(2);
		expect(result.label).toBe('Monitoring');
		expect(result.description).toBe(stage2.description); // unchanged
	});

	it('does not modify Stage 1 when the displayed grade is F (below cap)', () => {
		const result = capMaturityStage(stage1, 20);
		expect(result.stage).toBe(1);
		expect(result.label).toBe('Basic');
		expect(result.description).toBe(stage1.description); // unchanged
	});

	it('does not modify Stage 3 when the displayed grade is D (already at cap)', () => {
		const result = capMaturityStage(stage3, 65);
		expect(result.stage).toBe(3);
		expect(result.label).toBe('Enforcing');
		expect(result.description).toBe(stage3.description); // unchanged
	});

	// #640 follow-up — a capped web_only/non_mail domain used to be handed the MAIL
	// ladder's words. "Enforcing" is a claim about DMARC enforcement; a domain that
	// accepts no mail is not graded on email authentication at all, so the label was
	// factually wrong, not merely off-vocabulary.
	it('words a capped web_only stage in the WEB ladder, not the mail ladder', () => {
		const capped = capMaturityStage(stage4, 67, 'web_only');
		expect(capped.stage).toBe(3);
		expect(capped.label).toBe('Defensive (score-capped)');
		expect(capped.label).not.toContain('Enforcing');
	});

	it('words a capped non_mail stage in the WEB ladder too', () => {
		const capped = capMaturityStage(stage4, 40, 'non_mail');
		expect(capped.stage).toBe(2);
		expect(capped.label).toBe('Transport-Hardened (score-capped)');
		expect(capped.label).not.toContain('Monitoring');
	});

	it('keeps the MAIL ladder wording for mail profiles and for an omitted profile', () => {
		expect(capMaturityStage(stage4, 67, 'mail_enabled').label).toBe('Enforcing (score-capped)');
		expect(capMaturityStage(stage4, 40, 'mail_enabled').label).toBe('Monitoring (score-capped)');
		// Back-compat: no profile argument === the pre-#640 mail wording.
		expect(capMaturityStage(stage4, 67).label).toBe('Enforcing (score-capped)');
		expect(capMaturityStage(stage4, 40).label).toBe('Monitoring (score-capped)');
	});

	it('keeps the "(score-capped)" suffix on every ladder so the stage reads as imposed, not earned', () => {
		for (const profile of ['mail_enabled', 'web_only', 'non_mail', undefined] as const) {
			expect(capMaturityStage(stage4, 40, profile).label).toContain('(score-capped)');
			expect(capMaturityStage(stage4, 67, profile).label).toContain('(score-capped)');
		}
	});

	it('leaves an indeterminate stage untouched regardless of score', () => {
		const indeterminate: MaturityStage = {
			stage: 0,
			indeterminate: true,
			label: 'Not determined (TLS not measured)',
			description: 'x',
			nextStep: 'y',
		};
		for (const score of [0, 49, 55, 67, 95]) {
			const result = capMaturityStage(indeterminate, score);
			expect(result).toEqual(indeterminate);
		}
	});
});

/**
 * #640 — the report prints the customer-facing NIST 6-band letter next to the
 * maturity label. Those two are derived independently, so nothing structural
 * stopped them contradicting each other ("grade D" beside "Stage 4 — Hardened")
 * until `capMaturityStage` was moved onto the DISPLAYED scale.
 *
 * Two invariants are pinned here, over every integer score 0-100 × every raw
 * stage × every profile (i.e. BOTH ladders):
 *
 * 1. NUMERIC — the stage can never contradict the letter beside it:
 *      displayed F  ⇒ capped stage <= 2
 *      displayed D  ⇒ capped stage <= 3
 *      displayed C+ ⇒ uncapped, returned untouched
 *    and the cap only ever LOWERS a stage, never raises one.
 *
 * 2. VOCABULARY — a capped stage's label must be the label the SAME ladder
 *    would have used for that stage on its own. The expected label is not a
 *    literal here: it is read back out of `computeMaturityStage` by feeding it a
 *    fixture that genuinely lands on that stage. So if a ladder's wording is
 *    ever changed without the cap following, this fails — which is the tripwire
 *    that stops "Enforcing (score-capped)" reappearing on a domain that accepts
 *    no mail.
 */
describe('#640 grade/maturity reconciliation invariant', () => {
	const RAW_STAGES: MaturityStage[] = [
		{ stage: 0, label: 'Unprotected', description: '', nextStep: '' },
		{ stage: 1, label: 'Basic', description: '', nextStep: '' },
		{ stage: 2, label: 'Monitoring', description: '', nextStep: '' },
		{ stage: 3, label: 'Enforcing', description: '', nextStep: '' },
		{ stage: 4, label: 'Hardened', description: '', nextStep: '' },
		// web_only ladder's top rung — same numeric stage, different wording.
		{ stage: 4, label: 'Comprehensive', description: '', nextStep: '' },
	];

	/**
	 * Every profile, grouped by the ladder it selects. `undefined` is the legacy
	 * caller shape and must keep behaving as mail.
	 */
	const PROFILES = [undefined, 'mail_enabled', 'enterprise_mail', 'minimal', 'authoritative_dns_infra', 'web_only', 'non_mail'] as const;

	// --- Fixtures that land a ladder on exactly the stages the cap can emit (2, 3) ---

	/** mail ladder → Stage 3: SPF + DMARC p=reject, but no transport/integrity hardening. */
	function mailStage3(): CheckResult[] {
		return [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		];
	}

	/** mail ladder → Stage 2: SPF + DMARC p=none with aggregate reporting. */
	function mailStage2(): CheckResult[] {
		return [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy set to none', 'high', 'p=none, rua present')]),
		];
	}

	/** web ladder → Stage 3: SSL + DNSSEC + anti-spoof SPF, no HSTS. */
	function webStage3(): CheckResult[] {
		return [
			buildCheckResult('ssl', [createFinding('ssl', 'SSL certificate valid', 'info', 'ok')]),
			buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')]),
			buildCheckResult('spf', [createFinding('spf', 'SPF record found', 'info', 'v=spf1 -all')]),
		];
	}

	/** web ladder → Stage 2: SSL + DNSSEC only (no anti-spoof policy). */
	function webStage2(): CheckResult[] {
		return [
			buildCheckResult('ssl', [createFinding('ssl', 'SSL certificate valid', 'info', 'ok')]),
			buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')]),
		];
	}

	const FIXTURES = {
		mail: { 2: mailStage2, 3: mailStage3 },
		web_only: { 2: webStage2, 3: webStage3 },
	} as const;

	/**
	 * The label the ladder ITSELF produces at `stage` for `profile` — observed, not
	 * asserted from a literal. This is what makes the vocabulary invariant a real
	 * tripwire rather than a restatement of the implementation's lookup table.
	 */
	function observedLadderLabel(profile: (typeof PROFILES)[number], stage: 2 | 3): string {
		const ladder = profile === 'web_only' || profile === 'non_mail' ? 'web_only' : 'mail';
		const observed = computeMaturityStage(FIXTURES[ladder][stage](), profile);
		// Fixture sanity: if this drifts, the expectation below is meaningless.
		expect(observed.stage, `fixture for ${ladder} stage ${stage} landed on ${observed.stage}`).toBe(stage);
		expect(observed.indeterminate).toBeUndefined();
		return observed.label;
	}

	/** Max stage a given DISPLAYED band may present. */
	function ceilingFor(grade: string): number {
		if (grade === 'F') return 2;
		if (grade === 'D') return 3;
		return 4;
	}

	it('the ladder fixtures really do land on the stages the cap can emit', () => {
		expect(observedLadderLabel('mail_enabled', 2)).toBe('Monitoring');
		expect(observedLadderLabel('mail_enabled', 3)).toBe('Enforcing');
		expect(observedLadderLabel('web_only', 2)).toBe('Transport-Hardened');
		expect(observedLadderLabel('web_only', 3)).toBe('Defensive');
	});

	it('no score can display a grade that contradicts the maturity stage it is rendered beside — both ladders', async () => {
		const { nistScoreToGrade } = await import('../src/lib/scoring');

		for (const profile of PROFILES) {
			// Resolve the two ladder labels once per profile (running a ladder 101x6x7
			// times would be pure waste).
			const ladderLabel: Record<2 | 3, string> = {
				2: observedLadderLabel(profile, 2),
				3: observedLadderLabel(profile, 3),
			};

			for (let score = 0; score <= 100; score++) {
				const displayed = nistScoreToGrade(score);
				const ceiling = ceilingFor(displayed);

				for (const raw of RAW_STAGES) {
					const capped = capMaturityStage(raw, score, profile);
					const where = `profile ${profile ?? '(none)'} score ${score} (grade ${displayed}) raw stage ${raw.stage}`;

					// (1) NUMERIC invariant.
					expect(capped.stage, `${where} exceeded ceiling ${ceiling}`).toBeLessThanOrEqual(ceiling);
					expect(capped.stage, `${where} was RAISED by the cap`).toBeLessThanOrEqual(raw.stage);

					if (capped.stage === raw.stage) {
						expect(capped, `${where} was rewritten without being capped`).toEqual(raw);
						continue;
					}

					// (2) VOCABULARY invariant — the capped label is this ladder's own word
					// for the capped stage, plus the suffix marking it as imposed.
					const stage = capped.stage as 2 | 3;
					expect(capped.label, `${where} was worded by the wrong ladder`).toBe(`${ladderLabel[stage]} (score-capped)`);
					expect(capped.label, `${where} lost the score-capped marker`).toContain('(score-capped)');

					// The top-rung WORDS must not survive a D or F letter either — the
					// contradiction the customer sees is textual, not numeric.
					expect(capped.label).not.toMatch(/^(Hardened|Comprehensive)/);
				}
			}
		}
	});

	it('a passing displayed grade (C and better) never has its stage lowered, on any profile', async () => {
		const { nistScoreToGrade } = await import('../src/lib/scoring');

		for (let score = 70; score <= 100; score++) {
			expect(nistScoreToGrade(score)).not.toBe('D');
			for (const profile of PROFILES) {
				for (const raw of RAW_STAGES) {
					expect(capMaturityStage(raw, score, profile)).toEqual(raw);
				}
			}
		}
	});

	it('a capped stage never borrows the OTHER ladder vocabulary', () => {
		const MAIL_WORDS = ['Monitoring', 'Enforcing', 'Hardened'];
		const WEB_WORDS = ['Transport-Hardened', 'Defensive', 'Comprehensive'];
		const stage4: MaturityStage = { stage: 4, label: 'Hardened', description: '', nextStep: '' };

		for (const score of [30, 55, 59, 60, 67]) {
			const web = capMaturityStage(stage4, score, 'web_only').label;
			// 'Transport-Hardened' legitimately contains 'Hardened' — match on the
			// standalone mail word only.
			for (const word of MAIL_WORDS) expect(web).not.toMatch(new RegExp(`(^|\\s)${word}\\b`));

			const mail = capMaturityStage(stage4, score, 'mail_enabled').label;
			for (const word of WEB_WORDS) expect(mail).not.toContain(word);
		}
	});
});
