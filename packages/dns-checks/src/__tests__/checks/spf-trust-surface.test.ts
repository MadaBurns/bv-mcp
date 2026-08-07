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

	it('keeps the corroborated severities unchanged (medium per-platform, high summary)', () => {
		const findings = analyzeTrustSurface('v=spf1 include:_spf.google.com include:sendgrid.net -all', {
			corroboratedByWeakDmarc: true,
			dmarcPolicy: 'quarantine',
			dmarcAlignmentMode: 'relaxed',
		});

		expect(findings.filter((f) => f.severity === 'medium')).toHaveLength(2);
		expect(findings.filter((f) => f.severity === 'high')).toHaveLength(1);
	});
});

describe('core SPF trust-surface catalog — unrecognized senders (#572 part 2, PARKED)', () => {
	// The worker layer also counts unrecognized-but-broad shared senders toward the
	// trust-surface total (`src/tools/spf-trust-surface.ts`, the `unrecognized shared
	// sender` heuristic). The core deliberately does NOT — adopting it changes count
	// semantics corpus-wide and moves the `matchedPlatforms.length > 1` emission
	// threshold, so it is an operator call, not a config edit.
	//
	// TODO(operator decision): pin the CURRENT core semantics here, so that adopting
	// part 2 later has to break a test on purpose rather than drift silently.
	//
	// The trade-off to encode:
	//   - Assert the gap (e.g. one recognized + one unrecognized ESP yields exactly 1
	//     finding and no summary) → part 2 becomes a deliberate, reviewed change, but
	//     this file then asserts behavior we may consider a defect.
	//   - Leave it unasserted → the core stays free to converge on the worker heuristic
	//     without a test edit, at the cost of no tripwire on the divergence.
	//
	// A record that exercises the seam: 'v=spf1 include:_spf.google.com include:mail.some-esp.example -all'
	it.todo('pins whether unrecognized shared senders count toward the trust surface');
});
