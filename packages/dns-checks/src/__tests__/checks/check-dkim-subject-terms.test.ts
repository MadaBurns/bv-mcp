// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-97 — DKIM subject-term redaction was untested AND invisible to the structural audit.
 *
 * `check-dkim.ts` attaches `[SUBJECT_TERMS_METADATA_KEY]: [result.selector]` to its
 * high/critical findings (the malformed-key, weak/legacy-RSA-key and SHA-1-only branches, plus
 * `answeredSelectors` on the absence finding) so a caller-controlled selector cannot arm
 * `MISSING_CONTROL_REGEX` and zero the `dkim` category — the same defect class as the
 * 2026-08-20 `missingkids.org` incident documented on `redactSubjectData` in
 * `scoring/model.ts`. `selector` is caller-controlled on the public MCP surface
 * (`src/schemas/tool-args.ts:76`, validated only by `DkimSelectorSchema`: any lowercase
 * alphanumeric-and-hyphen label up to 63 chars), so a selector can literally BE a trigger word
 * ("required", "missing") with no punctuation needed to smuggle it into the finding's prose.
 * No test exercised this until now, and `missing-control-intent.audit.test.ts`'s structural
 * enumeration could not see the declaration either (it uses a computed metadata key, which
 * that audit's parser silently dropped — fixed alongside this test).
 */

import { describe, expect, it } from 'vitest';
import { checkDKIM } from '../../checks/check-dkim';
import { findingsIndicateMissingControl, SUBJECT_TERMS_METADATA_KEY } from '../../scoring/model';
import type { DNSQueryFunction, Finding } from '../../types';

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return async (domain: string) => records[domain] ?? [];
}

describe('checkDKIM — subject-term redaction of a hostile selector (SQ-97)', () => {
	// A key with no recognisable DER header and < 150 base64 chars scores 'critical' / rsa /
	// ~512 bits per `analyzeKeyStrength` — the "Weak RSA key" high/critical finding.
	const weakKey = 'A'.repeat(100);
	// Valid per DkimSelectorSchema (`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, max 63) AND a bare
	// MISSING_CONTROL_REGEX trigger word — no delimiter needed, the whole selector IS the word.
	const hostileSelector = 'required';

	it('does not zero the dkim category when the selector itself supplies a missing-control trigger word', async () => {
		const queryDNS = createMockDNS({
			[`${hostileSelector}._domainkey.example.com`]: [`v=DKIM1; k=rsa; p=${weakKey}`],
		});

		const result = await checkDKIM('example.com', queryDNS, { selector: hostileSelector });

		const finding = result.findings.find((f) => f.title.includes('Weak RSA key'));
		expect(finding, 'expected a "Weak RSA key" finding for the short, header-less key').toBeDefined();
		expect(finding!.severity).toBe('critical');
		// Non-vacuity: prove the hostile selector really did land in the finding's own prose —
		// otherwise the assertions below could pass for a reason that has nothing to do with
		// redaction (e.g. the sentence never containing a trigger word in the first place).
		expect(`${finding!.title} ${finding!.detail}`).toMatch(/required/i);
		expect(finding!.metadata?.[SUBJECT_TERMS_METADATA_KEY]).toEqual([hostileSelector]);

		// A critical finding costs a 40-point penalty (100 → 60) on the merits. The category must
		// be scored on THAT, not forced to 0/failed because the selector's own text happens to
		// read as an assertion of absence.
		expect(result.score).toBe(60);
		expect(result.passed).toBe(true);
	});

	it('reasons through the revert: the identical finding WITHOUT the subjectTerms declaration would zero the category', () => {
		// The exact finding shape checkDKIM emits above, with the one `[SUBJECT_TERMS_METADATA_KEY]`
		// entry removed — precisely what deleting that metadata line from check-dkim.ts would
		// produce. This does not re-run a source revert (verify-discipline discourages that
		// without a ticket requirement); it demonstrates, through the same exported scoring
		// predicate the check itself relies on, that the sentence is genuinely dangerous on its
		// own and that the declaration — not some unrelated gate — is what disarms it.
		const withoutRedaction: Finding = {
			category: 'dkim',
			title: `Weak RSA key: ${hostileSelector}`,
			severity: 'critical',
			detail: `DKIM RSA key for "${hostileSelector}" is weak (~512 bits). Upgrade to 2048-bit RSA or use Ed25519 for better security.`,
		};
		expect(
			findingsIndicateMissingControl([withoutRedaction]),
			'the sentence must still be dangerous on its own, or the assertion above proves nothing',
		).toBe(true);

		const withRedaction: Finding = { ...withoutRedaction, metadata: { [SUBJECT_TERMS_METADATA_KEY]: [hostileSelector] } };
		expect(findingsIndicateMissingControl([withRedaction]), 'the declared redaction must disarm the identical sentence').toBe(false);
	});
});
