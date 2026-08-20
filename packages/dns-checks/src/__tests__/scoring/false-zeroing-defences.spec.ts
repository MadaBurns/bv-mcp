import { describe, expect, it } from 'vitest';
import { buildCheckResult, createFinding, scoreIndicatesMissingControl } from '../../scoring/model.js';

/**
 * Guards the defence this change actually ships: `redactSubjectData` stops trigger words
 * that arrive as INTERPOLATED SUBJECT DATA — the scanned domain, an MX host, a policy URL
 * derived from the domain — from arming `MISSING_CONTROL_REGEX` and zeroing a category.
 *
 * Every "does not arm" assertion is paired with a known-bad control, because a redaction
 * bug that simply stops zeroing everything would otherwise turn this file green.
 *
 * ⚠️ SCOPE: redaction cannot help a trigger word in AUTHORED prose. Four RFC-conformance
 * findings in `checks/mta-sts-analysis.ts` ("MTA-STS policy missing max_age", "required by
 * RFC 8461") do zero their category at `high` even though the policy file was fetched and
 * parsed. That is deliberate and out of scope here — an RFC-invalid policy is inert, so a
 * failing category is defensible. See `test/check-mta-sts.spec.ts`
 * "DEPLOYED-BUT-BROKEN policy still penalises confidently".
 */
describe('redaction stops subject data from zeroing a category', () => {
	describe('control: the gate still arms when it should', () => {
		it('arms on authored absence prose at high severity', () => {
			const f = createFinding('mta_sts', 'MTA-STS policy not found', 'high', 'No MTA-STS policy record was published for this domain.', {
				confidence: 'deterministic',
			});
			expect(scoreIndicatesMissingControl([f])).toBe(true);
			expect(buildCheckResult('mta_sts', [f]).score).toBe(0);
		});

		it('arms even when the finding also carries a penaltyOverride', () => {
			const f = createFinding('mta_sts', 'MTA-STS policy not found', 'high', 'No MTA-STS policy record was published for this domain.', {
				confidence: 'deterministic',
				penaltyOverride: 15,
			});
			expect(scoreIndicatesMissingControl([f])).toBe(true);
		});
	});

	describe('subject data is projected out before the regex sees it', () => {
		it('does not arm when "missing" comes only from the interpolated policy URL', () => {
			const detail = 'MTA-STS policy file at https://mta-sts.missingkids.org/.well-known/mta-sts.txt does not contain a valid "mode:" directive.';
			const f = createFinding('mta_sts', 'MTA-STS policy invalid', 'high', detail, { confidence: 'deterministic' });
			expect(scoreIndicatesMissingControl([f])).toBe(false);
			expect(buildCheckResult('mta_sts', [f]).score).toBeGreaterThan(0);
		});

		it('does not arm when "missing" comes only from a bare interpolated MX hostname', () => {
			const detail = 'The MX host mail.missingkids.org is not matched by any mx: entry in the MTA-STS policy.';
			const f = createFinding('mta_sts', 'MTA-STS policy does not cover MX host mail.missingkids.org', 'high', detail, {
				confidence: 'deterministic',
			});
			expect(scoreIndicatesMissingControl([f])).toBe(false);
		});

		it('two domains differing only in name score identically', () => {
			const build = (domain: string) =>
				buildCheckResult('mta_sts', [
					createFinding('mta_sts', 'MTA-STS policy invalid', 'high', `MTA-STS policy file at https://mta-sts.${domain}/.well-known/mta-sts.txt is malformed.`, {
						confidence: 'deterministic',
					}),
				]);
			// The production symptom: byte-identical findings, different scores, purely
			// because one domain's NAME supplied a trigger word.
			expect(build('missingkids.org').score).toBe(build('example.com').score);
			expect(build('missingkids.org').passed).toBe(build('example.com').passed);
		});
	});
});
