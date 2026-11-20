// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { buildCheckResult, createFinding } from '../../scoring/model';
import type { CheckResult } from '../../scoring/model';
import { applySilentDomainDkimApplicability, mxDeclaresNoInboundMail, notApplicableMetadata } from '../../scoring/mail-applicability';

const NULL_MX = buildCheckResult('mx', [createFinding('mx', 'Null MX record (RFC 7505)', 'info', 'Domain declares it accepts no email.')], false);
const REAL_MX = buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX records.')], true);
const NO_SEND_SPF = buildCheckResult('spf', [
	createFinding('spf', 'SPF no-send policy', 'info', 'v=spf1 -all authorizes no sender.', { noSendPolicy: true }),
]);
const SENDING_SPF = buildCheckResult('spf', [createFinding('spf', 'SPF record valid', 'info', 'v=spf1 include:_spf.example.net -all')]);

function revokedDkim(): CheckResult {
	return buildCheckResult(
		'dkim',
		[
			createFinding('dkim', 'DKIM keys revoked', 'high', 'Every selector found has an empty p= tag.', { missingControl: true }),
			createFinding('dkim', 'Revoked DKIM key: selector1', 'high', 'selector1 has an empty p= tag.'),
			createFinding('dkim', 'DKIM key record has no public key: selector2', 'critical', 'selector2 publishes no p= tag.'),
		],
		false,
		true,
		{ selectorsFound: 2 },
	);
}

function dkimOf(results: CheckResult[]): CheckResult {
	const dkim = results.find((result) => result.category === 'dkim');
	if (!dkim) throw new Error('no dkim result');
	return dkim;
}

describe('applySilentDomainDkimApplicability', () => {
	it('downgrades revoked and keyless DKIM findings to info on a domain that neither sends nor receives mail', () => {
		const dkim = dkimOf(applySilentDomainDkimApplicability([NULL_MX, NO_SEND_SPF, revokedDkim()]));

		expect(dkim.findings.map((finding) => finding.severity)).toEqual(['info', 'info', 'info']);
		for (const finding of dkim.findings) {
			expect(finding.detail).toContain(
				'(expected — null MX and an SPF policy that authorizes no sender mean this domain neither sends nor receives mail, so revoked DKIM keys are the correct posture)',
			);
		}
		// A declared missing control is retracted with the downgrade, so the prose and the score agree.
		expect(dkim.findings[0].metadata?.missingControl).toBe(false);
		expect(dkim.passed).toBe(true);
		// What the probe observed is carried through the rebuild.
		expect(dkim.controlPresent).toBe(false);
		expect(dkim.recordPresent).toBe(true);
		expect(dkim.metadata).toEqual({ selectorsFound: 2 });
	});

	it('control: a domain that receives mail keeps the findings at their original severity', () => {
		const input = [REAL_MX, NO_SEND_SPF, revokedDkim()];
		expect(applySilentDomainDkimApplicability(input)).toEqual(input);
	});

	it('control: a null-MX domain whose SPF still authorizes a sender keeps the findings', () => {
		const input = [NULL_MX, SENDING_SPF, revokedDkim()];
		expect(applySilentDomainDkimApplicability(input)).toEqual(input);
	});

	it('control: no SPF result at all is not a no-send declaration', () => {
		const input = [NULL_MX, revokedDkim()];
		expect(applySilentDomainDkimApplicability(input)).toEqual(input);
	});

	it('does not claim "no mail" from an MX check that did not complete', () => {
		const unmeasuredMx: CheckResult = { ...NULL_MX, checkStatus: 'error' };
		const input = [unmeasuredMx, NO_SEND_SPF, revokedDkim()];
		expect(applySilentDomainDkimApplicability(input)).toEqual(input);
	});

	it('returns an abstained DKIM result untouched, never rebuilding it into a pass', () => {
		const abstained: CheckResult = { ...revokedDkim(), score: 0, passed: false, partial: true, checkStatus: 'error' };
		const dkim = dkimOf(applySilentDomainDkimApplicability([NULL_MX, NO_SEND_SPF, abstained]));
		expect(dkim).toBe(abstained);
	});

	it('leaves a usable but weak key at its rating: a factorable key can still forge mail', () => {
		const weak = buildCheckResult('dkim', [createFinding('dkim', 'Weak DKIM key: selector1 (1024-bit RSA)', 'high', 'Key is 1024 bits.')], true, true);
		const dkim = dkimOf(applySilentDomainDkimApplicability([NULL_MX, NO_SEND_SPF, weak]));
		expect(dkim.findings[0].severity).toBe('high');
		expect(dkim.findings[0].detail).toBe('Key is 1024 bits.');
	});

	it('touches no category other than dkim', () => {
		const output = applySilentDomainDkimApplicability([NULL_MX, NO_SEND_SPF, revokedDkim()]);
		expect(output[0]).toBe(NULL_MX);
		expect(output[1]).toBe(NO_SEND_SPF);
	});
});

describe('mxDeclaresNoInboundMail', () => {
	it('reads the structural signal: false control means no inbound mail, true means mail', () => {
		expect(mxDeclaresNoInboundMail(NULL_MX)).toBe(true);
		expect(mxDeclaresNoInboundMail(REAL_MX)).toBe(false);
		expect(mxDeclaresNoInboundMail(undefined)).toBe(false);
	});

	it('makes no claim from an incomplete probe', () => {
		expect(mxDeclaresNoInboundMail({ ...NULL_MX, checkStatus: 'timeout' })).toBe(false);
	});

	it('falls back to the legacy titles only when the structural signal is absent', () => {
		const legacy = buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'No MX.')]);
		expect(legacy.controlPresent).toBeUndefined();
		expect(mxDeclaresNoInboundMail(legacy)).toBe(true);
	});
});

describe('notApplicableMetadata', () => {
	it('retracts a declared missing control and leaves undeclared findings unpatched', () => {
		const declared = createFinding('dkim', 'DKIM keys revoked', 'high', 'x', { missingControl: true, selector: 's1' });
		expect(notApplicableMetadata(declared)).toEqual({ metadata: { ...declared.metadata, missingControl: false } });
		expect(notApplicableMetadata(createFinding('dkim', 'Revoked DKIM key: s1', 'high', 'x'))).toEqual({});
	});
});
