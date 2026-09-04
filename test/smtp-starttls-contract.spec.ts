// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';

const VALID_RESULT = {
	schemaVersion: '1.0',
	probe: 'smtp_starttls',
	domain: 'example.com',
	status: 'measured',
	outcome: 'starttls_available',
	observedAt: '2026-09-05T00:00:00.000Z',
	nonScoring: true,
	targets: [
		{
			target: { exchange: 'mx.example.com', preference: 10, address: '1.1.1.1', port: 25, tlsServerName: 'mx.example.com' },
			status: 'measured',
			phase: 'quit',
			starttlsAdvertised: true,
			tlsNegotiated: true,
			postTlsEhloAccepted: true,
			tls: { protocol: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256', peerNameValid: true },
		},
	],
} as const;

const FAILED_TARGET = {
	...VALID_RESULT.targets[0],
	target: { exchange: 'mx-fail.example.com', preference: 20, address: '8.8.8.8', port: 25, tlsServerName: 'mx-fail.example.com' },
	starttlsAdvertised: false,
	tlsNegotiated: false,
	postTlsEhloAccepted: false,
	tls: undefined,
	reason: 'starttls_not_advertised',
} as const;

const INCOMPLETE_TARGET = {
	target: { exchange: 'mx-pending.example.com', preference: 30, address: '9.9.9.9', port: 25, tlsServerName: 'mx-pending.example.com' },
	status: 'not-assessed',
	phase: 'connect',
	reason: 'connection_failed',
} as const;

describe('SMTP STARTTLS result contract', () => {
	it('accepts a bounded non-scoring measurement', async () => {
		const { SmtpStarttlsResultSchema } = await import('../src/schemas/smtp-starttls');
		expect(SmtpStarttlsResultSchema.parse(VALID_RESULT)).toEqual(VALID_RESULT);
	});

	it('forbids transcript material and unknown nested fields', async () => {
		const { SmtpStarttlsResultSchema } = await import('../src/schemas/smtp-starttls');
		expect(SmtpStarttlsResultSchema.safeParse({ ...VALID_RESULT, transcript: ['220 ready'] }).success).toBe(false);
		expect(
			SmtpStarttlsResultSchema.safeParse({
				...VALID_RESULT,
				targets: [{ ...VALID_RESULT.targets[0], rawReply: '250 STARTTLS' }],
			}).success,
		).toBe(false);
	});

	it('caps aggregate target results at three and fixes every target to port 25', async () => {
		const { SmtpStarttlsResultSchema } = await import('../src/schemas/smtp-starttls');
		expect(SmtpStarttlsResultSchema.safeParse({ ...VALID_RESULT, targets: Array(4).fill(VALID_RESULT.targets[0]) }).success).toBe(false);
		expect(
			SmtpStarttlsResultSchema.safeParse({
				...VALID_RESULT,
				targets: [{ ...VALID_RESULT.targets[0], target: { ...VALID_RESULT.targets[0].target, port: 587 } }],
			}).success,
		).toBe(false);
		for (const address of ['10.0.0.1', '::ffff:127.0.0.1', '2606:4700:4700::1111', '010.0.0.1']) {
			expect(
				SmtpStarttlsResultSchema.safeParse({
					...VALID_RESULT,
					targets: [{ ...VALID_RESULT.targets[0], target: { ...VALID_RESULT.targets[0].target, address } }],
				}).success,
			).toBe(false);
		}
	});

	it('rejects contradictory status, outcome, and target combinations', async () => {
		const { SmtpStarttlsResultSchema } = await import('../src/schemas/smtp-starttls');
		expect(SmtpStarttlsResultSchema.safeParse({ ...VALID_RESULT, status: 'not-assessed' }).success).toBe(false);
		expect(SmtpStarttlsResultSchema.safeParse({ ...VALID_RESULT, targets: [] }).success).toBe(false);
		expect(SmtpStarttlsResultSchema.safeParse({ ...VALID_RESULT, outcome: 'null_mx' }).success).toBe(false);
		expect(
			SmtpStarttlsResultSchema.safeParse({
				...VALID_RESULT,
				targets: [{ ...VALID_RESULT.targets[0], tlsNegotiated: false }],
			}).success,
		).toBe(false);
		expect(
			SmtpStarttlsResultSchema.safeParse({
				...VALID_RESULT,
				targets: [{ ...VALID_RESULT.targets[0], starttlsAdvertised: undefined }],
			}).success,
		).toBe(false);
	});

	it('accepts partial mixed only for genuinely mixed measurements or explicit incomplete evidence', async () => {
		const { SmtpStarttlsResultSchema } = await import('../src/schemas/smtp-starttls');
		const partial = { ...VALID_RESULT, status: 'partial', outcome: 'mixed' } as const;

		expect(SmtpStarttlsResultSchema.safeParse({ ...partial, targets: [VALID_RESULT.targets[0], FAILED_TARGET] }).success).toBe(true);
		expect(SmtpStarttlsResultSchema.safeParse({ ...partial, targets: [VALID_RESULT.targets[0], INCOMPLETE_TARGET] }).success).toBe(true);
		expect(SmtpStarttlsResultSchema.safeParse({ ...partial, targets: [VALID_RESULT.targets[0]] }).success).toBe(false);
		expect(SmtpStarttlsResultSchema.safeParse({ ...partial, targets: [FAILED_TARGET] }).success).toBe(false);
	});

	it('rejects uniform partial outcomes with incomplete or contradictory target evidence', async () => {
		const { SmtpStarttlsResultSchema } = await import('../src/schemas/smtp-starttls');
		const partial = { ...VALID_RESULT, status: 'partial' } as const;

		for (const candidate of [
			{ ...partial, outcome: 'starttls_available', targets: [VALID_RESULT.targets[0], INCOMPLETE_TARGET] },
			{ ...partial, outcome: 'starttls_available', targets: [VALID_RESULT.targets[0], FAILED_TARGET] },
			{ ...partial, outcome: 'starttls_available', targets: [VALID_RESULT.targets[0]] },
			{ ...partial, outcome: 'starttls_unavailable', targets: [FAILED_TARGET, INCOMPLETE_TARGET] },
			{ ...partial, outcome: 'starttls_unavailable', targets: [FAILED_TARGET, VALID_RESULT.targets[0]] },
			{ ...partial, outcome: 'starttls_unavailable', targets: [FAILED_TARGET] },
		] as const) {
			expect(SmtpStarttlsResultSchema.safeParse(candidate).success).toBe(false);
		}
	});

	it('represents null MX only as not-applicable', async () => {
		const { SmtpStarttlsResultSchema } = await import('../src/schemas/smtp-starttls');
		expect(
			SmtpStarttlsResultSchema.safeParse({
				schemaVersion: '1.0',
				probe: 'smtp_starttls',
				domain: 'example.com',
				status: 'not-applicable',
				outcome: 'null_mx',
				observedAt: '2026-09-05T00:00:00.000Z',
				nonScoring: true,
				targets: [],
				reason: 'null_mx',
			}).success,
		).toBe(true);
		expect(SmtpStarttlsResultSchema.safeParse({ ...VALID_RESULT, outcome: 'null_mx', targets: [] }).success).toBe(false);
	});

	it('pins normalized MX identity and explicit not-assessed reasons', async () => {
		const { SmtpStarttlsResultSchema, smtpNotAssessed } = await import('../src/schemas/smtp-starttls');
		expect(
			SmtpStarttlsResultSchema.safeParse({
				...VALID_RESULT,
				targets: [{ ...VALID_RESULT.targets[0], target: { ...VALID_RESULT.targets[0].target, tlsServerName: 'other.example.com' } }],
			}).success,
		).toBe(false);
		expect(
			SmtpStarttlsResultSchema.safeParse({
				schemaVersion: '1.0',
				probe: 'smtp_starttls',
				domain: 'example.com',
				status: 'not-assessed',
				outcome: 'no_explicit_mx',
				observedAt: '2026-09-05T00:00:00.000Z',
				nonScoring: true,
				targets: [],
				reason: 'probe_failed',
			}).success,
		).toBe(false);
		expect(SmtpStarttlsResultSchema.parse(smtpNotAssessed('example.com', 'no_explicit_mx'))).toMatchObject({
			status: 'not-assessed',
			outcome: 'no_explicit_mx',
			reason: 'no_explicit_mx',
		});
	});
});
