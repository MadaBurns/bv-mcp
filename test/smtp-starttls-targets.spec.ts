// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';

describe('SMTP MX target selection', () => {
	it('selects at most three public targets deterministically with hostname SNI and fixed port 25', async () => {
		const { selectSmtpMxTargets } = await import('../src/lib/smtp-starttls-targets');
		const result = selectSmtpMxTargets([
			{ preference: 20, exchange: 'mx-c.example.com.', addresses: ['93.184.216.35'] },
			{ preference: 10, exchange: 'mx-b.example.com.', addresses: ['93.184.216.34', '8.8.8.8'] },
			{ preference: 10, exchange: 'mx-a.example.com.', addresses: ['1.1.1.1'] },
			{ preference: 30, exchange: 'mx-d.example.com.', addresses: ['9.9.9.9'] },
		]);

		expect(result.status).toBe('measured');
		expect(result.targets).toEqual([
			{ exchange: 'mx-a.example.com', preference: 10, address: '1.1.1.1', port: 25, tlsServerName: 'mx-a.example.com' },
			{ exchange: 'mx-b.example.com', preference: 10, address: '8.8.8.8', port: 25, tlsServerName: 'mx-b.example.com' },
			{ exchange: 'mx-c.example.com', preference: 20, address: '93.184.216.35', port: 25, tlsServerName: 'mx-c.example.com' },
		]);
	});

	it('treats RFC 7505 null MX as a not-applicable outcome', async () => {
		const { selectSmtpMxTargets } = await import('../src/lib/smtp-starttls-targets');
		expect(selectSmtpMxTargets([{ preference: 0, exchange: '.', addresses: [] }])).toEqual({
			status: 'not-applicable',
			outcome: 'null_mx',
			targets: [],
			rejectedExchanges: [],
		});
	});

	it('distinguishes no explicit MX from an MX set with no public addresses', async () => {
		const { selectSmtpMxTargets } = await import('../src/lib/smtp-starttls-targets');
		expect(selectSmtpMxTargets([]).outcome).toBe('no_explicit_mx');
		const rejected = selectSmtpMxTargets([
			{
				preference: 10,
				exchange: 'mx.example.com',
				addresses: ['10.0.0.1', '192.0.2.10', '192.31.196.1', '192.52.193.1', '192.88.99.1', '192.175.48.1', '2001:db8::1'],
			},
		]);
		expect(rejected).toMatchObject({ status: 'not-assessed', outcome: 'no_public_mx_address', targets: [] });
		expect(rejected.rejectedExchanges).toEqual(['mx.example.com']);
	});

	it('keeps usable targets but labels rejected MX hosts partial', async () => {
		const { selectSmtpMxTargets } = await import('../src/lib/smtp-starttls-targets');
		const result = selectSmtpMxTargets([
			{ preference: 10, exchange: 'mx.example.com', addresses: ['1.1.1.1'] },
			{ preference: 20, exchange: 'localhost', addresses: ['8.8.8.8'] },
		]);
		expect(result.status).toBe('partial');
		expect(result.targets).toHaveLength(1);
		expect(result.rejectedExchanges).toEqual(['localhost']);
	});

	it('does not let malformed, duplicate, mixed-null, or embedded addresses bypass selection', async () => {
		const { selectSmtpMxTargets } = await import('../src/lib/smtp-starttls-targets');
		const result = selectSmtpMxTargets([
			{ preference: 0, exchange: '.', addresses: [] },
			{ preference: -1, exchange: 'bad.example.com', addresses: ['1.1.1.1'] },
			{ preference: 10, exchange: 'mx.example.com', addresses: ['010.0.0.1', '::ffff:127.0.0.1', '2606:4700:4700::1111', '1.1.1.1'] },
			{ preference: 20, exchange: 'mx.example.com.', addresses: ['8.8.8.8'] },
		]);

		expect(result.status).toBe('partial');
		expect(result.targets).toEqual([
			{
				exchange: 'mx.example.com',
				preference: 10,
				address: '1.1.1.1',
				port: 25,
				tlsServerName: 'mx.example.com',
			},
		]);
		expect(result.rejectedExchanges).toEqual(['<empty>', 'bad.example.com']);
	});
});
