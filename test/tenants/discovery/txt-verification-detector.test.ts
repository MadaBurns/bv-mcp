// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { detectSharedTxtVerifications } from '../../../src/tenants/discovery/txt-verification-detector';

describe('detectSharedTxtVerifications', () => {
	it('returns shared ownership verification tokens only', async () => {
		const dnsQuery = async (name: string) => ({
			Answer: [
				{
					data: name === 'example.com' ? '"google-site-verification=abc"' : '"google-site-verification=abc"',
				},
				{ data: '"v=spf1 include:_spf.example.test ~all"' },
			],
		});

		const result = await detectSharedTxtVerifications('example.com', {
			candidateDomains: ['example-shop.test'],
			dnsQuery,
		});

		expect(result.coOwnedDomains).toEqual([
			{
				domain: 'example-shop.test',
				sharedTxtVerifications: ['google-site-verification=abc'],
				confidence: 0.9,
			},
		]);
	});
});
