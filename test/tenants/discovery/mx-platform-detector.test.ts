// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { detectSharedMxPlatform } from '../../../src/tenants/discovery/mx-platform-detector';

describe('detectSharedMxPlatform', () => {
	it('identifies candidates using the same normalized mail platform', async () => {
		const dnsQuery = async (name: string) => ({
			Answer: [
				{
					data: name === 'example.com' ? '1 aspmx.l.google.com.' : '10 alt1.aspmx.l.google.com.',
				},
			],
		});

		const result = await detectSharedMxPlatform('example.com', {
			candidateDomains: ['example-mail.test'],
			dnsQuery,
		});

		expect(result.coOwnedDomains).toEqual([
			{
				domain: 'example-mail.test',
				sharedMxPlatform: 'google_workspace',
				confidence: 0.55,
			},
		]);
	});
});
