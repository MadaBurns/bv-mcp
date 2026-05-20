// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';

describe('authoritative_dns_infra profile', () => {
	it('accepts authoritative_dns_infra as a scan profile argument', async () => {
		const { ScanDomainArgs } = await import('../src/schemas/tool-args');

		const parsed = ScanDomainArgs.parse({
			domain: 'a.root-servers.net',
			profile: 'authoritative_dns_infra',
		});

		expect(parsed.profile).toBe('authoritative_dns_infra');
	});

	it('weights authoritative infrastructure above mail and web categories', async () => {
		const { PROFILE_WEIGHTS, PROFILE_EMAIL_BONUS_ELIGIBLE, PROFILE_CRITICAL_CATEGORIES } = await import('../packages/dns-checks/src/scoring');

		expect(PROFILE_EMAIL_BONUS_ELIGIBLE.authoritative_dns_infra).toBe(false);
		expect(PROFILE_CRITICAL_CATEGORIES.authoritative_dns_infra).toEqual([
			'authoritative_dns_infra',
			'dnssec',
			'ns',
			'zone_hygiene',
		]);
		expect(PROFILE_WEIGHTS.authoritative_dns_infra.authoritative_dns_infra.importance).toBe(40);
		expect(PROFILE_WEIGHTS.authoritative_dns_infra.dmarc.importance).toBe(0);
		expect(PROFILE_WEIGHTS.authoritative_dns_infra.spf.importance).toBe(0);
		expect(PROFILE_WEIGHTS.authoritative_dns_infra.http_security.importance).toBe(0);
	});
});
