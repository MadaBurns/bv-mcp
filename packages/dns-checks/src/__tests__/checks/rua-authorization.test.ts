// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi } from 'vitest';
import { checkDMARC } from '../../checks/check-dmarc';
import { checkRuaAuthorization, discoverDmarcOrganizationalDomain } from '../../checks/dmarc-utils';
import type { DNSQueryFunction } from '../../types';

const dns = (records: Record<string, string[]>): DNSQueryFunction => vi.fn(async (name) => records[name] ?? []);

describe('RUA organizational-domain authorization (#911)', () => {
	it.each(['example.com', 'reports.example.com'])('exempts a policy subdomain reporting to %s within its organization', async (target) => {
		const query = dns({ '_dmarc.docs.example.com': ['v=DMARC1; p=reject'], '_dmarc.example.com': ['v=DMARC1; p=reject'] });
		expect(await checkRuaAuthorization('docs.example.com', [`mailto:reports@${target}`], query)).toEqual([]);
		expect(vi.mocked(query).mock.calls.some(([name]) => name.includes('._report.'))).toBe(false);
	});

	it('respects a psd=n boundary even below a shared DNS suffix', async () => {
		const query = dns({ '_dmarc.example.com': ['v=DMARC1; p=reject'], '_dmarc.tenant.example.com': ['v=DMARC1; p=reject; psd=n'] });
		const findings = await checkRuaAuthorization('example.com', ['mailto:reports@tenant.example.com'], query);
		expect(findings.some((f) => f.title === 'Third-party aggregate reporting not authorized')).toBe(true);
	});

	it('respects psd=y and does not equate distinct organizations under a public suffix', async () => {
		const query = dns({ '_dmarc.co.test': ['v=DMARC1; p=reject; psd=y'] });
		expect(await discoverDmarcOrganizationalDomain('a.example.co.test', query)).toBe('example.co.test');
		expect(await discoverDmarcOrganizationalDomain('b.other.co.test', query)).toBe('other.co.test');
	});

	it('uses the inherited policy owner when constructing the authorization record', async () => {
		const query = dns({
			'_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:reports@example.net'],
			'example.com._report._dmarc.example.net': ['v=DMARC1;'],
		});
		const result = await checkDMARC('child.example.com', query);
		expect(result.findings.some((f) => f.title.includes('not authorized'))).toBe(false);
		expect(query).toHaveBeenCalledWith('example.com._report._dmarc.example.net', 'TXT', { timeout: 5000 });
		expect(vi.mocked(query).mock.calls.some(([name]) => name.startsWith('child.example.com._report.'))).toBe(false);
	});

	it.each(['_dmarc.example.net', 'example.com._report._dmarc.example.net'])(
		'records an unmeasured subcheck after failure at %s and prevents caching',
		async (failedName) => {
			const query: DNSQueryFunction = async (name) => {
				if (name === failedName) throw new Error('resolver unavailable');
				return name === '_dmarc.example.com' ? ['v=DMARC1; p=reject; rua=mailto:reports@example.net'] : [];
			};
			const result = await checkDMARC('example.com', query);
			expect(result.partial).toBe(true);
			expect(result.controlPresent).toBe(true);
			expect(result.findings.find((f) => f.metadata?.component === 'rua_authorization')).toMatchObject({
				severity: 'info',
				metadata: { assessment: 'not_assessed' },
			});
			expect(result.findings.some((f) => f.title.includes('not authorized'))).toBe(false);
		},
	);

	it('does not accept a version-prefix lookalike as authorization', async () => {
		const query = dns({ 'example.com._report._dmarc.example.net': ['v=DMARC10;'] });
		const findings = await checkRuaAuthorization('example.com', ['mailto:reports@example.net'], query);
		expect(findings.some((f) => f.title.includes('not authorized'))).toBe(true);
	});

	it('caps a deep organizational tree walk at eight queries', async () => {
		const query = dns({});
		const name = 'a.b.c.d.e.f.g.h.i.example.test';
		expect(await discoverDmarcOrganizationalDomain(name, query)).toBe(name);
		expect(query).toHaveBeenCalledTimes(8);
	});
});
