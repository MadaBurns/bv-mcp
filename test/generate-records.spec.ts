// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

function mockTxtRecords(records: string[], domain = 'example.com') {
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? '';
		const type = Number(u.searchParams.get('type') ?? '0');

		if (type === 16) {
			// Return records only for the matching domain
			if (name === domain || name === `_dmarc.${domain}` || name === `_mta-sts.${domain}`) {
				const data = records
					.filter((r) => {
						if (name.startsWith('_dmarc.') && r.startsWith('v=DMARC1')) return true;
						if (name.startsWith('_mta-sts.') && r.startsWith('v=STSv1')) return true;
						if (name === domain && r.startsWith('v=spf1')) return true;
						return false;
					})
					.map((d) => ({ name, type: 16, TTL: 300, data: `"${d}"` }));
				return Promise.resolve(createDohResponse([{ name, type }], data));
			}
		}
		// MX
		if (type === 15) {
			return Promise.resolve(createDohResponse([{ name, type }], [
				{ name, type: 15, TTL: 300, data: '10 mail.example.com.' },
			]));
		}
		return Promise.resolve(createDohResponse([{ name, type }], []));
	});
}

describe('generateSpfRecord', () => {
	async function run(domain = 'example.com', providers?: string[]) {
		const { generateSpfRecord } = await import('../src/tools/generate-records');
		return generateSpfRecord(domain, providers);
	}

	it('generates a valid SPF record with -all', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com ~all']);
		const record = await run();
		expect(record.recordType).toBe('TXT');
		expect(record.name).toBe('example.com');
		expect(record.value).toContain('v=spf1');
		expect(record.value).toContain('-all');
	});

	it('includes specified providers', async () => {
		mockTxtRecords(['v=spf1 ~all']);
		const record = await run('example.com', ['google', 'sendgrid']);
		expect(record.value).toContain('include:_spf.google.com');
		expect(record.value).toContain('include:sendgrid.net');
	});

	it('warns about unknown providers', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const record = await run('example.com', ['unknown-provider']);
		expect(record.warnings.length).toBeGreaterThan(0);
		expect(record.warnings[0]).toContain('Unknown provider');
	});

	it('accepts raw include domains', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const record = await run('example.com', ['custom.mailer.com']);
		expect(record.value).toContain('include:custom.mailer.com');
	});

	it('includes instructions', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const record = await run();
		expect(record.instructions.length).toBeGreaterThan(0);
		expect(record.instructions.some((i) => i.includes('TXT'))).toBe(true);
	});
});

describe('generateDmarcRecord', () => {
	async function run(domain = 'example.com', policy?: 'none' | 'quarantine' | 'reject', ruaEmail?: string) {
		const { generateDmarcRecord } = await import('../src/tools/generate-records');
		return generateDmarcRecord(domain, policy, ruaEmail);
	}

	it('generates DMARC record with reject policy by default', async () => {
		mockTxtRecords(['v=DMARC1; p=none']);
		const record = await run();
		expect(record.recordType).toBe('TXT');
		expect(record.name).toBe('_dmarc.example.com');
		expect(record.value).toContain('v=DMARC1');
		expect(record.value).toContain('p=reject');
	});

	it('uses specified policy', async () => {
		mockTxtRecords(['v=DMARC1; p=none']);
		const record = await run('example.com', 'quarantine');
		expect(record.value).toContain('p=quarantine');
	});

	it('uses custom report email', async () => {
		mockTxtRecords(['v=DMARC1; p=none']);
		const record = await run('example.com', undefined, 'reports@monitoring.example.com');
		expect(record.value).toContain('mailto:reports@monitoring.example.com');
	});

	it('defaults report email to dmarc-reports@domain', async () => {
		mockTxtRecords(['v=DMARC1; p=none']);
		const record = await run();
		expect(record.value).toContain('mailto:dmarc-reports@example.com');
	});

	it('includes strict alignment (adkim=s, aspf=s)', async () => {
		mockTxtRecords(['v=DMARC1; p=none']);
		const record = await run();
		expect(record.value).toContain('adkim=s');
		expect(record.value).toContain('aspf=s');
	});

	it('warns when policy is none', async () => {
		mockTxtRecords([]);
		const record = await run('example.com', 'none');
		expect(record.warnings.some((w) => w.includes('monitoring only'))).toBe(true);
	});

	it('includes subdomain policy', async () => {
		mockTxtRecords([]);
		const record = await run('example.com', 'reject');
		expect(record.value).toContain('sp=reject');
	});
});

describe('generateDkimConfig', () => {
	async function run(domain = 'example.com', provider?: string) {
		const { generateDkimConfig } = await import('../src/tools/generate-records');
		return generateDkimConfig(domain, provider);
	}

	it('returns generic instructions when no provider specified', async () => {
		const record = await run();
		expect(record.recordType).toBe('TXT');
		expect(record.name).toContain('_domainkey.example.com');
		expect(record.warnings.some((w) => w.includes('No email provider'))).toBe(true);
	});

	it('returns Google-specific instructions', async () => {
		const record = await run('example.com', 'google');
		expect(record.name).toContain('google._domainkey');
		expect(record.instructions.some((i) => i.includes('Google Admin'))).toBe(true);
	});

	it('returns Microsoft-specific instructions', async () => {
		const record = await run('example.com', 'microsoft');
		expect(record.name).toContain('selector1._domainkey');
		expect(record.instructions.some((i) => i.includes('Microsoft 365'))).toBe(true);
	});

	it('includes domain in instructions', async () => {
		const record = await run('mysite.org');
		expect(record.name).toContain('mysite.org');
	});
});

describe('generateMtaStsPolicy', () => {
	async function run(domain = 'example.com', mxHosts?: string[]) {
		const { generateMtaStsPolicy } = await import('../src/tools/generate-records');
		return generateMtaStsPolicy(domain, mxHosts);
	}

	it('generates MTA-STS TXT record', async () => {
		mockTxtRecords([]);
		const record = await run('example.com', ['mail.example.com']);
		expect(record.recordType).toBe('MTA-STS');
		expect(record.name).toBe('_mta-sts.example.com');
		expect(record.value).toContain('v=STSv1');
		expect(record.value).toContain('id=');
	});

	it('includes MX hosts in policy content', async () => {
		mockTxtRecords([]);
		const record = await run('example.com', ['mx1.example.com', 'mx2.example.com']);
		const policyContent = record.instructions.join('\n');
		expect(policyContent).toContain('mx: mx1.example.com');
		expect(policyContent).toContain('mx: mx2.example.com');
	});

	it('warns when no MX hosts provided or detected', async () => {
		mockTxtRecords([]);
		const record = await run('example.com');
		expect(record.warnings.some((w) => w.includes('No MX hosts'))).toBe(true);
	});

	it('includes hosting instructions', async () => {
		mockTxtRecords([]);
		const record = await run('example.com', ['mail.example.com']);
		const text = record.instructions.join('\n');
		expect(text).toContain('mta-sts.example.com');
		expect(text).toContain('.well-known/mta-sts.txt');
	});
});

describe('formatGeneratedRecord', () => {
	it('formats a record as readable text', async () => {
		const { formatGeneratedRecord } = await import('../src/tools/generate-records');
		const text = formatGeneratedRecord({
			recordType: 'TXT',
			name: 'example.com',
			value: 'v=spf1 -all',
			warnings: ['Test warning'],
			instructions: ['Step 1', 'Step 2'],
		});
		expect(text).toContain('Generated TXT Record');
		expect(text).toContain('example.com');
		expect(text).toContain('v=spf1 -all');
		expect(text).toContain('Test warning');
		expect(text).toContain('Step 1');
	});

	it('compact mode omits instructions but keeps warnings', async () => {
		const { formatGeneratedRecord } = await import('../src/tools/generate-records');
		const record = {
			recordType: 'TXT',
			name: 'example.com',
			value: 'v=spf1 -all',
			warnings: ['Test warning'],
			instructions: ['Step 1', 'Step 2'],
		};
		const compact = formatGeneratedRecord(record, 'compact');
		const full = formatGeneratedRecord(record, 'full');
		expect(compact.length).toBeLessThan(full.length);
		expect(compact).toContain('v=spf1 -all');
		expect(compact).toContain('Test warning');
		expect(compact).not.toContain('Step 1');
		expect(compact).not.toContain('Instructions');
		expect(compact).not.toContain('#');
	});
});
