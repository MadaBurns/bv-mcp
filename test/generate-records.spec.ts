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
		// The DoH transport sends the record type by NAME (e.g. "TXT", "MX"), not number.
		const typeName = (u.searchParams.get('type') ?? '').toUpperCase();
		const TYPE_CODE: Record<string, number> = { TXT: 16, MX: 15, DNSKEY: 48, DS: 43 };
		const typeCode = TYPE_CODE[typeName] ?? 0;

		if (typeName === 'TXT') {
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
				return Promise.resolve(createDohResponse([{ name, type: typeCode }], data));
			}
		}
		// MX — a single Google-Workspace-style exchange for the apex domain.
		if (typeName === 'MX' && name === domain) {
			return Promise.resolve(createDohResponse([{ name, type: typeCode }], [
				{ name, type: 15, TTL: 300, data: '10 mail.example.com.' },
			]));
		}
		return Promise.resolve(createDohResponse([{ name, type: typeCode }], []));
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
		// Detected include must be preserved.
		expect(record.value).toContain('include:_spf.google.com');
	});

	it('preserves ALL authorizing mechanisms from the live record (ip4, a, mx, include)', async () => {
		// A rich, healthy -all record: dropping the ip4 blocks would hard-fail mail.
		mockTxtRecords([
			'v=spf1 ip4:203.0.113.0/24 ip4:198.51.100.7 a mx include:_spf.google.com include:mailgun.org -all',
		]);
		const record = await run();
		expect(record.value).toContain('ip4:203.0.113.0/24');
		expect(record.value).toContain('ip4:198.51.100.7');
		expect(record.value).toContain(' a ');
		expect(record.value).toContain(' mx ');
		expect(record.value).toContain('include:_spf.google.com');
		expect(record.value).toContain('include:mailgun.org');
		expect(record.value.endsWith('-all')).toBe(true);
		// No double spaces.
		expect(record.value).not.toMatch(/ {2}/);
	});

	it('REFUSES to emit a bare "v=spf1 -all" when no senders detected and none provided', async () => {
		// Domain has no SPF record and caller passes no providers.
		mockTxtRecords([]);
		const record = await run();
		// Must NOT be the mail-breaking bare hard-fail.
		expect(record.value).not.toBe('v=spf1 -all');
		expect(record.value).not.toBe('v=spf1  -all');
		expect(record.value).toContain('?all'); // neutral, non-breaking placeholder
		expect(record.warnings.length).toBeGreaterThan(0);
		expect(record.warnings.join(' ')).toMatch(/REJECT ALL mail|no.*senders.*detected/i);
	});

	it('refuses bare -all even when SPF lookup fails (detection failure → loud warning)', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('DNS timeout'));
		const record = await run();
		expect(record.value).not.toBe('v=spf1 -all');
		expect(record.value).toContain('?all');
		expect(record.warnings.length).toBeGreaterThan(0);
	});

	it('never emits a double space', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com -all']);
		const record = await run();
		expect(record.value).not.toMatch(/ {2}/);
	});

	it('includes specified providers (in addition to detected senders)', async () => {
		mockTxtRecords(['v=spf1 ~all']);
		const record = await run('example.com', ['google', 'sendgrid']);
		expect(record.value).toContain('include:_spf.google.com');
		expect(record.value).toContain('include:sendgrid.net');
	});

	it('warns about unknown providers', async () => {
		// Existing sender present so we still produce a usable record.
		mockTxtRecords(['v=spf1 ip4:198.51.100.7 -all']);
		const record = await run('example.com', ['unknown-provider']);
		expect(record.warnings.length).toBeGreaterThan(0);
		expect(record.warnings.some((w) => w.includes('Unknown provider'))).toBe(true);
	});

	it('accepts raw include domains', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const record = await run('example.com', ['custom.mailer.com']);
		expect(record.value).toContain('include:custom.mailer.com');
	});

	it('does not append -all when the record uses a redirect modifier', async () => {
		mockTxtRecords(['v=spf1 redirect=_spf.example.net']);
		const record = await run();
		expect(record.value).toContain('redirect=_spf.example.net');
		expect(record.value).not.toContain('-all');
	});

	it('includes instructions', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com -all']);
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

	it('auto-detects MX from DNS when mx_hosts is omitted', async () => {
		// Default mock returns MX "10 mail.example.com." for type 15 queries.
		mockTxtRecords([]);
		const record = await run('example.com');
		const policyContent = record.instructions.join('\n');
		expect(policyContent).toContain('mx: mail.example.com');
		// Must NOT have warned or used the placeholder when MX is genuinely present.
		expect(record.warnings.some((w) => w.includes('No MX hosts'))).toBe(false);
		expect(policyContent).not.toContain('mx: mail.example.com\nmx: '); // no placeholder appended
	});

	it('warns only when the domain genuinely has no MX', async () => {
		// Mock: empty TXT AND empty MX (type 15 returns no answers).
		globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
			const u = new URL(typeof url === 'string' ? url : url.toString());
			const name = u.searchParams.get('name') ?? '';
			const type = Number(u.searchParams.get('type') ?? '0');
			return Promise.resolve(createDohResponse([{ name, type }], []));
		});
		const record = await run('example.com');
		expect(record.warnings.some((w) => w.includes('no MX records') || w.includes('No MX hosts'))).toBe(true);
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
