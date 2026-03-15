import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Helper to parse the DoH query name and type from a fetch URL */
function parseDohQuery(input: string | URL | Request): { name: string; type: string } | null {
	const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
	try {
		const parsed = new URL(url);
		if (parsed.hostname.includes('cloudflare-dns') || parsed.hostname.includes('dns.google')) {
			return { name: parsed.searchParams.get('name') ?? '', type: parsed.searchParams.get('type') ?? '' };
		}
	} catch {}
	return null;
}

// ---------- helpers for DNS mock routing ----------

function emptyResponse() {
	return createDohResponse([], []);
}

function nsRecords(domain: string, nameservers: string[]) {
	return createDohResponse(
		[{ name: domain, type: 2 }],
		nameservers.map((ns) => ({ name: domain, type: 2, TTL: 300, data: ns })),
	);
}

function aRecords(domain: string, ips: string[]) {
	return createDohResponse(
		[{ name: domain, type: 1 }],
		ips.map((ip) => ({ name: domain, type: 1, TTL: 300, data: ip })),
	);
}

function mxRecords(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 15 }],
		records.map((data) => ({ name: domain, type: 15, TTL: 300, data })),
	);
}

function txtRecords(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 16 }],
		records.map((data) => ({ name: domain, type: 16, TTL: 300, data: `"${data}"` })),
	);
}

describe('checkShadowDomains', () => {
	async function run(domain = 'example.com') {
		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		return checkShadowDomains(domain);
	}

	it('should return critical finding when variant has MX but no SPF and no DMARC', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary domain MX (for comparison)
			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// Make example.net a shadow variant with MX but no SPF/DMARC
			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.registrar.com.']));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['1.2.3.4']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(emptyResponse()); // no SPF
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse()); // no DMARC
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		expect(result.category).toBe('shadow_domains');
		const critical = result.findings.find(
			(f) => f.severity === 'critical' && f.detail.includes('example.net'),
		);
		expect(critical).toBeDefined();
		expect(critical!.title).toMatch(/fully spoofable/i);
	});

	it('should return high finding when variant has MX + SPF but no DMARC', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.registrar.com.']));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['1.2.3.4']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse()); // no DMARC
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const high = result.findings.find(
			(f) => f.severity === 'high' && f.detail.includes('example.net') && /lacks DMARC/i.test(f.title),
		);
		expect(high).toBeDefined();
	});

	it('should return high finding when variant has MX + DMARC p=none', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.registrar.com.']));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['1.2.3.4']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(txtRecords(name, ['v=DMARC1; p=none; rua=mailto:dmarc@example.net']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const high = result.findings.find(
			(f) => f.severity === 'high' && f.detail.includes('example.net') && /not enforcing/i.test(f.title),
		);
		expect(high).toBeDefined();
	});

	it('should return info finding for unregistered variant (defensive registration opportunity)', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// example.net has no NS → unregistered
			if (name === 'example.net') {
				return Promise.resolve(emptyResponse());
			}
			if (name === '_dmarc.example.net') {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const info = result.findings.find(
			(f) => f.severity === 'info' && f.detail.includes('example.net') && /unregistered/i.test(f.title),
		);
		expect(info).toBeDefined();
	});

	it('should return info finding for registered variant with no mail', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.registrar.com.']));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['1.2.3.4']));
				if (type === 'MX' || type === '15') return Promise.resolve(emptyResponse()); // no MX
				if (type === 'TXT' || type === '16') return Promise.resolve(emptyResponse());
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const info = result.findings.find(
			(f) => f.severity === 'info' && f.detail.includes('example.net') && /registered.*no mail/i.test(f.title),
		);
		expect(info).toBeDefined();
	});

	it('should exclude primary domain from findings', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary domain has MX
			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		// No finding should mention the primary domain in a variant-specific way
		const primaryFinding = result.findings.find(
			(f) =>
				f.metadata?.variant === target,
		);
		expect(primaryFinding).toBeUndefined();
	});

	it('should return low finding for well-managed shadow with matching MX and enforcing DMARC', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary domain MX
			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// example.org: same MX infra, SPF, enforcing DMARC
			if (name === 'example.org') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.registrar.com.']));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['1.2.3.4']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.example.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.org' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(txtRecords(name, ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const low = result.findings.find(
			(f) => f.severity === 'low' && f.detail.includes('example.org') && /well-managed/i.test(f.title),
		);
		expect(low).toBeDefined();
	});

	it('should return medium finding for divergent MX with enforcing DMARC', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary domain MX
			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// example.org: different MX infra, SPF, enforcing DMARC
			if (name === 'example.org') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.registrar.com.']));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['1.2.3.4']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.other-provider.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.org' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(txtRecords(name, ['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const medium = result.findings.find(
			(f) => f.severity === 'medium' && f.detail.includes('example.org') && /divergent/i.test(f.title),
		);
		expect(medium).toBeDefined();
	});

	it('should detect shared NS across multiple variants', async () => {
		const target = 'example.com';
		const sharedNs = ['ns1.shared-registrar.com.', 'ns2.shared-registrar.com.'];

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary domain MX
			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// Two variants share the same NS
			if (name === 'example.net' || name === 'example.org') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, sharedNs));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['1.2.3.4']));
				if (type === 'MX' || type === '15') return Promise.resolve(emptyResponse());
				if (type === 'TXT' || type === '16') return Promise.resolve(emptyResponse());
			}
			if ((name === '_dmarc.example.net' || name === '_dmarc.example.org') && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const sharedNsFinding = result.findings.find(
			(f) => f.severity === 'info' && /shared.*NS/i.test(f.title),
		);
		expect(sharedNsFinding).toBeDefined();
	});
});

describe('generateVariants', () => {
	it('should generate correct NZ regional + global set for .co.nz domain', async () => {
		const { generateVariants } = await import('../src/tools/check-shadow-domains');
		const variants = generateVariants('example', '.co.nz', 'example.co.nz');

		// Should include NZ regional TLDs
		expect(variants).toContain('example.nz');
		expect(variants).toContain('example.org.nz');
		expect(variants).toContain('example.net.nz');
		expect(variants).toContain('example.govt.nz');
		expect(variants).toContain('example.ac.nz');
		expect(variants).toContain('example.school.nz');
		expect(variants).toContain('example.gen.nz');
		expect(variants).toContain('example.kiwi');

		// Should include global ccTLDs
		expect(variants).toContain('example.com');
		expect(variants).toContain('example.net');
		expect(variants).toContain('example.org');
		expect(variants).toContain('example.io');

		// Should NOT include the primary domain itself
		expect(variants).not.toContain('example.co.nz');
	});

	it('should generate correct set for generic .com domain', async () => {
		const { generateVariants } = await import('../src/tools/check-shadow-domains');
		const variants = generateVariants('example', '.com', 'example.com');

		// Should include global ccTLDs
		expect(variants).toContain('example.net');
		expect(variants).toContain('example.org');
		expect(variants).toContain('example.io');
		expect(variants).toContain('example.ai');
		expect(variants).toContain('example.co');

		// Generic family includes .dev and .app
		expect(variants).toContain('example.dev');
		expect(variants).toContain('example.app');

		// Should NOT include the primary domain
		expect(variants).not.toContain('example.com');
	});
});
