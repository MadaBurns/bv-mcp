import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse, nxdomainResponse } from './helpers/dns-mock';

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

function soaRecords(domain: string) {
	return createDohResponse(
		[{ name: domain, type: 6 }],
		[{ name: domain, type: 6, TTL: 300, data: 'ns1.shared.example. hostmaster.shared.example. 1 7200 3600 1209600 3600' }],
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

	// D4 (2026-07-26): `example.net` here is delegated to `ns1.registrar.com` while
	// the primary answers no NS at all — no in-bailiwick delegation, no NS-set
	// overlap, so `classifyOwnership()` returns `third_party`. The fully-spoofable
	// record shape is real and still reported, but its severity is now capped at
	// `info`: the scanner has no evidence the scanned organisation controls this
	// domain, and a CRITICAL "shadow domain" finding in the customer's name about
	// an unrelated organisation's domain is the defect this slice removes. The
	// unclamped ladder is covered by the owned-variant cases below.
	it('reports a third-party variant with MX but no SPF and no DMARC at info, not critical', async () => {
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
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
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
		const netFinding = result.findings.find((f) => (f.metadata as { variant?: string } | undefined)?.variant === 'example.net');
		expect(netFinding).toBeDefined();
		expect(netFinding!.severity).toBe('info');
		expect((netFinding!.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('third_party');
		expect(result.findings.some((f) => f.severity === 'critical')).toBe(false);
	});

	// D4: same third-party fixture (`ns1.registrar.com`, no seed NS overlap) —
	// the lacks-DMARC rung is computed but capped at info for a non-owned domain.
	it('reports a third-party variant with MX + SPF but no DMARC at info, not high', async () => {
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
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse()); // no DMARC
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const netFinding = result.findings.find((f) => (f.metadata as { variant?: string } | undefined)?.variant === 'example.net');
		expect(netFinding).toBeDefined();
		expect(netFinding!.severity).toBe('info');
		expect((netFinding!.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('third_party');
		expect((netFinding!.metadata as { hasSpf?: boolean }).hasSpf).toBe(true);
		expect((netFinding!.metadata as { dmarcPolicy?: string | null }).dmarcPolicy).toBeNull();
	});

	// D4: as above — the DMARC-not-enforcing rung is capped at info for a
	// non-owned domain. `dmarcPolicy` in metadata still pins the parsed policy.
	it('reports a third-party variant with MX + DMARC p=none at info, not high', async () => {
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
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(txtRecords(name, ['v=DMARC1; p=none; rua=mailto:dmarc@example.net']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const netFinding = result.findings.find((f) => (f.metadata as { variant?: string } | undefined)?.variant === 'example.net');
		expect(netFinding).toBeDefined();
		expect(netFinding!.severity).toBe('info');
		expect((netFinding!.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('third_party');
		expect((netFinding!.metadata as { dmarcPolicy?: string | null }).dmarcPolicy).toBe('none');
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

			// example.net returns NXDOMAIN — genuinely non-existent, the only state that
			// supports an "unregistered" claim.
			if (name === 'example.net') {
				return Promise.resolve(nxdomainResponse(name));
			}
			if (name === '_dmarc.example.net') {
				return Promise.resolve(nxdomainResponse(name));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const info = result.findings.find((f) => f.severity === 'info' && f.detail.includes('example.net') && /unregistered/i.test(f.title));
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
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
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
		const primaryFinding = result.findings.find((f) => f.metadata?.variant === target);
		expect(primaryFinding).toBeUndefined();
	});

	// D4 fixture repair: this case's subject is the MX-infrastructure match, not
	// ownership. The old fixture gave the variant an unrelated registrar's NS, so
	// under the ownership gate it would now cap at `info` and the well-managed
	// rung would never be observable. The primary and the variant now share a
	// dedicated NS pair (`owned_by_seed`), which is the only configuration in
	// which the ladder legitimately runs unclamped — keeping the test on its
	// actual subject.
	it('should return low finding for well-managed shadow with matching MX and enforcing DMARC', async () => {
		const target = 'example.com';
		const ownNs = ['ns1.example-dns.net.', 'ns2.example-dns.net.'];

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary domain NS + MX
			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ownNs));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// example.org: same NS (same owner), same MX infra, SPF, enforcing DMARC
			if (name === 'example.org') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ownNs));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.example.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.org' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(txtRecords(name, ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const low = result.findings.find((f) => f.severity === 'low' && f.detail.includes('example.org') && /well-managed/i.test(f.title));
		expect(low).toBeDefined();
		expect((low!.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('owned_by_seed');
	});

	// D4 fixture repair, same rationale as the well-managed case above: the
	// subject is divergent MX infrastructure, which is only observable on a
	// domain the seed actually owns.
	it('should return medium finding for divergent MX with enforcing DMARC', async () => {
		const target = 'example.com';
		const ownNs = ['ns1.example-dns.net.', 'ns2.example-dns.net.'];

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary domain NS + MX
			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ownNs));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// example.org: same NS (same owner), different MX infra, SPF, enforcing DMARC
			if (name === 'example.org') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ownNs));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.other-provider.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.org' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(txtRecords(name, ['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const medium = result.findings.find((f) => f.severity === 'medium' && f.detail.includes('example.org') && /divergent/i.test(f.title));
		expect(medium).toBeDefined();
		expect((medium!.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('owned_by_seed');
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
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(emptyResponse());
				if (type === 'TXT' || type === '16') return Promise.resolve(emptyResponse());
			}
			if ((name === '_dmarc.example.net' || name === '_dmarc.example.org') && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const sharedNsFinding = result.findings.find((f) => f.severity === 'info' && /shared.*NS/i.test(f.title));
		expect(sharedNsFinding).toBeDefined();
	});

	it('should classify a variant as unregistered only on NXDOMAIN', async () => {
		// Registration contract (src/lib/registration-state.ts): NXDOMAIN is the ONLY
		// state that supports an "unregistered" claim. NOERROR-with-no-answers (on NS,
		// SOA, and the A escalation alike), SERVFAIL, and transport failures are all
		// genuinely inconclusive and must surface as "registration unknown" instead —
		// never as "unregistered". This replaces the old NS+A-empty heuristic (removed
		// Phase 1.5 A-record fallback), which conflated "no records returned" with
		// "domain does not exist".
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// example.net returns NXDOMAIN — genuinely non-existent.
			if (name === 'example.net') {
				return Promise.resolve(nxdomainResponse(name));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(nxdomainResponse(name));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const unregistered = result.findings.find(
			(f) => f.severity === 'info' && f.detail.includes('example.net') && /unregistered/i.test(f.title),
		);
		expect(unregistered).toBeDefined();
	});

	it('does NOT label a mail-only variant "unregistered" when NS+A are absent but MX/SPF exist (Bug #4 residual path)', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// example.net is a MAIL-ONLY registration: no NS (or slow-server NS that
			// missed the tight window), no web A record — but a real MX + SPF. The old
			// NS+A-only classifier wrongly emitted "unregistered" with a hardcoded
			// hasSpf:false. The residual full-timeout probe must find the MX/SPF
			// evidence and classify it as registered, never unregistered.
			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(emptyResponse());
				if (type === 'A' || type === '1') return Promise.resolve(emptyResponse());
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.attacker.net.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:sendgrid.net ~all']));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const netFindings = result.findings.filter((f) => f.detail.includes('example.net') || f.metadata?.variant === 'example.net');
		// No "unregistered" verdict for a variant that publishes MX + SPF.
		expect(netFindings.some((f) => /unregistered/i.test(f.title))).toBe(false);
		// And no finding may carry the contradictory positive-SPF + unregistered pair,
		// nor the old hardcoded hasSpf:false when SPF is actually present.
		const varFinding = netFindings.find((f) => f.metadata?.variant === 'example.net');
		expect(varFinding).toBeDefined();
		expect(varFinding?.metadata?.hasSpf).toBe(true);
	});
});

describe('generateVariants', () => {
	it('should generate correct NZ regional + global set for .co.nz domain (no leading dot)', async () => {
		const { generateVariants } = await import('../src/tools/check-shadow-domains');
		// Use 'co.nz' without leading dot — this is what getEffectiveTld actually returns
		const variants = generateVariants('example', 'co.nz', 'example.co.nz');

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

	it('should generate correct set for generic .com domain (no leading dot)', async () => {
		const { generateVariants } = await import('../src/tools/check-shadow-domains');
		// Use 'com' without leading dot — this is what getEffectiveTld actually returns
		const variants = generateVariants('example', 'com', 'example.com');

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

	it('should also work with leading-dot format for backward compat', async () => {
		const { generateVariants } = await import('../src/tools/check-shadow-domains');
		const variants = generateVariants('example', '.com', 'example.com');

		// Should still include generic extras
		expect(variants).toContain('example.dev');
		expect(variants).toContain('example.app');
	});

	it('should include UK regional variants for co.uk TLD (no leading dot)', async () => {
		const { generateVariants } = await import('../src/tools/check-shadow-domains');
		const variants = generateVariants('example', 'co.uk', 'example.co.uk');

		expect(variants).toContain('example.org.uk');
		expect(variants).toContain('example.uk');
		// Global TLDs too
		expect(variants).toContain('example.com');
	});

	it('should include NZ single-level for nz TLD (no leading dot)', async () => {
		const { generateVariants } = await import('../src/tools/check-shadow-domains');
		// 'nz' without leading dot — getEffectiveTld('blackveil.nz') returns 'nz'
		const variants = generateVariants('blackveil', 'nz', 'blackveil.nz');

		// Should include NZ regional TLDs because 'nz' endsWith '.nz' after normalization
		expect(variants).toContain('blackveil.co.nz');
		expect(variants).toContain('blackveil.org.nz');
		expect(variants).toContain('blackveil.kiwi');
	});

	it('should integrate correctly with getEffectiveTld output for .com domain', async () => {
		const { generateVariants } = await import('../src/tools/check-shadow-domains');
		const { getEffectiveTld, extractBrandName } = await import('../src/lib/public-suffix');

		const domain = 'example.com';
		const brand = extractBrandName(domain)!;
		const tld = getEffectiveTld(domain)!;

		// getEffectiveTld returns 'com' (no dot), verify that generateVariants works
		expect(tld).toBe('com');
		const variants = generateVariants(brand, tld, domain);

		// Should include generic extras (proves the GENERIC_TLDS check works without leading dot)
		expect(variants).toContain('example.dev');
		expect(variants).toContain('example.app');
		// And global TLDs
		expect(variants).toContain('example.net');
		expect(variants).toContain('example.org');
	});
});

describe('checkShadowDomains — classification edge cases', () => {
	async function run(domain = 'example.com') {
		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		return checkShadowDomains(domain);
	}

	it('should NOT classify MX + no SPF + DMARC p=reject as critical', async () => {
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
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(emptyResponse()); // no SPF
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(txtRecords(name, ['v=DMARC1; p=reject; rua=mailto:dmarc@example.net']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		// DMARC p=reject present so should NOT be critical
		const critical = result.findings.find((f) => f.severity === 'critical' && f.detail.includes('example.net'));
		expect(critical).toBeUndefined();
	});

	it('should NOT classify a variant as unregistered when NS empty but A resolves (slow-ccTLD safety net)', async () => {
		// Reproduces the openai.nl false-negative: Phase 1 NS query returns empty (slow .nl
		// authoritative server exceeds the 2s PHASE1 timeout) but the domain IS registered and
		// resolves an A record. The classifier must use A as a fallback positive-existence signal
		// rather than concluding "unregistered".
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(emptyResponse());
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.99']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mailrelay.example.net.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(emptyResponse());
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const wronglyUnregistered = result.findings.find(
			(f) => f.detail.includes('example.net') && /does not appear to be registered/i.test(f.detail),
		);
		expect(wronglyUnregistered).toBeUndefined();
	});

	it('should NOT call a variant unregistered when it publishes SPF but has no NS/MX (bnz.co contradiction)', async () => {
		// bnz.co resolved an A record + published an SPF TXT (brand discovery independently
		// surfaced it as a live 0.95 candidate via http_redirect), but its NS query came back
		// empty and it has no MX. The classifier used NS/MX presence ONLY, so it emitted
		// "Brand variant unregistered" WHILE its own metadata carried hasSpf:true — an internally
		// contradictory verdict (an unregistered domain cannot publish SPF). A published SPF/A
		// record is proof of registration.
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(emptyResponse()); // NS empty (as observed)
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.50'])); // resolves
				if (type === 'MX' || type === '15') return Promise.resolve(emptyResponse()); // no mail
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 -all'])); // SPF published
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const netFindings = result.findings.filter((f) => f.detail.includes('example.net'));

		// It must not be labelled unregistered…
		expect(netFindings.some((f) => /unregistered|does not appear to be registered/i.test(`${f.title} ${f.detail}`))).toBe(false);
		// …and NO finding may claim unregistered while its metadata reports positive SPF evidence.
		expect(
			netFindings.some(
				(f) => f.metadata?.hasSpf === true && /unregistered|does not appear to be registered/i.test(`${f.title} ${f.detail}`),
			),
		).toBe(false);
	});

	it('should classify RFC 7505 null MX (MX 0 .) as INFO non-mail, not as spoofable', async () => {
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
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				// Null MX per RFC 7505: priority 0, target = root (".")
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['0 .']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 -all']));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse()); // no DMARC, irrelevant when null MX
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const nullMxFinding = result.findings.find((f) => f.detail.includes('example.net') && /non-mail|RFC 7505/i.test(f.title));
		expect(nullMxFinding).toBeDefined();
		expect(nullMxFinding!.severity).toBe('info');
		// Must NOT be classified as spoofable or weak-DMARC
		const spoofable = result.findings.find((f) => f.detail.includes('example.net') && /spoofable|lacks DMARC|not enforcing/i.test(f.title));
		expect(spoofable).toBeUndefined();
	});

	it('should classify legacy null MX (MX 0 localhost.) as INFO non-mail', async () => {
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
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				// Legacy null-MX convention: priority 0 → "localhost"
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['0 localhost.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 -all']));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const nullMxFinding = result.findings.find((f) => f.detail.includes('example.net') && /non-mail|RFC 7505/i.test(f.title));
		expect(nullMxFinding).toBeDefined();
		expect(nullMxFinding!.severity).toBe('info');
		const wrongHigh = result.findings.find((f) => f.detail.includes('example.net') && f.severity !== 'info');
		expect(wrongHigh).toBeUndefined();
	});

	// D4 fixture repair: the subject is DMARC parsing (a missing `p=` tag defaults
	// to `p=none`), not ownership. The variant now shares the primary's dedicated
	// NS pair so the not-enforcing rung stays observable; the parsed policy is
	// additionally pinned directly in metadata, which no ownership gate can mask.
	it('should treat DMARC with no p= tag as p=none', async () => {
		const target = 'example.com';
		const ownNs = ['ns1.example-dns.net.', 'ns2.example-dns.net.'];

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ownNs));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ownNs));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				// DMARC record with no p= tag at all
				return Promise.resolve(txtRecords(name, ['v=DMARC1; rua=mailto:dmarc@example.net']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		// Missing p= tag defaults to p=none: the not-enforcing rung, softened one
		// step to medium because the variant is the seed's own domain.
		const notEnforcing = result.findings.find((f) => f.detail.includes('example.net') && /not enforcing/i.test(f.title));
		expect(notEnforcing).toBeDefined();
		expect(notEnforcing!.severity).toBe('medium');
		expect((notEnforcing!.metadata as { dmarcPolicy?: string | null }).dmarcPolicy).toBe('none');
	});

	// D4 fixture repair: the subject is trailing-dot normalisation in the
	// MX-infrastructure comparison, only observable on an owned variant.
	it('should normalize trailing dot on MX hostname for comparison', async () => {
		const target = 'example.com';
		const ownNs = ['ns1.example-dns.net.', 'ns2.example-dns.net.'];

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary NS + MX with trailing dot
			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ownNs));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// Variant with same NS (same owner) and same MX but without trailing dot
			if (name === 'example.org') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ownNs));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.example.com'])); // no trailing dot
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 -all']));
			}
			if (name === '_dmarc.example.org' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(txtRecords(name, ['v=DMARC1; p=reject']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		// Should match as same infrastructure (low severity) despite trailing dot difference
		const low = result.findings.find((f) => f.severity === 'low' && f.detail.includes('example.org') && /well-managed/i.test(f.title));
		expect(low).toBeDefined();
		// Should NOT be medium/divergent
		const divergent = result.findings.find(
			(f) => f.severity === 'medium' && f.detail.includes('example.org') && /divergent/i.test(f.title),
		);
		expect(divergent).toBeUndefined();
	});
});

describe('checkShadowDomains — shared NS severity downgrade', () => {
	const sharedNs = ['ns1.shared-registrar.com.', 'ns2.shared-registrar.com.'];

	async function run(domain = 'example.com') {
		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		return checkShadowDomains(domain);
	}

	it('should downgrade "fully spoofable" from critical to high when variant shares NS with primary', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary: NS + MX
			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, sharedNs));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// Variant: same NS, MX present, but no SPF and no DMARC
			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, sharedNs));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(emptyResponse());
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		// Should be downgraded to high (not critical)
		const critical = result.findings.find((f) => f.severity === 'critical' && f.detail.includes('example.net'));
		expect(critical).toBeUndefined();

		const high = result.findings.find((f) => f.severity === 'high' && f.detail.includes('example.net') && /fully spoofable/i.test(f.title));
		expect(high).toBeDefined();
		expect(high!.detail).toContain('shares 2/2 dedicated nameservers');
		expect((high!.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('owned_by_seed');
	});

	it('should downgrade "lacks DMARC" from high to medium when variant shares NS with primary', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, sharedNs));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// Variant: same NS, MX + SPF but no DMARC
			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, sharedNs));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		// Should be downgraded to medium (not high)
		const high = result.findings.find((f) => f.severity === 'high' && f.detail.includes('example.net') && /lacks DMARC/i.test(f.title));
		expect(high).toBeUndefined();

		const medium = result.findings.find((f) => f.severity === 'medium' && f.detail.includes('example.net') && /lacks DMARC/i.test(f.title));
		expect(medium).toBeDefined();
		expect(medium!.detail).toContain('shares 2/2 dedicated nameservers');
		expect((medium!.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('owned_by_seed');
	});

	it('should downgrade "DMARC not enforcing" from high to medium when variant shares NS with primary', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, sharedNs));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// Variant: same NS, MX + SPF + DMARC p=none
			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, sharedNs));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(txtRecords(name, ['v=DMARC1; p=none; rua=mailto:dmarc@example.net']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const high = result.findings.find((f) => f.severity === 'high' && f.detail.includes('example.net') && /not enforcing/i.test(f.title));
		expect(high).toBeUndefined();

		const medium = result.findings.find(
			(f) => f.severity === 'medium' && f.detail.includes('example.net') && /not enforcing/i.test(f.title),
		);
		expect(medium).toBeDefined();
		expect(medium!.detail).toContain('shares 2/2 dedicated nameservers');
		expect((medium!.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('owned_by_seed');
	});

	it('should annotate divergent MX finding when variant shares NS with primary', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, sharedNs));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// Variant: same NS, different MX, enforcing DMARC
			if (name === 'example.org') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, sharedNs));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.other-provider.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.org' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(txtRecords(name, ['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const divergent = result.findings.find(
			(f) => f.severity === 'medium' && f.detail.includes('example.org') && /divergent/i.test(f.title),
		);
		expect(divergent).toBeDefined();
		expect(divergent!.detail).toContain('common ownership');
	});

	// D4: the pre-fix contract here was "different NS => no same-owner softening,
	// so the lacks-DMARC rung stays HIGH". That is the liability defect stated as
	// a requirement: a variant on `ns1.other-registrar.com` is not the customer's
	// domain, so a HIGH finding about it in the customer's report is exactly what
	// this slice removes. Different NS now means `third_party`, which caps at
	// info — the finding is still emitted, and the same-owner note stays absent.
	it('treats a variant with different NS as third-party: capped at info, no same-owner note', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary: own NS
			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, sharedNs));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
			}

			// Variant: DIFFERENT NS, MX + SPF but no DMARC
			if (name === 'example.net') {
				if (type === 'NS' || type === '2')
					return Promise.resolve(nsRecords(name, ['ns1.other-registrar.com.', 'ns2.other-registrar.com.']));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:spf.provider.com -all']));
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const netFinding = result.findings.find((f) => (f.metadata as { variant?: string } | undefined)?.variant === 'example.net');
		expect(netFinding).toBeDefined();
		expect(netFinding!.severity).toBe('info');
		expect((netFinding!.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('third_party');
		// The same-owner softening note must not appear on a non-owned domain.
		expect(netFinding!.detail).not.toContain('Likely same owner');
	});
});

describe('checkShadowDomains — primary DNS unavailable', () => {
	async function run(domain = 'example.com') {
		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		return checkShadowDomains(domain);
	}

	it('adds info finding when primary domain DNS is unavailable', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary domain MX and NS queries BOTH fail
			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.reject(new Error('DNS query failed'));
			}
			if (name === target && (type === 'NS' || type === '2')) {
				return Promise.reject(new Error('DNS query failed'));
			}

			// Variant resolves fine
			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.registrar.com.']));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(emptyResponse());
			}
			if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
				return Promise.resolve(emptyResponse());
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const dnsUnavailableFinding = result.findings.find((f) => f.title === 'Primary domain DNS unavailable');
		expect(dnsUnavailableFinding).toBeDefined();
		expect(dnsUnavailableFinding!.severity).toBe('info');
		expect(dnsUnavailableFinding!.detail).toContain(target);
	});

	it('does NOT add DNS unavailable finding when only one primary query fails', async () => {
		const target = 'example.com';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;

			// Primary MX fails, but NS succeeds
			if (name === target && (type === 'MX' || type === '15')) {
				return Promise.reject(new Error('DNS query failed'));
			}
			if (name === target && (type === 'NS' || type === '2')) {
				return Promise.resolve(nsRecords(name, ['ns1.example.com.', 'ns2.example.com.']));
			}

			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const dnsUnavailableFinding = result.findings.find((f) => f.title === 'Primary domain DNS unavailable');
		expect(dnsUnavailableFinding).toBeUndefined();
	});
});

describe('checkShadowDomains — Phase 1 constants', () => {
	it('exports Phase 1 lean DNS options and FAILURE_THRESHOLD', async () => {
		const mod = await import('../src/tools/check-shadow-domains');
		expect(mod.PHASE1_DNS_OPTS).toEqual({
			timeoutMs: 2000,
			retries: 0,
			skipSecondaryConfirmation: true,
		});
		expect(mod.FAILURE_THRESHOLD).toBe(0);
	});
});

describe('registration-state correctness', () => {
	it('does NOT claim unregistered when the NS lookup SERVFAILs', async () => {
		const { servfailResponse } = await import('./helpers/dns-mock');
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			const q = parseDohQuery(input);
			if (!q) return emptyResponse();
			// Primary resolves normally; every variant SERVFAILs.
			if (q.name === 'bnz.co.nz') return nsRecords('bnz.co.nz', ['a1-97.akam.net.']);
			return servfailResponse(q.name, q.type === 'NS' ? 2 : 1);
		}) as unknown as typeof fetch;

		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('bnz.co.nz');

		expect(result.findings.some((f) => f.title === 'Brand variant unregistered')).toBe(false);
		expect(result.findings.some((f) => f.title === 'Brand variant registration unknown')).toBe(true);
	});

	it('DOES claim unregistered on a clean NXDOMAIN', async () => {
		const { nxdomainResponse } = await import('./helpers/dns-mock');
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			const q = parseDohQuery(input);
			if (!q) return emptyResponse();
			if (q.name === 'bnz.co.nz') return nsRecords('bnz.co.nz', ['a1-97.akam.net.']);
			return nxdomainResponse(q.name, q.type === 'NS' ? 2 : 1);
		}) as unknown as typeof fetch;

		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('bnz.co.nz');

		expect(result.findings.some((f) => f.title === 'Brand variant unregistered')).toBe(true);
	});

	it('re-probing an unknown variant can never yield an "unregistered" verdict, even when the re-probe itself NXDOMAINs', async () => {
		// The unknown-bucket re-probe (added when main's mail-only regression test
		// exposed that a MX/SPF-only variant was reported unknown with a hardcoded
		// `hasSpf: false`) must only ever move a variant `unknown → registered`.
		//
		// This is the hostile case for that invariant: Phase 1 SERVFAILs on NS+SOA
		// (→ unknown/servfail), and then EVERY re-probe query comes back NXDOMAIN.
		// A naive "no evidence found on re-probe ⇒ unregistered" would fire here —
		// but an NXDOMAIN reached after a SERVFAIL is contradictory evidence, not
		// proof of non-existence. NXDOMAIN resolved in Phase 1 by
		// `resolveRegistration` remains the SOLE path to an unregistered claim.
		const { servfailResponse, nxdomainResponse } = await import('./helpers/dns-mock');
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			const q = parseDohQuery(input);
			if (!q) return emptyResponse();
			if (q.name === 'bnz.co.nz') return nsRecords('bnz.co.nz', ['a1-97.akam.net.']);
			// Phase 1 looks at NS (2) and SOA (6) — both SERVFAIL, so the variant is
			// UNKNOWN, never unregistered. Everything the re-probe asks for NXDOMAINs.
			if (q.type === 'NS' || q.type === '2') return servfailResponse(q.name, 2);
			if (q.type === 'SOA' || q.type === '6') return servfailResponse(q.name, 6);
			return nxdomainResponse(q.name, q.type === 'A' || q.type === '1' ? 1 : 16);
		}) as unknown as typeof fetch;

		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('bnz.co.nz');

		// Non-vacuous: the unknown bucket must actually be populated, or the
		// assertion below proves nothing.
		expect(result.findings.some((f) => f.title === 'Brand variant registration unknown')).toBe(true);
		// The invariant itself.
		expect(result.findings.some((f) => f.title === 'Brand variant unregistered')).toBe(false);
		expect(result.findings.some((f) => /does not appear to be registered/i.test(f.detail))).toBe(false);
		expect(result.findings.some((f) => f.metadata?.registrationState === 'unregistered')).toBe(false);
	});

	it('an unknown variant whose re-probe finds nothing keeps state "unknown" carrying the probe\'s actual observations', async () => {
		// Negative-path honesty pin. The re-probe's observations are threaded into
		// the finding rather than a hardcoded literal set; on this path the probe
		// genuinely observes nothing, so the metadata must report exactly that —
		// empty record sets, `hasSpf: false`, `dmarcPolicy: null` — while the state
		// stays `unknown` and the reason stays the Phase-1 rcode ('servfail'), NOT a
		// value invented by the re-probe.
		const { servfailResponse } = await import('./helpers/dns-mock');
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			const q = parseDohQuery(input);
			if (!q) return emptyResponse();
			if (q.name === 'bnz.co.nz') return nsRecords('bnz.co.nz', ['a1-97.akam.net.']);
			if (q.type === 'NS' || q.type === '2') return servfailResponse(q.name, 2);
			if (q.type === 'SOA' || q.type === '6') return servfailResponse(q.name, 6);
			return emptyResponse();
		}) as unknown as typeof fetch;

		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('bnz.co.nz');

		const unknownFindings = result.findings.filter((f) => f.title === 'Brand variant registration unknown');
		expect(unknownFindings.length).toBeGreaterThan(0);
		for (const f of unknownFindings) {
			expect(f.metadata?.registrationState).toBe('unknown');
			expect(f.metadata?.reason).toBe('servfail');
			expect(f.metadata?.hasSpf).toBe(false);
			expect(f.metadata?.dmarcPolicy).toBeNull();
			expect(f.metadata?.ns).toEqual([]);
			expect(f.metadata?.mx).toEqual([]);
		}
	});

	it('reserves budget for Phase 2: an exhausted re-probe sub-deadline emits every unknown finding, probes none, and Phase 2 still runs', async () => {
		// Budget-reservation contract. The unknown re-probe may consume at most half
		// the check's budget (`reprobeDeadline`), so a flaky ccTLD family cannot
		// starve Phase 2 — whose detail probes produce the check's most valuable
		// output (fully-spoofable / lacks-DMARC criticals on REGISTERED variants).
		//
		// Wall-clock starvation is not reproducible in-suite (mocked DNS resolves
		// instantly), so the clock is advanced directly instead of slept through:
		// `Date.now` jumps to start+15s the moment Phase 1 is under way. That is past
		// `reprobeDeadline` (start + SHADOW_TIMEOUT_MS/2 = 10s) but short of the full
		// `deadline` (start + 20s) — precisely the window the reservation exists to
		// protect. The jump is keyed on the first SOA query because `resolveRegistration`
		// (Phase 1) is the ONLY caller that asks for SOA; `probeVariant` queries
		// NS/A/MX/TXT and never SOA, so this cannot fire from a probe stage. Phase 1
		// itself checks no deadline, so advancing the clock mid-bucketing is inert.
		const { servfailResponse } = await import('./helpers/dns-mock');
		const realNow = Date.now;
		const base = realNow.call(Date);
		let phase1Started = false;
		const probeQueriedNames = new Set<string>();

		try {
			Date.now = () => (phase1Started ? base + 15_000 : base);

			globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
				const q = parseDohQuery(input);
				if (!q) return emptyResponse();
				const isSoa = q.type === 'SOA' || q.type === '6';
				if (isSoa) phase1Started = true;
				// Only `probeVariant` asks for MX/TXT — record those to prove which
				// variants were (and were not) re-probed.
				if (q.type === 'MX' || q.type === '15' || q.type === 'TXT' || q.type === '16') {
					probeQueriedNames.add(q.name.replace(/^_dmarc\./, ''));
				}

				if (q.name === 'example.com') {
					if (q.type === 'MX' || q.type === '15') return mxRecords('example.com', ['10 mail.example.com.']);
					return nsRecords('example.com', ['ns1.example.com.']);
				}
				// One REGISTERED variant, so Phase 2 has work to do.
				if (q.name === 'example.net') {
					if (q.type === 'NS' || q.type === '2') return nsRecords('example.net', ['ns1.registrar.com.']);
					return emptyResponse();
				}
				// Every other variant SERVFAILs its Phase-1 NS+SOA → unknown bucket.
				return servfailResponse(q.name, isSoa ? 6 : 2);
			}) as unknown as typeof fetch;

			const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
			const result = await checkShadowDomains('example.com');

			const unknownFindings = result.findings.filter((f) => f.title === 'Brand variant registration unknown');
			// Non-vacuous: the unknown bucket must actually be populated.
			expect(unknownFindings.length).toBeGreaterThan(0);

			// (1) EVERY unknown-bucket variant still gets its finding — the sub-deadline
			//     degrades the re-probe, it never silently drops a variant.
			for (const f of unknownFindings) {
				expect(f.metadata?.registrationState).toBe('unknown');
			}

			// (2) …and NONE of them was re-probed: the stage bailed at loop entry.
			for (const f of unknownFindings) {
				expect(probeQueriedNames.has(String(f.metadata?.variant))).toBe(false);
			}

			// (3) Phase 2 still ran on the budget the reservation protected: the
			//     registered variant WAS detail-probed and produced a real classification,
			//     not an unknown/timeout placeholder.
			expect(probeQueriedNames.has('example.net')).toBe(true);
			const netFinding = result.findings.find((f) => f.metadata?.variant === 'example.net');
			expect(netFinding).toBeDefined();
			expect(netFinding?.title).not.toBe('Brand variant registration unknown');
		} finally {
			Date.now = realNow;
		}
	});

	it('never recommends defensive registration on an inconclusive lookup', async () => {
		const { servfailResponse } = await import('./helpers/dns-mock');
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			const q = parseDohQuery(input);
			if (!q) return emptyResponse();
			if (q.name === 'bnz.co.nz') return nsRecords('bnz.co.nz', ['a1-97.akam.net.']);
			return servfailResponse(q.name, q.type === 'NS' ? 2 : 1);
		}) as unknown as typeof fetch;

		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('bnz.co.nz');

		// Non-vacuous guard: an empty findings list would make the loop below prove
		// nothing.
		expect(result.findings.length).toBeGreaterThan(0);
		for (const f of result.findings) {
			expect(f.detail).not.toMatch(/defensive registration/i);
		}
	});

	it('pins post-buildCheckResult confidence: heuristic for unknown, deterministic for unregistered', async () => {
		// FindingConfidence (packages/dns-checks/src/scoring/model.ts) is exactly
		// 'deterministic' | 'heuristic' | 'verified'. An out-of-union value declared in
		// metadata.confidence is silently rejected by isExplicitConfidence() and falls
		// through inferFindingConfidence()'s keyword matching to the 'deterministic'
		// default — so a value must be asserted on the finding AFTER it passes through
		// buildCheckResult's withConfidenceMetadata plumbing, not on the pre-build object,
		// or a regression back to an invalid value would go undetected.
		const { servfailResponse, nxdomainResponse } = await import('./helpers/dns-mock');
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			const q = parseDohQuery(input);
			if (!q) return emptyResponse();
			if (q.name === 'bnz.co.nz') return nsRecords('bnz.co.nz', ['a1-97.akam.net.']);
			// One variant is a clean NXDOMAIN (→ unregistered); every other variant SERVFAILs
			// (→ registration unknown).
			if (q.name === 'bnz.kiwi') return nxdomainResponse(q.name, q.type === 'NS' ? 2 : 1);
			return servfailResponse(q.name, q.type === 'NS' ? 2 : 1);
		}) as unknown as typeof fetch;

		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('bnz.co.nz');

		const unknown = result.findings.find((f) => f.title === 'Brand variant registration unknown');
		expect(unknown).toBeDefined();
		expect(unknown!.metadata?.confidence).toBe('heuristic');

		const unregistered = result.findings.find((f) => f.title === 'Brand variant unregistered');
		expect(unregistered).toBeDefined();
		// SCOPE: pins the CUSTOMER-VISIBLE value only. 'deterministic' is
		// inferFindingConfidence()'s fallback, so this line cannot distinguish the
		// correct literal from an out-of-union one at the emission site — the
		// declaration itself is pinned pre-normalisation by the createFinding
		// interception test in test/audits/registration-invariant.audit.test.ts.
		expect(unregistered!.metadata?.confidence).toBe('deterministic');
	});

	it('never emits an unregistered finding alongside observed records', async () => {
		// Registration evidence comes from an A-only escalation (NS + SOA both
		// NOERROR/empty for variants, so resolveRegistration falls through to the
		// A-record escalation), which — like the SOA-only path — proves
		// "registered" while leaving `ns` empty. That is exactly the shape that
		// reached classifyVariant's fallthrough pre-fix: registered (so Task 3's
		// gate lets it through), but with no NS and no MX, so it fell to the final
		// "Brand variant unregistered" branch while still carrying the SPF record
		// this probe observed.
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			const q = parseDohQuery(input);
			if (!q) return emptyResponse();
			if (q.type === 'NS') return q.name === 'bnz.co.nz' ? nsRecords(q.name, ['ns1.bnz.co.nz.']) : emptyResponse();
			if (q.type === 'A') return aRecords(q.name, ['203.0.113.10']);
			if (q.type === 'TXT') return txtRecords(q.name, ['v=spf1 mx -all']);
			return emptyResponse();
		}) as unknown as typeof fetch;

		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		// Sentinel: proves the capture below is live. Without it, a spy that stopped
		// recording (or a snapshot taken after `mockRestore()` cleared the calls)
		// would make the "no violation logged" assertion pass vacuously.
		console.log('__log-capture-sentinel__');
		let result;
		let logged: string;
		try {
			const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
			result = await checkShadowDomains('bnz.co.nz');
		} finally {
			// Snapshot BEFORE restoring: `mockRestore()` also resets the mock, which
			// clears `mock.calls` and would leave the log assertion below vacuous.
			logged = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
			logSpy.mockRestore();
		}

		// Guard against a vacuous pass: the assertions below are only meaningful
		// if the scan produced findings at all.
		expect(result.findings.length).toBeGreaterThan(0);

		// Assert the invariant over EVERY finding, matching on the semantic claim
		// rather than one title string — a title rename must not silently disarm
		// this test. In this scenario every variant is registered via the A
		// escalation, so NOTHING may assert non-existence. Asserted as an empty
		// list rather than a filtered loop: a loop body here would be dead by
		// construction and could never fail.
		const nonExistenceClaims = result.findings.filter((f) => /unregistered|not registered|does not exist/i.test(`${f.title} ${f.detail}`));
		expect(nonExistenceClaims.map((f) => f.title)).toEqual([]);

		// The fallthrough finding must exist and must NOT contradict its own metadata.
		const fallthrough = result.findings.find((f) => f.title === 'Shadow domain registered, records not observed');
		expect(fallthrough).toBeDefined();
		// Asserted unconditionally: wrapping the detail check in `if (hasSpf)` let a
		// regression that flipped hasSpf to false skip the check instead of failing.
		const fm = fallthrough!.metadata as { hasSpf?: boolean };
		expect(fm.hasSpf).toBe(true);
		expect(fallthrough!.detail).not.toMatch(/no .*SPF records were observed/i);

		// The log capture is retained only to prove the sentinel path works; the
		// former "registration invariant violated" warn was deleted along with the
		// tautological guard that emitted it (no call site can produce that string
		// any more, so asserting its absence could never fail).
		expect(logged).toMatch(/__log-capture-sentinel__/);
	});

	describe('canClaimUnregistered', () => {
		// The predicate is no longer called on the claim path — `RegistrationState`'s
		// payload-free `unregistered` arm enforces the invariant structurally — but it
		// stays exported for any future site that threads real observed records
		// alongside a non-existence claim. These exercise it directly so the retained
		// export is not untested.
		it('permits the claim only when nothing at all was observed', async () => {
			const { canClaimUnregistered } = await import('../src/tools/check-shadow-domains');
			expect(canClaimUnregistered({ ns: [], mx: [], hasSpf: false })).toBe(true);
		});

		it('refuses the claim when ANY record was observed', async () => {
			const { canClaimUnregistered } = await import('../src/tools/check-shadow-domains');
			expect(canClaimUnregistered({ ns: ['ns1.example.'], mx: [], hasSpf: false })).toBe(false);
			expect(canClaimUnregistered({ ns: [], mx: ['10 mail.example.'], hasSpf: false })).toBe(false);
			expect(canClaimUnregistered({ ns: [], mx: [], hasSpf: true })).toBe(false);
		});
	});

	it('re-queries NS in Phase 2 when Phase 1 proved registration without NS evidence', async () => {
		// A customer's own defensive registration, parked on the primary's
		// nameservers. Its Phase-1 NS query comes back empty under the lean
		// `timeoutMs: 2000, retries: 0` budget, but its SOA answers — so it is
		// bucketed `registered` with `ns: []` and `evidence: ['soa']`.
		//
		// Passing that empty `ns` straight through as `prefetchedNs` suppressed
		// the Phase-2 NS query, forcing `sharesNsWithPrimary` to false and making
		// the same-owner downgrade unreachable. The customer's own domain was then
		// reported to them as a CRITICAL hostile shadow domain. An incomplete
		// Phase-1 measurement must not drive a confident Phase-2 severity.
		const SHARED_NS = ['ns1.shared.example.', 'ns2.shared.example.'];
		let variantNsQueries = 0;
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			const q = parseDohQuery(input);
			if (!q) return emptyResponse();
			if (q.name === 'example.com') {
				if (q.type === 'NS') return nsRecords(q.name, SHARED_NS);
				return emptyResponse();
			}
			if (q.name !== 'example.net') return emptyResponse();
			if (q.type === 'NS') {
				// First (Phase-1, lean budget) answer is empty; the Phase-2 re-query
				// under full options sees the real delegation.
				variantNsQueries++;
				return variantNsQueries === 1 ? emptyResponse() : nsRecords(q.name, SHARED_NS);
			}
			if (q.type === 'SOA') return soaRecords(q.name);
			if (q.type === 'MX') return mxRecords(q.name, ['10 mail.shadow.example.']);
			return emptyResponse();
		}) as unknown as typeof fetch;

		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('example.com');

		// Phase 2 must actually re-query NS for the soa-evidence variant.
		expect(variantNsQueries).toBeGreaterThanOrEqual(2);

		const spoofable = result.findings.find((f) => (f.metadata as { variant?: string } | undefined)?.variant === 'example.net');
		expect(spoofable).toBeDefined();
		expect(spoofable!.title).toBe('Shadow domain fully spoofable');
		expect((spoofable!.metadata as { ns?: string[] }).ns).toEqual(SHARED_NS);
		// Shared nameservers => same owner => downgraded from critical to high.
		expect(spoofable!.severity).toBe('high');
	});
});

describe('checkShadowDomains — D4 ownership-gated severity', () => {
	async function run(domain: string) {
		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		return checkShadowDomains(domain);
	}

	/** All findings this scan made about one named variant, via metadata (never prose matching). */
	function forVariant(findings: Array<{ metadata?: Record<string, unknown> }>, variant: string) {
		return findings.filter((f) => (f.metadata as { variant?: string } | undefined)?.variant === variant);
	}

	it('caps a third-party variant at info instead of critical — and still EMITS it', async () => {
		// example.net is registered on its own unrelated registrar's nameservers:
		// no in-bailiwick NS, no NS-set overlap with the primary, no shared-provider
		// full match => classifyOwnership() returns `third_party`. Its record shape
		// (MX, no SPF, no DMARC) is the fully-spoofable ladder's top rung, so the
		// pre-fix classifier reported CRITICAL "Shadow domain fully spoofable" about
		// a domain the scanned organisation demonstrably does not control.
		//
		// The brand label here is `example` — 7 characters, comfortably past
		// MIN_ATTRIBUTION_LABEL_LENGTH — so this case ALSO pins that the ceiling is
		// gated on the ownership VERDICT and not on attributionConfidence(): a
		// confidence-gated implementation would read 'corroborated' here and let the
		// critical through.
		const target = 'example.com';
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;
			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.primary-dns.net.', 'ns2.primary-dns.net.']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.example.com.']));
			}
			if (name === 'example.net') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.unrelated-registrar.net.']));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.somewhere-else.net.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(emptyResponse());
			}
			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const netFindings = forVariant(result.findings, 'example.net');

		// DEMOTE, NEVER DELETE: the measurement is still reported.
		expect(netFindings.length).toBeGreaterThan(0);
		for (const f of netFindings) expect(f.severity).toBe('info');

		// Prose surface: no title may assert a spoofing posture the customer owns.
		expect(netFindings.some((f) => /fully spoofable|lacks DMARC|not enforcing|well-managed/i.test(f.title))).toBe(false);

		// Structured surface: the verdict is recorded, not merely implied by the severity.
		const gated = netFindings[0];
		expect((gated.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('third_party');
		expect(String((gated.metadata as { ownershipRationale?: string }).ownershipRationale)).toContain('example.net');
		// Wording must not imply the scanned organisation controls or must act on it.
		expect(gated.detail).toMatch(/no action .*is implied/i);
	});

	it('never attributes an Akamai-hosted variant to the seed on a 1/6 partial NS overlap', async () => {
		// The ANZ/Westpac trap from the design doc §3.3: bnz.co.nz and an unrelated
		// bank both sit on Akamai's shared NS pool, so one hostname in common is
		// operational plumbing, not ownership. `akam.net` is in SHARED_NS_APEXES
		// (Task 1), so the overlap contributes no dedicated-NS evidence and the
		// set match is 1/6, not complete => third_party.
		const target = 'bnz.co.nz';
		const seedNs = ['a1-97.akam.net.', 'a3-67.akam.net.', 'a8-66.akam.net.', 'a9-65.akam.net.', 'a16-65.akam.net.', 'a24-64.akam.net.'];
		const variantNs = ['a1-6.akam.net.', 'a3-66.akam.net.', 'a6-65.akam.net.', 'a9-65.akam.net.', 'a12-66.akam.net.', 'a28-67.akam.net.'];

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;
			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, seedNs));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.bnz.co.nz.']));
			}
			if (name === 'bnz.de') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, variantNs));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.somewhere-else.net.']));
			}
			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const deFindings = forVariant(result.findings, 'bnz.de');
		expect(deFindings.length).toBeGreaterThan(0);
		for (const f of deFindings) {
			expect(f.severity).toBe('info');
			expect((f.metadata as { ownershipVerdict?: string }).ownershipVerdict).not.toBe('owned_by_seed');
		}
	});

	it('keeps a short brand label’s uncorroborated match at info WITHOUT suppressing it', async () => {
		// `bnz` is 3 characters — below MIN_ATTRIBUTION_LABEL_LENGTH — and the
		// variant's mail infrastructure does not overlap the primary's, so
		// attributionConfidence() reports 'uncorroborated'. That governs WORDING
		// only: the finding is still emitted, at info. A guard that SUPPRESSED it
		// would fail the first assertion here (and the registration-invariant audit).
		const target = 'bnz.co.nz';
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;
			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.primary-dns.net.', 'ns2.primary-dns.net.']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.bnz.co.nz.']));
			}
			if (name === 'bnz.de') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.unrelated-registrar.net.']));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.somewhere-else.net.']));
			}
			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const deFindings = forVariant(result.findings, 'bnz.de');
		expect(deFindings.length).toBeGreaterThan(0);
		const gated = deFindings[0];
		expect(gated.severity).toBe('info');
		expect((gated.metadata as { attributionConfidence?: string }).attributionConfidence).toBe('uncorroborated');
		expect(gated.detail).toMatch(/name similarity alone/i);
	});

	it('still surfaces the customer-owned in-bailiwick variant above info', async () => {
		// bnz.nz delegates to nameservers UNDER the seed apex — the one signal an
		// attacker cannot forge without controlling the seed's own zone. Ownership
		// is established, so classifyVariant's ladder applies unclamped (critical,
		// softened one rung to high by the same-owner note).
		const target = 'bnz.co.nz';
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;
			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['a1-97.akam.net.']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.bnz.co.nz.']));
			}
			if (name === 'bnz.nz') {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.bnz.co.nz.', 'ns2.bnz.co.nz.']));
				if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.1']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.evil-shadow.net.']));
			}
			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const owned = forVariant(result.findings, 'bnz.nz');
		expect(owned.length).toBeGreaterThan(0);
		const spoofable = owned.find((f) => /fully spoofable/i.test(f.title));
		expect(spoofable).toBeDefined();
		expect(spoofable!.severity).toBe('high');
		expect((spoofable!.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('owned_by_seed');
	});

	it('gates the UNKNOWN-BUCKET RE-PROBE call site, not just the Phase-2 loop', async () => {
		// SECOND CALL SITE. example.net answers NOERROR-empty for NS, SOA and A, so
		// Phase 1 buckets it `unknown` — it never reaches the Phase-2 completed-probe
		// loop. The unknown re-probe then finds MX + SPF, proving registration, and
		// classifies it from its real records ('Shadow domain lacks DMARC', high).
		// Wiring only the Phase-2 site leaves this path emitting an ungated `high`
		// with no ownership verdict at all — the defect through the back door.
		const target = 'example.com';
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const q = parseDohQuery(input);
			if (!q) return Promise.resolve(emptyResponse());
			const { name, type } = q;
			if (name === target) {
				if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.primary-dns.net.', 'ns2.primary-dns.net.']));
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.example.com.']));
			}
			if (name === 'example.net') {
				// NS / SOA / A all NOERROR-empty => Phase 1 verdict `unknown`.
				if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.attacker.net.']));
				if (type === 'TXT' || type === '16') return Promise.resolve(txtRecords(name, ['v=spf1 include:sendgrid.net ~all']));
			}
			return Promise.resolve(emptyResponse());
		});

		const result = await run(target);
		const netFindings = forVariant(result.findings, 'example.net');
		// The re-probe path must have run and reclassified it (not left it "unknown").
		const reclassified = netFindings.find((f) => (f.metadata as { hasSpf?: boolean }).hasSpf === true);
		expect(reclassified).toBeDefined();
		// …and it must carry an ownership verdict and be capped, exactly like Phase 2.
		expect((reclassified!.metadata as { ownershipVerdict?: string }).ownershipVerdict).toBe('unattributed');
		expect(reclassified!.severity).toBe('info');
		expect(/lacks DMARC/i.test(reclassified!.title)).toBe(false);
		for (const f of netFindings) expect(f.severity).toBe('info');
	});
});
