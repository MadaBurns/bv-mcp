import { describe, it, expect } from 'vitest';
import {
	CLOUDFLARE_IPV4_RANGES,
	isIpInCloudflareRange,
	detectCloudflareViaNsAndIp,
	detectCloudflareFallback,
} from '../src/lib/cdn-fallback-detection';

describe('CLOUDFLARE_IPV4_RANGES', () => {
	it('includes all 15 published Cloudflare IPv4 ranges', () => {
		// Snapshot the canonical published list; if Cloudflare adds/removes a
		// range, this assertion forces a deliberate update.
		expect(CLOUDFLARE_IPV4_RANGES).toEqual([
			'103.21.244.0/22',
			'103.22.200.0/22',
			'103.31.4.0/22',
			'104.16.0.0/13',
			'104.24.0.0/14',
			'108.162.192.0/18',
			'131.0.72.0/22',
			'141.101.64.0/18',
			'162.158.0.0/15',
			'172.64.0.0/13',
			'173.245.48.0/20',
			'188.114.96.0/20',
			'190.93.240.0/20',
			'197.234.240.0/22',
			'198.41.128.0/17',
		]);
	});
});

describe('isIpInCloudflareRange', () => {
	it('matches across all 15 published CF ranges (one sample per range)', () => {
		// Sample one IP per range to prove the CIDR table is wired correctly.
		expect(isIpInCloudflareRange('103.21.244.10')).toBe(true); // 103.21.244.0/22
		expect(isIpInCloudflareRange('103.22.200.10')).toBe(true); // 103.22.200.0/22
		expect(isIpInCloudflareRange('103.31.4.10')).toBe(true); // 103.31.4.0/22
		expect(isIpInCloudflareRange('104.16.45.99')).toBe(true); // 104.16.0.0/13
		expect(isIpInCloudflareRange('104.24.10.10')).toBe(true); // 104.24.0.0/14
		expect(isIpInCloudflareRange('108.162.192.10')).toBe(true); // 108.162.192.0/18
		expect(isIpInCloudflareRange('131.0.72.10')).toBe(true); // 131.0.72.0/22
		expect(isIpInCloudflareRange('141.101.64.10')).toBe(true); // 141.101.64.0/18
		expect(isIpInCloudflareRange('162.158.0.10')).toBe(true); // 162.158.0.0/15
		expect(isIpInCloudflareRange('172.64.149.224')).toBe(true); // 172.64.0.0/13
		expect(isIpInCloudflareRange('173.245.48.10')).toBe(true); // 173.245.48.0/20
		expect(isIpInCloudflareRange('188.114.96.10')).toBe(true); // 188.114.96.0/20
		expect(isIpInCloudflareRange('190.93.240.10')).toBe(true); // 190.93.240.0/20
		expect(isIpInCloudflareRange('197.234.240.10')).toBe(true); // 197.234.240.0/22
		expect(isIpInCloudflareRange('198.41.128.10')).toBe(true); // 198.41.128.0/17
	});

	it('rejects IPs outside Cloudflare ranges', () => {
		expect(isIpInCloudflareRange('8.8.8.8')).toBe(false);
		expect(isIpInCloudflareRange('192.168.1.1')).toBe(false);
		expect(isIpInCloudflareRange('1.1.1.1')).toBe(false);
		// Edge-adjacent: 104.15.255.255 is just outside 104.16.0.0/13.
		expect(isIpInCloudflareRange('104.15.255.255')).toBe(false);
	});

	it('returns false for malformed input rather than throwing', () => {
		expect(isIpInCloudflareRange('not-an-ip')).toBe(false);
		expect(isIpInCloudflareRange('')).toBe(false);
		expect(isIpInCloudflareRange('999.999.999.999')).toBe(false);
		expect(isIpInCloudflareRange('1.2.3')).toBe(false);
	});
});

describe('detectCloudflareViaNsAndIp', () => {
	it('attributes CF when NS matches *.ns.cloudflare.com AND A record in CF range', () => {
		// Real-world shape: ietf.org has NS on Cloudflare and serves A records
		// from Cloudflare's edge — but no header-based detection works because
		// the scanner runs inside a CF Worker which rewrites server: cloudflare
		// on every outbound response.
		expect(
			detectCloudflareViaNsAndIp({
				nsHosts: ['jill.ns.cloudflare.com', 'ken.ns.cloudflare.com'],
				aRecords: ['104.16.45.99', '104.16.44.99'],
			}),
		).toEqual({ provider: 'Cloudflare', confidence: 'heuristic' });
	});

	it('does NOT attribute CF when NS matches but A records are outside CF ranges', () => {
		// Customer points NS at Cloudflare for DNS-only management but resolves
		// to a non-CF origin (eg. self-hosted, AWS, GCP). DNS is on CF, edge is
		// not — don't claim CDN attribution.
		expect(
			detectCloudflareViaNsAndIp({
				nsHosts: ['jill.ns.cloudflare.com', 'ken.ns.cloudflare.com'],
				aRecords: ['8.8.8.8'],
			}),
		).toBeNull();
	});

	it('does NOT attribute CF when A records in CF range but NS is elsewhere (transit-only scenario)', () => {
		// Someone behind a CF transit IP but using a different NS provider.
		// Not a CF customer — don't claim CDN attribution.
		expect(
			detectCloudflareViaNsAndIp({
				nsHosts: ['ns-1.awsdns-01.com'],
				aRecords: ['104.16.45.99'],
			}),
		).toBeNull();
	});

	it('does NOT attribute when both signals absent', () => {
		expect(
			detectCloudflareViaNsAndIp({
				nsHosts: ['ns-1.awsdns-01.com'],
				aRecords: ['8.8.8.8'],
			}),
		).toBeNull();
	});

	it('does NOT attribute when NS list is empty', () => {
		expect(
			detectCloudflareViaNsAndIp({
				nsHosts: [],
				aRecords: ['104.16.45.99'],
			}),
		).toBeNull();
	});

	it('does NOT attribute when A record list is empty', () => {
		expect(
			detectCloudflareViaNsAndIp({
				nsHosts: ['jill.ns.cloudflare.com', 'ken.ns.cloudflare.com'],
				aRecords: [],
			}),
		).toBeNull();
	});

	it('requires ALL NS hosts on Cloudflare (mixed NS does NOT attribute)', () => {
		// Mixed NS (CF + non-CF) is an unusual config but doesn't prove the
		// origin is on CF — could be a partial migration. Stay conservative.
		expect(
			detectCloudflareViaNsAndIp({
				nsHosts: ['jill.ns.cloudflare.com', 'ns-1.awsdns-01.com'],
				aRecords: ['104.16.45.99'],
			}),
		).toBeNull();
	});

	it('attributes CF when AT LEAST ONE A record is in CF range', () => {
		// Multi-A zones (CF DNS often returns multiple A records) — one
		// in-range record is sufficient corroboration.
		expect(
			detectCloudflareViaNsAndIp({
				nsHosts: ['jill.ns.cloudflare.com', 'ken.ns.cloudflare.com'],
				aRecords: ['8.8.8.8', '104.16.45.99'],
			}),
		).toEqual({ provider: 'Cloudflare', confidence: 'heuristic' });
	});
});

describe('detectCloudflareFallback — cert-issuer signal (v3.3.17 extension)', () => {
	it('attributes CF when A-record in CF range AND cert issuer is Cloudflare, even when NS is external (external-DNS-on-CF pattern)', () => {
		// External NS provider (eg. Foundation DNS) + origin on CF edge + CF-issued
		// cert. Signal A absent (NS not on CF), but B+C present → 2-of-3 → attribute.
		// This is the real-world gap the cert-issuer signal closes.
		expect(
			detectCloudflareFallback({
				nsHosts: ['gold.foundationdns.com', 'gold.foundationdns.net'], // EXTERNAL DNS
				aRecords: ['104.16.45.99'], // CF published range (104.16.0.0/13)
				certIssuer: 'C=US, O=Cloudflare, Inc., CN=Cloudflare Inc ECC CA-3',
			}),
		).toEqual({ provider: 'Cloudflare', confidence: 'heuristic' });
	});

	it('attributes CF when NS on CF AND cert issuer is Cloudflare, even when A-records are not in any published CF range', () => {
		expect(
			detectCloudflareFallback({
				nsHosts: ['jill.ns.cloudflare.com', 'ken.ns.cloudflare.com'],
				aRecords: ['8.8.8.8'], // not in any published CF range
				certIssuer: 'CN=Cloudflare Origin SSL ECC Issuer ECC',
			}),
		).toEqual({ provider: 'Cloudflare', confidence: 'heuristic' });
	});

	it('does NOT attribute CF when only cert issuer matches (single signal)', () => {
		expect(
			detectCloudflareFallback({
				nsHosts: ['ns-1.awsdns-01.com'],
				aRecords: ['8.8.8.8'],
				certIssuer: 'CN=Cloudflare Inc ECC CA-3',
			}),
		).toBeNull();
	});

	it('does NOT attribute CF when only A-record is in CF range (single signal, transit case)', () => {
		expect(
			detectCloudflareFallback({
				nsHosts: ['ns-1.awsdns-01.com'],
				aRecords: ['104.16.45.99'], // CF range
				certIssuer: 'CN=DigiCert TLS RSA SHA256 2020 CA1', // not CF
			}),
		).toBeNull();
	});

	it('matches Cloudflare Origin SSL ECC Issuer ECC (the origin-CA variant)', () => {
		expect(
			detectCloudflareFallback({
				nsHosts: ['gold.foundationdns.com'],
				aRecords: ['104.16.45.99'],
				certIssuer: 'CN=Cloudflare Origin SSL ECC Issuer ECC, O=Cloudflare, Inc., L=San Francisco, C=US',
			}),
		).toEqual({ provider: 'Cloudflare', confidence: 'heuristic' });
	});

	it('case-insensitive on the cert issuer match', () => {
		expect(
			detectCloudflareFallback({
				nsHosts: ['gold.foundationdns.com'],
				aRecords: ['104.16.45.99'],
				certIssuer: 'cn=cloudflare inc ecc ca-3, o=CLOUDFLARE, INC.',
			}),
		).toEqual({ provider: 'Cloudflare', confidence: 'heuristic' });
	});

	it('handles null/undefined cert issuer gracefully (degrades to old NS+IP-only behavior)', () => {
		// NS not on CF, no cert signal → single signal (IP) only → null
		expect(
			detectCloudflareFallback({
				nsHosts: ['gold.foundationdns.com'],
				aRecords: ['104.16.45.99'],
				certIssuer: null,
			}),
		).toBeNull();

		// NS on CF, A in CF range, certIssuer omitted entirely → 2 signals (A + B) → attribute
		expect(
			detectCloudflareFallback({
				nsHosts: ['jill.ns.cloudflare.com'],
				aRecords: ['104.16.45.99'],
			}),
		).toEqual({ provider: 'Cloudflare', confidence: 'heuristic' });
	});

	it('attributes CF when all three signals present (NS + IP + cert)', () => {
		expect(
			detectCloudflareFallback({
				nsHosts: ['jill.ns.cloudflare.com', 'ken.ns.cloudflare.com'],
				aRecords: ['104.16.45.99'],
				certIssuer: 'CN=Cloudflare Inc ECC CA-3',
			}),
		).toEqual({ provider: 'Cloudflare', confidence: 'heuristic' });
	});

	it('treats empty aRecords as signal-B-absent (NS+cert still attributes with 2 signals)', () => {
		// Regression guard: empty A-record list does NOT short-circuit when the
		// other two signals are present. Old NS+IP-only function returned null on
		// empty A; new 2-of-3 rule treats signal B as absent and lets A+C attribute.
		expect(
			detectCloudflareFallback({
				nsHosts: ['jill.ns.cloudflare.com', 'ken.ns.cloudflare.com'],
				aRecords: [],
				certIssuer: 'CN=Cloudflare Inc ECC CA-3',
			}),
		).toEqual({ provider: 'Cloudflare', confidence: 'heuristic' });
	});

	it('treats empty nsHosts as signal-A-absent (IP+cert still attributes with 2 signals)', () => {
		expect(
			detectCloudflareFallback({
				nsHosts: [],
				aRecords: ['104.16.45.99'],
				certIssuer: 'CN=Cloudflare Inc ECC CA-3',
			}),
		).toEqual({ provider: 'Cloudflare', confidence: 'heuristic' });
	});

	it('returns null when no signals present at all', () => {
		expect(
			detectCloudflareFallback({
				nsHosts: [],
				aRecords: [],
				certIssuer: null,
			}),
		).toBeNull();
	});
});

describe('detectCloudflareViaNsAndIp — backward-compat wrapper', () => {
	it('still requires BOTH NS+IP and ignores cert-issuer (deprecated NS+IP-only contract)', () => {
		// Confirms the deprecated wrapper preserves its conservative gate
		// regardless of any new cert-issuer plumbing on the underlying function.
		expect(
			detectCloudflareViaNsAndIp({
				nsHosts: ['jill.ns.cloudflare.com'],
				aRecords: ['8.8.8.8'],
			}),
		).toBeNull();
	});
});
