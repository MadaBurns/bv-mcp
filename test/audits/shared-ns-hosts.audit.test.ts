// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: SHARED_NS_APEXES coverage for the NS-correlator multi-tenant filter.
 *
 * The well-known parking services, registrar-default NS hosts and every
 * uniform-set / small-pool platform measured for #939 MUST be classified as
 * shared-tenant so an overlap on their hostnames neither inflates
 * brand-discovery confidence nor reaches `classifyOwnership()`'s dedicated
 * `ns_set_match` arm. Cloudflare and Route 53 are pinned as NOT shared-tenant:
 * re-measured 2026-09-09 (14,062 Tranco domains) they draw per-account /
 * per-zone hostnames from a large pool, so an overlap there is ownership
 * evidence. Gandi LiveDNS is pinned as not-listed as the CURRENT state (47
 * distinct 3-host sets across 48 sampled tenants — no repeat observed, pool
 * unbounded) — membership is an evidence decision (#929), never an
 * assumption. Every pin below names a REAL hostname so a public-suffix
 * surprise (`ns1.dns.ne.jp` registers under `ne.jp`) shows up here, not in
 * production.
 *
 * Ref: v2.14.0 audit, LR-2 (Slice 6 defense-in-depth).
 */

import { describe, it, expect } from 'vitest';
import {
	isPooledSharedNsHost,
	isSharedNsHost,
	POOLED_SHARED_NS_APEXES,
	SHARED_NS_APEXES,
} from '../../src/tenants/discovery/shared-ns-hosts';

const SHARED_NS_MUST_MATCH: ReadonlyArray<readonly [string, string]> = [
	// Parking services
	['ns1.sedoparking.com', 'Sedo parking'],
	['ns2.sedoparking.com', 'Sedo parking'],
	['ns1.parkingcrew.com', 'ParkingCrew'],
	['dns1.bodis.com', 'Bodis parking'],
	['ns1.dan.com', 'Dan.com / Sedo parking'],
	['ns1.above.com', 'Above.com parking'],
	['ns1.dnsowl.com', 'DNSOwl parking'],
	// GoDaddy default / parked
	['ns01.domaincontrol.com', 'GoDaddy default NS (parked or default-registered)'],
	['ns73.domaincontrol.com', 'GoDaddy default NS — high-number variant'],
	['ns1.secureserver.net', 'GoDaddy secureserver'],
	// Namecheap registrar default
	['dns1.registrar-servers.com', 'Namecheap registrar-default NS'],
	// one.com shared hosting — identical pair for every tenant (#929, live 2026-09-09)
	['ns01.one.com', 'one.com shared hosting — every tenant gets ns01/ns02'],
	['ns02.one.com', 'one.com shared hosting — every tenant gets ns01/ns02'],
	// #939 — uniform-set / small-pool platforms, each measured on two unrelated
	// tenants over Cloudflare + Google DoH, 2026-09-09 (tenants in the entry
	// comments in shared-ns-hosts.ts and the #939 PR evidence table).
	['ns1.dns-parking.com', 'Hostinger default — identical ns1/ns2 for every tenant'],
	['ns2.dns-parking.com', 'Hostinger default — identical ns1/ns2 for every tenant'],
	['ns0.wixdns.net', 'Wix — pairs from a pool of ~8'],
	['ns15.wixdns.net', 'Wix — pairs from a pool of ~8 (high-number variant)'],
	['ns01.squarespacedns.com', 'Squarespace Domains — same ns01-04 on every tenant'],
	['dns1.p01.nsone.net', 'NS1 — p0N quartets from a pool of ~9'],
	['ns-cloud-a1.googledomains.com', 'Google Cloud DNS — one of five fixed sets (was pinned as NOT listed before #939)'],
	['ns-cloud-e4.googledomains.com', 'Google Cloud DNS — one of five fixed sets'],
	['ns1045.ui-dns.com', 'IONOS — same ns{N} handed to unrelated tenants'],
	['ns1045.ui-dns.de', 'IONOS — .de apex of the same set'],
	['ns1045.ui-dns.org', 'IONOS — .org apex of the same set'],
	['ns1045.ui-dns.biz', 'IONOS — .biz apex of the same set'],
	['ns1.bluehost.com', 'Bluehost — uniform ns1/ns2'],
	['docks08.rzone.de', 'Strato — docks/shades pairs from a small pool'],
	['shades18.rzone.de', 'Strato — docks/shades pairs from a small pool'],
	['hydrogen.ns.hetzner.com', 'Hetzner DNS Console — uniform 3-host set'],
	['helium.ns.hetzner.de', 'Hetzner DNS Console — .de apex of the same set'],
	['ns1.first-ns.de', 'Hetzner Robot — uniform 3-host set'],
	['robotns2.second-ns.de', 'Hetzner Robot — uniform 3-host set'],
	['robotns3.second-ns.com', 'Hetzner Robot — uniform 3-host set'],
	['ns1.your-server.de', 'Hetzner Robot (older set) — uniform'],
	['dns100.ovh.net', 'OVH — dnsN/nsN pairs from a small pool'],
	['ns14.ovh.net', 'OVH — dnsN/nsN pairs from a small pool'],
	['dns200.anycast.me', 'OVH anycast — uniform dns200/ns200'],
	['ns1.digital.govt.nz', 'digital.govt.nz — shared NZ-government platform, identical ns1-5 on 13 agencies'],
	['ns5.digital.govt.nz', 'digital.govt.nz — shared NZ-government platform (registrable apex under govt.nz)'],
	['ns1.digitalocean.com', 'DigitalOcean — uniform ns1-3'],
	['ns5.linode.com', 'Linode — uniform ns1-5'],
	['ns1.vercel-dns.com', 'Vercel — uniform ns1/ns2'],
	['ns2.hover.com', 'Hover — uniform ns1/ns2'],
	['ns1.dnsimple.com', 'DNSimple — uniform ns1-4'],
	['ns1.dnsimple-edge.com', 'DNSimple edge — uniform 4-apex set'],
	['ns2.dnsimple-edge.net', 'DNSimple edge — uniform 4-apex set'],
	['ns3.dnsimple-edge.io', 'DNSimple edge — uniform 4-apex set'],
	['ns4.dnsimple-edge.org', 'DNSimple edge — uniform 4-apex set'],
	['ns1.dreamhost.com', 'DreamHost — uniform ns1-3'],
	['ns1.siteground.net', 'SiteGround — uniform ns1/ns2'],
	['curitiba.ns.porkbun.com', 'Porkbun — uniform 4-host set'],
	['ns1.eurodns.com', 'EuroDNS — uniform ns1-4'],
	['ns1.dyna-ns.net', 'Dynadot — uniform ns1/ns2'],
	['dns1.cscdns.net', 'CSC — uniform dns1/dns2 shared by unrelated enterprises'],
	['udns2.cscdns.uk', 'CSC — .uk half of the udns set'],
	['ns1.markmonitor.com', 'MarkMonitor — uniform ns1-7 shared by unrelated enterprises'],
	['ns0.dnsmadeeasy.com', 'DNS Made Easy — fixed shared sets'],
	['ns11.constellix.com', 'Constellix — fixed shared set'],
	['ns41.constellix.net', 'Constellix — .net half of the same set'],
	['pdns1.ultradns.net', 'UltraDNS — shared pdns1-6 set'],
	['pdns3.ultradns.org', 'UltraDNS — shared pdns1-6 set'],
	['pdns5.ultradns.info', 'UltraDNS — shared pdns1-6 set'],
	['pdns6.ultradns.co.uk', 'UltraDNS — shared pdns1-6 set (registrable apex under co.uk)'],
	['pdns109.ultradns.com', 'UltraDNS — numbered sets are shared too'],
	['pdns109.ultradns.biz', 'UltraDNS — numbered sets are shared too'],
	['ns1-09.azure-dns.com', 'Azure DNS — numbered sets from a pool of ~23'],
	['ns2-09.azure-dns.net', 'Azure DNS — numbered sets from a pool of ~23'],
	['ns3-09.azure-dns.org', 'Azure DNS — numbered sets from a pool of ~23'],
	['ns4-09.azure-dns.info', 'Azure DNS — numbered sets from a pool of ~23'],
	['ns47.worldnic.com', 'Network Solutions — nsNN pairs from a small pool'],
	['pns21.cloudns.net', 'ClouDNS — shared quartets'],
	['dns1.namecheaphosting.com', 'Namecheap shared hosting — uniform dns1/dns2'],
	['launch1.spaceship.net', 'Spaceship — uniform launch1/launch2'],
	['vip3.alidns.com', 'Alibaba Cloud DNS — fixed vip pairs'],
	['dns9.hichina.com', 'HiChina — fixed dnsN pairs'],
	['f1g1ns1.dnspod.net', 'DNSPod — fixed f1g1ns1/2 pair'],
	['ns3.dnsv4.com', 'dnsv4 — fixed pair'],
	['a.share-dns.com', 'share-dns — uniform a/b set'],
	['b.share-dns.net', 'share-dns — .net half of the same set'],
	['ns11.xincache.com', 'Xinnet — fixed pairs'],
	['ns1.reg.ru', 'REG.RU — uniform ns1/ns2'],
	['ns1.timeweb.ru', 'Timeweb — uniform 4-host set'],
	['ns3.timeweb.org', 'Timeweb — .org half of the same set'],
	['ns1.beget.com', 'Beget — uniform 6-host set'],
	['ns1.beget.pro', 'Beget — uniform 6-host set'],
	['ns2.beget.ru', 'Beget — uniform 6-host set'],
	['a.ns.selectel.ru', 'Selectel — uniform a-d set'],
	['ns4-l2.nic.ru', 'RU-CENTER — fixed shared set'],
	['dns1.yandex.net', 'Yandex 360 — uniform dns1/dns2'],
	['ns1.yandexcloud.net', 'Yandex Cloud — uniform ns1/ns2'],
	['01.dnsv.jp', 'GMO — uniform 01-04'],
	['ns1.dns.ne.jp', 'Sakura — uniform ns1/ns2 (registrable apex dns.ne.jp under the ne.jp public suffix)'],
	['a.ns14.net', 'ns14.net — uniform a-d'],
	['dns.technorail.com', 'Aruba — uniform 3-apex set'],
	['dns3.arubadns.net', 'Aruba — uniform 3-apex set'],
	['dns4.arubadns.cz', 'Aruba — uniform 3-apex set'],
	// Akamai — hostnames are shared across unrelated customers (2026-07-26
	// correctness-defects design §3.3: bnz.co.nz shares a9-65.akam.net with
	// anz.co.nz and a3-67.akam.net with westpac.co.nz — three competing banks).
	['a1-97.akam.net', 'Akamai — shared across unrelated customer zones'],
	['a9-65.akam.net', 'Akamai — shared across unrelated customer zones'],
];

const SHARED_NS_MUST_NOT_MATCH: ReadonlyArray<readonly [string, string]> = [
	// Hyperscale managed DNS — unique NS per account, overlap IS evidence
	['alice.ns.cloudflare.com', 'Cloudflare assigns unique NS per account'],
	['bob.ns.cloudflare.com', 'Cloudflare assigns unique NS per account'],
	['ns-1234.awsdns-56.com', 'AWS Route 53 assigns unique NS per hosted zone'],
	// Gandi LiveDNS draws `ns-N-{a,b,c}.gandi.net` per zone from a large pool:
	// 47 distinct sets across 48 sampled tenants, no repeat (#939, 2026-09-09).
	// Pinned as the CURRENT state, not as proof of uniqueness.
	['ns-67-b.gandi.net', 'Gandi LiveDNS — no shared complete set observed; pinned as-is'],
	// User-controlled / clearly unrelated
	['ns1.example.com', 'Generic example domain'],
	['blackveilsecurity.com', 'Our own apex (defensive)'],
];

describe('SHARED_NS_APEXES coverage — parking / registrar-default NS', () => {
	for (const [ns, reason] of SHARED_NS_MUST_MATCH) {
		it(`classifies ${ns} as shared-tenant (${reason})`, () => {
			expect(isSharedNsHost(ns)).toBe(true);
		});
	}
});

describe('SHARED_NS_APEXES non-coverage — hyperscale DNS must remain ownership-bearing', () => {
	for (const [ns, reason] of SHARED_NS_MUST_NOT_MATCH) {
		it(`does NOT classify ${ns} as shared-tenant (${reason})`, () => {
			expect(isSharedNsHost(ns)).toBe(false);
		});
	}

	it('returns false for empty / whitespace input (defensive)', () => {
		expect(isSharedNsHost('')).toBe(false);
		expect(isSharedNsHost('   ')).toBe(false);
	});
});

describe('POOLED_SHARED_NS_APEXES — the only shared providers a complete NS-set match may credit (#929)', () => {
	it('is a strict subset of SHARED_NS_APEXES (a pooled host must also be excluded from the dedicated arm)', () => {
		expect(POOLED_SHARED_NS_APEXES.size).toBeGreaterThan(0);
		expect(POOLED_SHARED_NS_APEXES.size).toBeLessThan(SHARED_NS_APEXES.size);
		for (const apex of POOLED_SHARED_NS_APEXES) expect(SHARED_NS_APEXES.has(apex)).toBe(true);
	});

	it('classes Akamai as pooled (six hosts per zone from a large pool — a 6/6 match is one account)', () => {
		expect(isPooledSharedNsHost('a1-97.akam.net')).toBe(true);
	});

	for (const [ns] of SHARED_NS_MUST_MATCH) {
		if (ns.endsWith('.akam.net')) continue;
		it(`does NOT class ${ns} as pooled — every tenant of that platform receives the same set`, () => {
			expect(isPooledSharedNsHost(ns)).toBe(false);
		});
	}

	it('#939 added no pooled apex — Akamai remains the only member (each new platform was measured uniform or small-pool)', () => {
		expect([...POOLED_SHARED_NS_APEXES]).toEqual(['akam.net']);
	});
});
