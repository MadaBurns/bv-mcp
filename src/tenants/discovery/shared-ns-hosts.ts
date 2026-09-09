// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared-tenant NS hosts — apex domains of nameserver providers that assign
 * the *same* NS hostnames to many unrelated customers.
 *
 * NS overlap is normally a strong ownership signal: two zones delegating to
 * the exact same nameserver hostnames typically share a DNS account. But
 * parking services and some shared-hosting / registrar-default platforms
 * publish the same `ns1.X.com` / `ns2.X.com` pair across thousands of
 * unrelated zones, so an overlap there is operational plumbing, not
 * ownership evidence.
 *
 * Cloudflare and Route 53 are deliberately NOT in this set: they draw NS
 * hostnames per account / per zone from a large pool, so an overlap there
 * still implies same-account ownership. Both were re-measured for #939
 * (2026-09-09, 14,062 resolved Tranco domains): Route 53 repeated a complete
 * 4-host set only within one organisation (zooplus.*, condenast/vogue/gq);
 * Cloudflare produced 4,661 distinct pairs across 5,254 tenants, its repeats
 * consistent with multi-domain accounts. Google Cloud DNS is NOT in that
 * class — it hands out one of five fixed `ns-cloud-{a..e}{1..4}` sets — and
 * is listed below.
 *
 * The ns-correlator drops shared-NS entries whose apex matches this set
 * from its `confidence` math; if ALL shared NS land here, the candidate is
 * skipped entirely (no signal contribution).
 *
 * TWO CLASSES OF SHARED PROVIDER (#929, 2026-09-09). `classifyOwnership()`
 * (`src/lib/ownership-attribution.ts`) credits a COMPLETE NS-set match on a
 * shared provider as medium ownership evidence — but that is only true where
 * the provider draws hostnames per zone from a large POOL (Akamai: six from
 * ~128 `a*-*.akam.net` hosts, so an identical 6/6 set means one account).
 * A platform that hands EVERY tenant the same set — one.com's `ns01`/`ns02`,
 * a parking service's `ns1`/`ns2`, a registrar default — makes a complete
 * match the DEFAULT relationship between two unrelated customers, and a
 * squatter who hosts a lookalike on the same platform would earn the seed's
 * `owned_by_seed` (and its `info` severity ceiling) for free. Measured live
 * 2026-09-09: `net-agents.dk`, `net-agent.dk` and `net-agents.com` all
 * delegate to `ns01.one.com` / `ns02.one.com`, and were attributed to each
 * other at confidence 1.00. So membership here is split: every apex in
 * `SHARED_NS_APEXES` is excluded from the dedicated-NS arm, and ONLY the
 * `POOLED_SHARED_NS_APEXES` subset may earn the complete-match arm. The
 * default for a new shared platform is therefore the safe one — add it to
 * `SHARED_NS_APEXES` and it can never attribute; promote it to the pooled
 * subset only with evidence that its complete sets are per-account.
 *
 * Ref: v2.14.0 audit, leakage risk LR-2 (defense-in-depth at the correlator
 * layer; the orchestrator's corroboration gate already filters single-signal
 * NS, this covers two-signal scenarios where parking-NS would otherwise
 * inflate combined confidence).
 */

import { registeredApex } from './infrastructure-providers';

/**
 * Apex-form (2-label) domains of NS providers that assign shared NS
 * hostnames across many unrelated customers.
 *
 * Membership bar (rewritten 2026-09-09, #929): list a provider when two
 * UNRELATED tenants can be observed sharing NS hostnames. The cost of a
 * missing entry is a manufacturable `owned_by_seed` — a squatter hosting a
 * lookalike on the seed's platform earns the seed's severity ceiling — which
 * is worse than the cost of an extra entry (an ownership lead that must be
 * corroborated some other way). Verify with two tenants over DoH before
 * adding; record the measurement in the entry's comment.
 *
 * #939 (2026-09-09): the bar was applied at scale. A sweep of 14,334 Tranco
 * domains (ranks 20k–1M, NS over Cloudflare + Google DoH, 14,062 resolved)
 * was grouped by exact NS set; every apex below whose comment cites "#939"
 * showed an IDENTICAL complete set on at least three tenants that are
 * visibly different organisations, and the two named tenants were then
 * re-read from both resolvers. A platform whose sets are drawn from a pool
 * SMALL enough that unrelated tenants collide (GoDaddy's ~50 pairs, OVH's
 * `dnsN`/`nsN`, Azure's 23 numbered sets, Cloud DNS's five) is listed on the
 * same evidence as a uniform-set one: a complete match there is not
 * per-account. Two tenant names per entry, not the whole sample; the raw
 * table is in the PR for #939. Multi-apex sets (IONOS, UltraDNS, Hetzner
 * Robot, Aruba, DNSimple edge) list EVERY apex the set spans — half-listing
 * a set leaves the other half counting as "dedicated" and `ns_set_match`'s
 * >=50% bar is met by that half alone (Squarespace: 4 platform + 4 NS1 hosts).
 */
export const SHARED_NS_APEXES: ReadonlySet<string> = new Set([
	// Parking services
	'sedoparking.com',
	'parkingcrew.com',
	'parkingcrew.net',
	'bodis.com',
	'cashparking.com',
	'dan.com',
	'above.com',
	'internettraffic.com',
	'dnsowl.com',
	'parklogic.com',
	// GoDaddy default / parked / shared — ~50 `nsNN`/`nsNN+1` pairs over 489
	// sampled tenants (#939: stonyfield.com and centerforfoodsafety.org both
	// on ns33/ns34.domaincontrol.com, 2026-09-09).
	'domaincontrol.com',
	'secureserver.net',
	// Namecheap registrar-default — BasicDNS `dns1`/`dns2` (111 of 122
	// sampled tenants; #939: candidthemes.com, bighugelabs.com) and PremiumDNS
	// `pdns1`/`pdns2` (seedr.cc, sketchucation.com), 2026-09-09.
	'registrar-servers.com',
	// Namecheap shared hosting `dns1`/`dns2.namecheaphosting.com` (#939:
	// airsial.com, drawingdatabase.com, 2026-09-09) and Spaceship
	// `launch1`/`launch2` (openstepnews.com, itray.net).
	'namecheaphosting.com',
	'spaceship.net',
	// one.com shared hosting — every tenant delegates to the identical
	// `ns01.one.com` / `ns02.one.com` pair (#929; verified live 2026-09-09 on
	// net-agents.dk, net-agent.dk, net-agents.com). NOT pooled: a complete
	// 2/2 match is what any two one.com customers look like.
	'one.com',
	// Hostinger — `ns1`/`ns2.dns-parking.com` is the default for every
	// Hostinger domain, parked or live (#939: debugpoint.com, sweetberry.gr;
	// 69 of 95 sampled tenants on the identical pair, 2026-09-09).
	'dns-parking.com',
	// Wix — pairs `ns{2k}`/`ns{2k+1}.wixdns.net` from a pool of ~8 (#939:
	// lviusa.com and interclinicapuertovaras.cl on ns0/ns1; tendersgo.com and
	// myhomepropertymarketing.com on ns2/ns3, 2026-09-09).
	'wixdns.net',
	// Squarespace Domains — every tenant carries the same
	// `ns01`–`ns04.squarespacedns.com` plus one NS1 `dns1-4.p0N.nsone.net`
	// quartet (#939: usahockeymagazine.com p05, biosites.com p06, 2026-09-09).
	// The four squarespacedns hosts alone are 4/8 = the ns_set_match bar.
	'squarespacedns.com',
	// NS1 (IBM) — `dns1-4.p0N.nsone.net` quartets, N from a pool of ~9 (#939:
	// zonealarm.com and gooddata.com both on p01, 2026-09-09).
	'nsone.net',
	// Google Cloud DNS / Google Domains — one of five FIXED sets
	// `ns-cloud-{a..e}{1..4}.googledomains.com`, manufacturable by any GCP
	// project (#939: americanbanker.com and edmontonjournal.com on set b;
	// motorcycle.com and japanknowledge.com on set a; local.ch and macon.com
	// on set c; 1001fonts.com and aptoslabs.com on set d; cardinalhealth.com
	// and rewe-group.com on set e — 2026-09-09).
	'googledomains.com',
	// IONOS (1&1) — `ns{N}.ui-dns.{com,de,org,biz}`; the same N is handed to
	// unrelated tenants (#939: calcionapoli24.it, aicateringequipments.ie and
	// hoteldesigns.net all on ns1045 x4, 2026-09-09).
	'ui-dns.com',
	'ui-dns.de',
	'ui-dns.org',
	'ui-dns.biz',
	// Bluehost — uniform `ns1`/`ns2.bluehost.com` (#939: godandscience.org,
	// heraldwholesale.com, 2026-09-09).
	'bluehost.com',
	// Strato — `docksNN`/`shadesNN.rzone.de` pairs from a small pool (#939:
	// handball360.net and elsbett.com both on docks08/shades18, 2026-09-09).
	'rzone.de',
	// Hetzner DNS Console — uniform `hydrogen`/`oxygen.ns.hetzner.com` +
	// `helium.ns.hetzner.de` (#939: edudip.com, echo-online.de, 2026-09-09).
	'hetzner.com',
	'hetzner.de',
	// Hetzner Robot — uniform `ns1.first-ns.de` / `robotns2.second-ns.de` /
	// `robotns3.second-ns.com` (#939: netzpolitik.org, jtl-software.de) and
	// the older `ns1.your-server.de` / `ns.second-ns.com` / `ns3.second-ns.de`
	// set (namibia-forum.ch, retailads.net), 2026-09-09.
	'first-ns.de',
	'second-ns.de',
	'second-ns.com',
	'your-server.de',
	// OVH — `dnsN`/`nsN.ovh.net` pairs, N from a small pool (#939:
	// framaforms.org and ffhandball.fr on dns100/ns100; spip.net and
	// foot-national.com on dns14/ns14, 2026-09-09); OVH anycast is the uniform
	// `dns200`/`ns200.anycast.me` (vide-greniers.org, rcf.fr).
	'ovh.net',
	'anycast.me',
	// digital.govt.nz — the shared NZ-government DNS platform: the identical
	// `ns1`–`ns5.digital.govt.nz` set on 13 unrelated agencies (#939: nzta,
	// dia, customs, stats, treasury, linz, tec, corrections, mfat, beehive,
	// dpmc, tpk .govt.nz and nzdf.mil.nz, 2026-09-09).
	'digital.govt.nz',
	// Cloud / hosting platforms with one fixed set for every tenant (#939,
	// 2026-09-09; two of the sampled tenants named per entry).
	'digitalocean.com', // ns1-3 — peoplespharmacy.com, fakturoid.cz
	'linode.com', // ns1-5 — owlcat.games, international-schools-database.com
	'vercel-dns.com', // ns1/ns2 — break.com, moneygeek.com
	'hover.com', // ns1/ns2 — thespinoff.co.nz, accountingtools.com
	'dreamhost.com', // ns1-3 — victorianweb.org, earthisland.org
	'siteground.net', // ns1/ns2 — bluezones.com, anseladams.com
	'porkbun.com', // curitiba/fortaleza/maceio/salvador.ns — enby.software, spqrome.org
	'eurodns.com', // ns1-4 — wbcsd.org, proteste.pt
	'dyna-ns.net', // Dynadot ns1/ns2 — bhajanganga.com, fwme.eu
	// DNSimple — uniform `ns1-4.dnsimple.com` (eventsair.com, borisfx.com) or
	// the uniform edge set `ns1.dnsimple-edge.com` / `ns2.dnsimple-edge.net` /
	// `ns3.dnsimple-edge.io` / `ns4.dnsimple-edge.org` (nutrislice.com,
	// openapis.org); #939, 2026-09-09.
	'dnsimple.com',
	'dnsimple-edge.com',
	'dnsimple-edge.net',
	'dnsimple-edge.io',
	'dnsimple-edge.org',
	// Enterprise managed DNS / brand registrars that assign a FIXED set — the
	// case that matters most for this scanner's customers, because two
	// Fortune-500 seeds on the same set attribute each other's lookalikes
	// (#939, 2026-09-09).
	'cscdns.net', // CSC dns1/dns2 — stryker.com, dentsu.com; udns1/udns2 — natwest.com, delonghi.com
	'cscdns.uk', // the .uk half of CSC's udns set
	'markmonitor.com', // ns1-7 — rockwool.com, ahdictionary.com
	'dnsmadeeasy.com', // ns0-4 — travelweekly.com, viarail.ca; ns10-15 — agu.org, kissmetrics.com
	'constellix.com', // ns11/21/31 + .net ns41/51/61 — hesk.com, ih8mud.com
	'constellix.net',
	// UltraDNS (Vercara) — shared `pdns1-6` set spans six apexes (pioneer.com,
	// installshield.com); numbered sets such as `pdns109.*` are ALSO shared
	// (cricket.com.au, danskebank.dk); #939, 2026-09-09.
	'ultradns.net',
	'ultradns.org',
	'ultradns.com',
	'ultradns.biz',
	'ultradns.info',
	'ultradns.co.uk',
	// Azure DNS — 4-host sets numbered `ns1-NN.azure-dns.com` … from a pool
	// of ~23 over 178 sampled tenants (#939: lawsociety.org.uk and umicore.com
	// on set 09; 360learning.com and schoolspecialty.com on set 02).
	'azure-dns.com',
	'azure-dns.net',
	'azure-dns.org',
	'azure-dns.info',
	// Network Solutions — `nsNN`/`nsNN+1.worldnic.com` pairs from a small pool
	// (#939: fedbar.org and royrogersrestaurants.com on ns47/ns48).
	'worldnic.com',
	// ClouDNS — `pns21-24` / `gns21-24` quartets shared across tenants (#939:
	// transfermarkt.technology, conservador.cl on pns21-24).
	'cloudns.net',
	// Regional registrar / hosting defaults with one fixed set (#939,
	// 2026-09-09). CN:
	'alidns.com', // Alibaba vip3/vip4 — yicai.com, hoymiles.com
	'hichina.com', // Alibaba/HiChina dns9/dns10 — huion.com, dulwich.org
	'dnspod.net', // Tencent f1g1ns1/f1g1ns2 — leiphone.com, 360che.com
	'dnsv4.com', // ns3/ns4 — xywy.com, wuhan.gov.cn
	'share-dns.com', // a.share-dns.com / b.share-dns.net — fabang.com, huajinlawyer.com
	'share-dns.net',
	'xincache.com', // ns11/ns12 — cankaoxiaoxi.com, sdcourt.gov.cn
	// RU:
	'reg.ru', // ns1/ns2 — translate.ru, wi-fi.ru
	'timeweb.ru', // ns1/ns2.timeweb.ru + ns3/ns4.timeweb.org — rosebook.ru, accreditation.ru
	'timeweb.org',
	'beget.com', // ns1/ns2 across .com/.pro/.ru — mds.ru, clmedical.ru
	'beget.pro',
	'beget.ru',
	'selectel.ru', // a-d.ns.selectel.ru — cerkov.ru, moe-online.ru
	'nic.ru', // ns3-l2/ns4-l2/ns8-l2 + ns4-cloud/ns8-cloud — subscribe.ru, sudact.ru
	'yandex.net', // dns1/dns2 — poliklinika45.ru, audiosector.ru
	// Yandex Cloud DNS ns1/ns2 — bigenc.ru, 4lapy.ru. `yandexcloud.net` is a
	// PRIVATE public suffix (tldts, allowPrivateDomains), so `registeredApex()`
	// returns the hostname itself; the set therefore keys the two hostnames.
	'ns1.yandexcloud.net',
	'ns2.yandexcloud.net',
	// JP:
	'dnsv.jp', // GMO 01-04.dnsv.jp — fate-go.jp, gyomusuper.jp
	'dns.ne.jp', // Sakura ns1/ns2.dns.ne.jp (registrable apex under the ne.jp public suffix) — pressnet.or.jp, mansion-review.jp
	// DE / IT:
	'ns14.net', // a-d.ns14.net — wttc.org, ifw-kiel.de
	'technorail.com', // Aruba dns/dns2.technorail.com + dns3.arubadns.net + dns4.arubadns.cz — museoscienza.org, retailwatch.it
	'arubadns.net',
	'arubadns.cz',
	// Akamai — assigns NS hostnames from a shared pool reused across unrelated
	// customer zones (2026-07-26 correctness-defects design §3.3, verified
	// live: bnz.co.nz shares a9-65.akam.net with anz.co.nz and a3-67.akam.net
	// with westpac.co.nz). Overlap on an Akamai hostname alone is NOT
	// ownership evidence; only a complete NS-set match is (see
	// `classifyOwnership()` in `src/lib/ownership-attribution.ts`) — which is
	// why it is ALSO in `POOLED_SHARED_NS_APEXES` below.
	'akam.net',
]);

/**
 * The subset of `SHARED_NS_APEXES` whose hostnames are assigned PER ZONE from
 * a pool large enough that an identical COMPLETE set implies one account
 * (#929). Only these may satisfy `classifyOwnership()`'s
 * `ns_shared_provider_complete` arm; every other shared apex hands each
 * tenant the same set, so a complete match there is not evidence.
 *
 * Membership is an evidence decision, not a convenience: promote an apex here
 * only after measuring that unrelated tenants receive DIFFERENT complete sets
 * (the Akamai measurement is in the `SHARED_NS_APEXES` comment above). The
 * `shared-ns-hosts` audit pins that this set stays a subset of the shared set.
 */
export const POOLED_SHARED_NS_APEXES: ReadonlySet<string> = new Set(['akam.net']);

/**
 * True if `nsHost` (a nameserver hostname like `ns1.sedoparking.com`) is
 * served by a shared-tenant NS provider — i.e. its registered apex appears
 * in SHARED_NS_APEXES.
 */
export function isSharedNsHost(nsHost: string): boolean {
	if (!nsHost) return false;
	const apex = registeredApex(nsHost);
	return SHARED_NS_APEXES.has(apex);
}

/**
 * True if `nsHost` is served by a POOLED shared-tenant provider — one whose
 * complete NS set is per-account evidence (see `POOLED_SHARED_NS_APEXES`).
 * Always implies `isSharedNsHost(nsHost)`.
 */
export function isPooledSharedNsHost(nsHost: string): boolean {
	if (!nsHost) return false;
	const apex = registeredApex(nsHost);
	return POOLED_SHARED_NS_APEXES.has(apex);
}
