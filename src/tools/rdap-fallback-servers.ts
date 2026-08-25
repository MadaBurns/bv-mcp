// SPDX-License-Identifier: BUSL-1.1

/**
 * The hand-maintained RDAP fallback server map, and the IANA bootstrap URL it
 * duplicates.
 *
 * A LEAF MODULE ON PURPOSE — it imports NOTHING. `check-rdap-lookup.ts` pulls
 * in the scoring/sanitize chain, which is workerd-shaped and cannot be loaded
 * by a plain Node/tsx process; keeping the table here lets the out-of-band
 * reconciliation script (`scripts/audits/rdap-fallback-reconcile.ts`) read the
 * SAME object the runtime uses instead of re-declaring it, which is the one
 * thing that would make the reconciliation worthless. Do not add an import to
 * this file.
 *
 * `check-rdap-lookup.ts` re-exports `FALLBACK_RDAP_SERVERS`, so every existing
 * consumer and `test/rdap-fallback-server-map.spec.ts` keep their import site.
 */

/** RDAP bootstrap URL (IANA). */
export const IANA_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

/**
 * Hardcoded RDAP server fallbacks for common TLDs. Used when the IANA bootstrap
 * fetch is unavailable (cold start, network blip). Snapshot from IANA's
 * canonical bootstrap; rarely changes — the audit test in Phase 6 of the
 * registrar-coverage TDD plan pins the coverage list. URLs that change at the
 * registry level get corrected when IANA bootstrap comes back online.
 *
 * ⚠️ A WRONG OR DEAD ENTRY HERE DEGRADES SILENTLY (#780). `probeRdap()` in
 * `lookalike-enrichment.ts` fail-softs, so a host that does not resolve yields
 * `registrationDays: null` on EVERY domain under that TLD — indistinguishable
 * from "old domain, nothing notable". `test/rdap-fallback-server-map.spec.ts`
 * says plainly that its structural assertions cannot catch that class; the
 * guard that can is `npx tsx scripts/audits/rdap-fallback-reconcile.ts`, which
 * reconciles this table against {@link IANA_BOOTSTRAP_URL} live. Run it before
 * adding or editing an entry.
 */
export const FALLBACK_RDAP_SERVERS: Record<string, string> = {
	// Verisign-operated
	com: 'https://rdap.verisign.com/com/v1/',
	net: 'https://rdap.verisign.com/net/v1/',
	// Public Interest Registry
	org: 'https://rdap.publicinterestregistry.org/rdap/',
	// Identity Digital (formerly Afilias / Donuts)
	info: 'https://rdap.identitydigital.services/rdap/',
	biz: 'https://rdap.nic.biz/',
	us: 'https://rdap.identitydigital.services/rdap/',
	// ⚠️ `.tech` and `.online` are Radix, NOT Identity Digital — same #780 shape,
	// found by `npm run audit:rdap-fallback` reconciling this table against IANA.
	// The host resolves and answers, so nothing errored; it just 404s every
	// `.tech`/`.online` domain, which fail-softs to `registrationDays: null`.
	// A REACHABLE-but-wrong operator is the nastier variant of #780: there is no
	// DNS failure to notice. Measured 2026-08-25 — get.tech and radix.online both
	// return 200 with a registration event from radix.host and 404 from
	// identitydigital. IANA maps both to radix.host.
	tech: 'https://rdap.radix.host/rdap/',
	online: 'https://rdap.radix.host/rdap/',
	email: 'https://rdap.identitydigital.services/rdap/',
	global: 'https://rdap.identitydigital.services/rdap/',
	group: 'https://rdap.identitydigital.services/rdap/',
	life: 'https://rdap.identitydigital.services/rdap/',
	live: 'https://rdap.identitydigital.services/rdap/',
	media: 'https://rdap.identitydigital.services/rdap/',
	news: 'https://rdap.identitydigital.services/rdap/',
	services: 'https://rdap.identitydigital.services/rdap/',
	software: 'https://rdap.identitydigital.services/rdap/',
	solutions: 'https://rdap.identitydigital.services/rdap/',
	support: 'https://rdap.identitydigital.services/rdap/',
	systems: 'https://rdap.identitydigital.services/rdap/',
	technology: 'https://rdap.identitydigital.services/rdap/',
	tools: 'https://rdap.identitydigital.services/rdap/',
	// Identity Digital ccTLDs / TLD operators
	io: 'https://rdap.identitydigital.services/rdap/',
	// ⚠️ `.ai` is Identity Digital, NOT `rdap.nic.ai` (#780). That host has NO A
	// RECORD — it does not resolve and never answered. Because `probeRdap`
	// fail-softs to `EMPTY_RDAP_PROBE`, every `.ai` lookup silently produced
	// `registrationDays: null` while `.org`/`.com` populated correctly, so the
	// "recently registered" signal — the highest-value thing lookalike triage
	// surfaces — was dead for the whole TLD with no error raised anywhere.
	// Verified against IANA's authoritative bootstrap (data.iana.org/rdap/dns.json
	// maps ai → identitydigital) and by live probe: openclaw.ai returns 200 with
	// a registration event. Do NOT "restore" rdap.nic.ai.
	ai: 'https://rdap.identitydigital.services/rdap/',
	sh: 'https://rdap.identitydigital.services/rdap/',
	// auDA
	au: 'https://rdap.cctld.au/rdap/',
	// Traficom
	fi: 'https://rdap.fi/rdap/rdap/',
	// ⚠️ `.co` is DELIBERATELY ABSENT. It was `https://rdap.nic.co/`, a host with
	// no A record (#780's exact shape). There is no replacement to point at: IANA's
	// bootstrap does not publish `co` at all, and rdap.org, centralnic, verisign,
	// godaddy and identitydigital were each probed on 2026-08-25 and none serve it.
	// An entry that cannot answer is strictly worse than no entry — the result is
	// the same `registrationDays: null`, but a dead host also spends a DNS failure
	// and the probe timeout to get there. Do NOT re-add a guess; if `.co` RDAP
	// appears, add it WITH a live probe showing a registration event.
	// ME Registry is Identity Digital — `rdap.nic.me` also had no A record.
	// Verified: google.me returns 200 with registration 2008-06-13.
	me: 'https://rdap.identitydigital.services/rdap/',
	// Google Registry — pubapi is the canonical RDAP endpoint; www.registry.google returns 404.
	app: 'https://pubapi.registry.google/rdap/',
	dev: 'https://pubapi.registry.google/rdap/',
	// XYZ.COM LLC — served by CentralNic, not `rdap.nic.xyz` (no A record, #780
	// shape). IANA maps xyz → rdap.centralnic.com/xyz/; verified 2026-08-25,
	// google.xyz returns 200 with registration 2014-05-20.
	xyz: 'https://rdap.centralnic.com/xyz/',
	// ccTLDs reachable via IANA bootstrap — hardcoded here as failsafe for when
	// the bootstrap fetch is negative-cached (transient data.iana.org outage).
	ca: 'https://rdap.ca.fury.ca/rdap/',
	cz: 'https://rdap.nic.cz/',
	fr: 'https://rdap.nic.fr/',
	in: 'https://rdap.nixiregistry.in/rdap/',
	nl: 'https://rdap.sidn.nl/',
	no: 'https://rdap.norid.no/',
	pl: 'https://rdap.dns.pl/',
	sg: 'https://rdap.sgnic.sg/rdap/',
	uk: 'https://rdap.nominet.uk/uk/',
};
