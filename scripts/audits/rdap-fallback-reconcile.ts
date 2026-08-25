// SPDX-License-Identifier: BUSL-1.1
//
// RDAP fallback-server reconciliation against IANA (#780).
//
// `FALLBACK_RDAP_SERVERS` in src/tools/check-rdap-lookup.ts is a hand-maintained
// TLD → RDAP base URL table that DUPLICATES IANA's authoritative bootstrap at
// https://data.iana.org/rdap/dns.json. A wrong or dead entry there degrades
// SILENTLY: `probeRdap()` fail-softs, so every domain under that TLD returns
// `registrationDays: null` — indistinguishable at every consumer from "old
// domain, nothing notable". That is exactly how `.ai` pointed at
// `https://rdap.nic.ai/` (a host with NO A record) for an unknown length of
// time while `.com`/`.org` populated correctly.
//
// WHY THIS IS A SCRIPT AND NOT A UNIT TEST. test/rdap-fallback-server-map.spec.ts
// states the reasoning and this script honours it: its structural assertions
// (well-formed https base URL, lowercase key, trailing slash) would NOT have
// caught #780 — `https://rdap.nic.ai/` is perfectly well-formed, it just does
// not exist. Only a LIVE reconciliation catches the class, and a unit test that
// fetched IANA would make the suite depend on someone else's uptime and fail
// closed on a network blip. So the class-level guard lives here, out-of-band,
// and is NOT wired into `npm test`.
//
// Usage:
//   npx tsx scripts/audits/rdap-fallback-reconcile.ts                 # report
//   npx tsx scripts/audits/rdap-fallback-reconcile.ts --json          # machine-readable
//   npx tsx scripts/audits/rdap-fallback-reconcile.ts --list-missing  # list every TLD IANA covers that the table lacks
//   npx tsx scripts/audits/rdap-fallback-reconcile.ts --probe         # additionally HTTP-probe each table host
//
// Exit codes — the whole point is that a failure can never read as "all clear":
//   0  reconciled, no divergence and no dead host
//   1  DEFECTS found (divergent entry, dead host, or a TLD IANA does not know)
//   2  INCONCLUSIVE — the IANA fetch/parse failed, or a host's DNS status could
//      not be established. NOTHING is asserted about the table in this case.
//
// It reports three classes, per the #780 post-mortem:
//   (a) entries whose target disagrees with IANA (host and/or path);
//   (b) entries whose host does not resolve (the #780 shape);
//   (c) TLDs IANA covers that the table lacks.
//
// (c) is INFORMATIONAL, not a defect: the table is deliberately a failsafe
// SUBSET consulted only when the live bootstrap is unavailable, so IANA's ~1.2k
// TLDs will always dwarf it. It is reported as a count so a deliberate coverage
// decision stays a decision.
//
// A FOURTH class falls out of the reconciliation and is deliberately NOT a
// defect: a TLD the table pins that IANA does not publish at all (several
// ccTLDs — co, me, io, sh, us). Its target cannot be checked against the
// authority, which is precisely the case the fallback table exists to cover, so
// as long as the host RESOLVES it is reported as a NOTICE. Making it red would
// keep this script permanently red on legitimate entries and train the operator
// to ignore it. Such an entry that ALSO fails to resolve is still caught — by
// (b), where it belongs.

import { Resolver } from 'node:dns/promises';
// The LEAF module, not `check-rdap-lookup.ts`: this reads the SAME object the
// runtime uses (never a copy — a copy would reconcile against itself), and the
// leaf imports nothing, so a plain Node/tsx process can load it. Importing the
// tool instead drags in the scoring → sanitize → punycode chain and dies.
import { FALLBACK_RDAP_SERVERS, IANA_BOOTSTRAP_URL as DEFAULT_BOOTSTRAP_URL } from '../../src/tools/rdap-fallback-servers';

/**
 * Override for an IANA mirror — and the only way to exercise the fail-closed
 * path on demand, which is how this script was proven to DISCRIMINATE rather
 * than merely to pass: pointed at an unreachable host it must exit 2 with
 * "INCONCLUSIVE", never at a green all-clear.
 *   BV_RDAP_BOOTSTRAP_URL=https://data.iana.invalid/rdap/dns.json npx tsx …
 */
const IANA_BOOTSTRAP_URL = process.env.BV_RDAP_BOOTSTRAP_URL ?? DEFAULT_BOOTSTRAP_URL;

const FETCH_TIMEOUT_MS = 20_000;
const DNS_TIMEOUT_MS = 5_000;
const PROBE_TIMEOUT_MS = 10_000;

/**
 * Sanity floor on the parsed bootstrap. A 200 response carrying an unexpected
 * shape would otherwise parse to an empty map, and an empty map makes EVERY
 * table entry look like "IANA does not know this TLD" — a fabricated
 * catastrophe. Below this floor we refuse to conclude anything (exit 2).
 */
const MIN_PLAUSIBLE_IANA_TLDS = 500;

const args = new Set(process.argv.slice(2));
const asJson = args.has('--json');
const listMissing = args.has('--list-missing');
const doProbe = args.has('--probe');

/** How the table's target compares with IANA's. */
type Verdict = 'match' | 'path-differs' | 'host-differs' | 'not-in-iana';

/** DNS status of a table host. `unknown` is NOT "dead" — see the exit-code note. */
type DnsStatus = 'resolves' | 'dead' | 'unknown';

interface Row {
	tld: string;
	tableUrl: string;
	ianaUrl: string | null;
	verdict: Verdict;
	host: string;
	dns: DnsStatus;
	/** Populated only when DNS could not be established — the raw resolver error codes. */
	dnsDetail?: string;
	/** Populated only with --probe: the HTTP status, or a transport-failure marker. */
	probe?: string;
}

function die(message: string, code: 1 | 2): never {
	if (asJson) {
		console.log(JSON.stringify({ ok: false, inconclusive: code === 2, error: message }, null, 2));
	} else {
		console.error(`\n❌ ${message}`);
		if (code === 2) {
			console.error('   INCONCLUSIVE — nothing is asserted about FALLBACK_RDAP_SERVERS by this run.');
		}
	}
	process.exit(code);
}

/**
 * Fetch and parse IANA's bootstrap into a TLD → base-URL map, using the SAME
 * "first URL wins" rule as `fetchBootstrap()` in check-rdap-lookup.ts, so this
 * script compares like with like. Any failure is fatal and loud — never an
 * empty map handed to the comparison.
 */
async function fetchIanaBootstrap(): Promise<Record<string, string>> {
	let resp: Response;
	try {
		resp = await fetch(IANA_BOOTSTRAP_URL, {
			signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
			headers: { Accept: 'application/json' },
		});
	} catch (err) {
		die(`Could not reach ${IANA_BOOTSTRAP_URL}: ${(err as Error).message}`, 2);
	}
	if (!resp.ok) {
		die(`${IANA_BOOTSTRAP_URL} returned HTTP ${resp.status} ${resp.statusText}`, 2);
	}

	let data: { services?: unknown };
	try {
		data = (await resp.json()) as { services?: unknown };
	} catch (err) {
		die(`${IANA_BOOTSTRAP_URL} did not return parseable JSON: ${(err as Error).message}`, 2);
	}

	const services = data.services;
	if (!Array.isArray(services)) {
		die(`${IANA_BOOTSTRAP_URL} has no \`services\` array — bootstrap format changed?`, 2);
	}

	const map: Record<string, string> = {};
	for (const service of services) {
		if (!Array.isArray(service)) continue;
		const [tlds, urls] = service as [unknown, unknown];
		if (!Array.isArray(tlds) || !Array.isArray(urls) || urls.length === 0) continue;
		const serverUrl = urls[0];
		for (const tld of tlds) {
			if (typeof tld === 'string' && typeof serverUrl === 'string') map[tld.toLowerCase()] = serverUrl;
		}
	}

	if (Object.keys(map).length < MIN_PLAUSIBLE_IANA_TLDS) {
		die(`IANA bootstrap parsed to only ${Object.keys(map).length} TLDs (< ${MIN_PLAUSIBLE_IANA_TLDS}) — refusing to reconcile against it.`, 2);
	}
	return map;
}

/** Normalise a base URL the way `probeRdap()` consumes it: lowercase host, exactly one trailing slash. */
function normalizeBase(url: string): string {
	try {
		const parsed = new URL(url);
		parsed.hostname = parsed.hostname.toLowerCase();
		const path = parsed.pathname.endsWith('/') ? parsed.pathname : `${parsed.pathname}/`;
		return `${parsed.protocol}//${parsed.host}${path}`;
	} catch {
		return url;
	}
}

function hostOf(url: string): string {
	try {
		return new URL(url).hostname.toLowerCase();
	} catch {
		return '';
	}
}

/**
 * Establish whether a host resolves. Returns `dead` ONLY on an authoritative
 * "no such name / no such record" for BOTH A and AAAA — a timeout or SERVFAIL
 * is `unknown`, never `dead`. Reading a resolver timeout as a dead host is the
 * inverse of the #780 defect and would send someone editing a working entry.
 */
async function resolveHost(resolver: Resolver, host: string): Promise<{ status: DnsStatus; detail?: string }> {
	const AUTHORITATIVE_ABSENCE = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN', 'NOTFOUND']);
	// allSettled, NOT an early return out of a loop: both lookups are started
	// eagerly, so returning on the first success would leave the other promise's
	// rejection unhandled and crash the process on Node's unhandled-rejection
	// default — a script that dies mid-run is a script whose verdict you cannot
	// read.
	const settled = await Promise.allSettled([resolver.resolve4(host), resolver.resolve6(host)]);
	const codes: string[] = [];
	let sawAbsence = 0;
	let sawRecords = false;

	for (const outcome of settled) {
		if (outcome.status === 'fulfilled') {
			if (Array.isArray(outcome.value) && outcome.value.length > 0) {
				sawRecords = true;
				codes.push('OK');
				continue;
			}
			// An empty array is an authoritative NODATA for this record type.
			sawAbsence++;
			codes.push('EMPTY');
			continue;
		}
		const code = (outcome.reason as NodeJS.ErrnoException).code ?? (outcome.reason as Error).message;
		codes.push(String(code));
		if (AUTHORITATIVE_ABSENCE.has(String(code))) sawAbsence++;
	}

	if (sawRecords) return { status: 'resolves' };
	if (sawAbsence === 2) return { status: 'dead', detail: codes.join('/') };
	return { status: 'unknown', detail: codes.join('/') };
}

/** Optional live reachability probe of the RDAP base URL. Reports, never judges the HTTP status. */
async function probeBase(url: string): Promise<string> {
	try {
		const resp = await fetch(url, {
			method: 'GET',
			redirect: 'manual',
			signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
			headers: { Accept: 'application/rdap+json, application/json' },
		});
		void resp.body?.cancel();
		return `HTTP ${resp.status}`;
	} catch (err) {
		return `TRANSPORT-FAIL (${(err as Error).message})`;
	}
}

async function main(): Promise<void> {
	const iana = await fetchIanaBootstrap();
	const resolver = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 2 });

	const tableTlds = Object.keys(FALLBACK_RDAP_SERVERS).sort();
	const rows: Row[] = [];

	// One DNS lookup per DISTINCT host — the table maps 20+ TLDs onto a handful
	// of operators, so per-TLD lookups would be mostly duplicate queries.
	const hosts = [...new Set(tableTlds.map((tld) => hostOf(FALLBACK_RDAP_SERVERS[tld])))].filter(Boolean);
	const dnsByHost = new Map<string, { status: DnsStatus; detail?: string }>();
	await Promise.all(hosts.map(async (host) => dnsByHost.set(host, await resolveHost(resolver, host))));

	const probeByUrl = new Map<string, string>();
	if (doProbe) {
		const urls = [...new Set(tableTlds.map((tld) => normalizeBase(FALLBACK_RDAP_SERVERS[tld])))];
		await Promise.all(urls.map(async (url) => probeByUrl.set(url, await probeBase(url))));
	}

	for (const tld of tableTlds) {
		const tableUrl = normalizeBase(FALLBACK_RDAP_SERVERS[tld]);
		const ianaRaw = iana[tld];
		const ianaUrl = ianaRaw ? normalizeBase(ianaRaw) : null;
		const host = hostOf(tableUrl);

		let verdict: Verdict;
		if (ianaUrl === null) verdict = 'not-in-iana';
		else if (ianaUrl === tableUrl) verdict = 'match';
		else if (hostOf(ianaUrl) !== host) verdict = 'host-differs';
		else verdict = 'path-differs';

		const dns = dnsByHost.get(host) ?? { status: 'unknown' as DnsStatus, detail: 'no-lookup' };
		rows.push({
			tld,
			tableUrl,
			ianaUrl,
			verdict,
			host,
			dns: dns.status,
			...(dns.status === 'resolves' ? {} : { dnsDetail: dns.detail }),
			...(doProbe ? { probe: probeByUrl.get(tableUrl) } : {}),
		});
	}

	const missingTlds = Object.keys(iana)
		.filter((tld) => !(tld in FALLBACK_RDAP_SERVERS))
		.sort();

	const divergent = rows.filter((r) => r.verdict === 'host-differs' || r.verdict === 'path-differs');
	const notInIana = rows.filter((r) => r.verdict === 'not-in-iana');
	const dead = rows.filter((r) => r.dns === 'dead');
	const unknownDns = rows.filter((r) => r.dns === 'unknown');
	// `notInIana` is deliberately NOT counted here — see the fourth-class note in
	// the header. An unpublished TLD whose host is dead is already in `dead`.
	const defects = divergent.length + dead.length;

	if (asJson) {
		console.log(
			JSON.stringify(
				{
					ok: defects === 0 && unknownDns.length === 0,
					source: IANA_BOOTSTRAP_URL,
					checkedAt: new Date().toISOString(),
					ianaTldCount: Object.keys(iana).length,
					tableTldCount: tableTlds.length,
					rows,
					divergent: divergent.map((r) => r.tld),
					notInIana: notInIana.map((r) => r.tld),
					deadHosts: [...new Set(dead.map((r) => r.host))],
					unknownDnsHosts: [...new Set(unknownDns.map((r) => r.host))],
					missingTldCount: missingTlds.length,
					...(listMissing ? { missingTlds } : {}),
				},
				null,
				2,
			),
		);
	} else {
		const header = ['tld', 'table target', 'verdict', 'dns', ...(doProbe ? ['probe'] : [])];
		const table = rows.map((r) => [
			r.tld,
			r.tableUrl,
			r.verdict === 'match' ? 'match' : `${r.verdict.toUpperCase()} → ${r.ianaUrl ?? '(absent from IANA)'}`,
			r.dns === 'resolves' ? 'ok' : `${r.dns.toUpperCase()} (${r.dnsDetail ?? '?'})`,
			...(doProbe ? [r.probe ?? ''] : []),
		]);
		const widths = header.map((h, i) => Math.max(h.length, ...table.map((row) => row[i].length)));
		const fmt = (row: string[]) => row.map((cell, i) => cell.padEnd(widths[i])).join('  ');
		console.log(`RDAP fallback reconciliation against ${IANA_BOOTSTRAP_URL}`);
		console.log(`IANA covers ${Object.keys(iana).length} TLDs; the table pins ${tableTlds.length}.\n`);
		console.log(fmt(header));
		console.log(widths.map((w) => '-'.repeat(w)).join('  '));
		for (const row of table) console.log(fmt(row));

		console.log('\n--- (a) entries whose target disagrees with IANA [DEFECT] ---');
		if (divergent.length === 0) {
			console.log('none');
		} else {
			for (const r of divergent) console.log(`${r.tld}: table=${r.tableUrl}  IANA=${r.ianaUrl}  (${r.verdict})`);
		}

		console.log('\n--- (a2) entries IANA does not publish at all [NOTICE, not a defect] ---');
		if (notInIana.length === 0) {
			console.log('none');
		} else {
			console.log('Unverifiable against the authority — which is exactly the case this fallback table exists to cover.');
			for (const r of notInIana) {
				console.log(`${r.tld}: table=${r.tableUrl}  (host ${r.dns === 'resolves' ? 'resolves' : r.dns.toUpperCase()})`);
			}
		}

		console.log('\n--- (b) entries whose host does not resolve (the #780 shape) ---');
		if (dead.length === 0) {
			console.log('none');
		} else {
			for (const r of dead) console.log(`${r.tld}: ${r.host} — ${r.dnsDetail}  (every ${r.tld} lookup silently returns registrationDays: null)`);
		}
		if (unknownDns.length > 0) {
			console.log(`\n⚠️  DNS status could not be established for ${unknownDns.length} entr${unknownDns.length === 1 ? 'y' : 'ies'} —`);
			console.log('   NOT reported as dead (a resolver timeout is not an authoritative absence):');
			for (const r of unknownDns) console.log(`   ${r.tld}: ${r.host} — ${r.dnsDetail}`);
		}

		console.log('\n--- (c) TLDs IANA covers that the table lacks ---');
		console.log(
			`${missingTlds.length} of ${Object.keys(iana).length}. INFORMATIONAL: the table is a deliberate failsafe subset ` +
				'consulted only when the live bootstrap is unavailable.',
		);
		if (listMissing) console.log(missingTlds.join(' '));
		else if (missingTlds.length > 0) console.log('(re-run with --list-missing to enumerate)');

		console.log(
			`\ntotals: ${tableTlds.length} entries · match ${rows.filter((r) => r.verdict === 'match').length}` +
				` · divergent ${divergent.length} · not-in-IANA ${notInIana.length} · dead ${dead.length} · dns-unknown ${unknownDns.length}`,
		);
	}

	if (defects > 0) {
		if (!asJson) console.error(`\n❌ ${defects} defect(s) found in FALLBACK_RDAP_SERVERS — see (a) and (b) above.`);
		process.exit(1);
	}
	if (unknownDns.length > 0) {
		if (!asJson) console.error(`\n⚠️  INCONCLUSIVE: ${unknownDns.length} host(s) had an unresolvable DNS status. This is NOT an all-clear.`);
		process.exit(2);
	}
	if (!asJson) console.log('\n✅ FALLBACK_RDAP_SERVERS reconciles with IANA and every host resolves.');
}

void main().catch((err: unknown) => {
	// A throw anywhere above is a failure to reconcile, never an all-clear.
	die(`Unexpected failure during reconciliation: ${(err as Error).stack ?? String(err)}`, 2);
});
