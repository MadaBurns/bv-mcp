// SPDX-License-Identifier: BUSL-1.1

/**
 * Live authoritative-DNS-infra probe orchestration.
 *
 * Fills `AuthoritativeDnsInfraEvidence` from direct TCP/53 queries against a
 * bounded set of nameserver addresses, dependency-injected exactly like
 * `probeDelegationConsistency`. Every socket connects to an IP literal that
 * already passed `isGloballyRoutableIp` — never a hostname (SSRF pinning,
 * US-4 contract #2). Only fields actually measured are filled; a probe that
 * never established contact returns no verdict fields at all (contract #6).
 */

import { queryDns } from '../dns';
import { RecordType, type RecordTypeName } from '../dns-types';
import { Semaphore } from '../semaphore';
import {
	buildDirectDnsQuery,
	isGloballyRoutableIp,
	openDnsTcpSession,
	parseDirectDnsResponse,
	readFirstFramedResponse,
	resolvePublicNameserverAddresses,
	type DirectDnsResponse,
	type DirectQueryOptions,
	type DnsTcpSession,
	type DnsTcpSessionFactory,
	type NameserverAddressResolver,
} from './dns-tcp';
import type { RecursiveDnsQuery } from './delegation-probe';
import { ROOT_HINTS, ROOT_SERVER_NAMES } from './root-hints';
import type { AuthoritativeDnsInfraEvidence } from './types';

const MAX_NAMESERVERS = 3;
// Cloudflare Workers cap simultaneous outgoing connections at 6, measured from the
// TOP-LEVEL request and shared with the calling MCP Worker's own in-flight
// connections and this sidecar's DoH fetches (US-4 story contract addendum #2).
// Capping at 4 leaves headroom instead of relying on the 7th connection silently
// queuing.
const MAX_CONCURRENT_SESSIONS = 4;
const DEFAULT_BUDGET_MS = 4_000;
const NAMESERVER_RESOLUTION_TIMEOUT_MS = 2_000;
const RECURSIVE_QUERY_TIMEOUT_MS = 1_500;
const RECURSION_CANARY_NAME = 'example.com';
// IANA Private Use RR-type range (65280-65534): guaranteed never assigned, so any
// answer to it is unambiguously an "unsupported query" probe.
const UNSUPPORTED_QTYPE = 65_399;
const AXFR_QTYPE = 252;
const CHAOS_QCLASS = 3;
const CHAOS_STRING_MAX_LENGTH = 64;
const DNS_PORT = 53;
// SERVFAIL, NOTIMP, REFUSED, NOTAUTH.
const AXFR_REFUSAL_RCODES = new Set([2, 4, 5, 9]);
/** Reported when the probe never established any contact at all (US-4 contract #6). */
const NO_CONTACT_ERROR = 'raw_dns_probe_no_contact';
/** Reported when at least one session answered, but none proved authoritative for the zone
 * (AA=1) — a single vantage cannot distinguish genuine lame delegation from an intercepting
 * middlebox, so no verdict-shaped field is published, not even aaFlag (orchestrator steering,
 * extends contract #6). */
const NO_AUTHORITATIVE_ANSWER_ERROR = 'raw_dns_probe_no_authoritative_answer';

export type RecursiveNameLookup = RecursiveDnsQuery;

/** Minimal raw-socket shape needed for the AXFR refusal probe: the `DnsTcpSession` abstraction
 * only exposes `query()`/`close()`, and AXFR must read with `readFirstFramedResponse` (tolerates
 * trailing bytes, cancels after frame 1) instead of the strict `readFramedResponse` `query()` uses
 * internally — so it needs the raw stream, not a parsed response. */
export interface AxfrSocket {
	opened: Promise<unknown>;
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	close(): Promise<void>;
}

export type AxfrSocketFactory = (pinnedAddress: string) => Promise<AxfrSocket>;

export interface AuthoritativeProbeDependencies {
	recursiveQuery?: RecursiveDnsQuery;
	resolveAddresses?: NameserverAddressResolver;
	openSession?: DnsTcpSessionFactory;
	/** Opens the standalone short-lived socket the AXFR refusal test runs on, after the
	 * address's main session has already closed (US-4 contract #3). */
	openAxfrSocket?: AxfrSocketFactory;
	now?: () => Date;
}

export interface AuthoritativeProbeOptions {
	activeProbes: boolean;
	budgetMs?: number;
}

interface ProbeTarget {
	zone: string;
	nameservers: string[];
	rootServerMode: boolean;
}

interface ResolvedNameserverAddress {
	nameserver: string;
	address: string;
	family: 'ipv4' | 'ipv6';
}

interface AddressResult {
	nameserver: string;
	address: string;
	family: 'ipv4' | 'ipv6';
	ok: boolean;
	connectError?: string;
	aaFlag?: boolean;
	soaSerial?: number;
	soaRcode?: number;
	nsNames?: string[];
	dnskeyPresent?: boolean;
	rrsigPresent?: boolean;
	recursionExposed?: boolean;
	unsupportedRefused?: boolean;
	axfrRefused?: boolean;
	chaosVersion?: string;
	chaosId?: string;
}

function normalizeName(name: string): string {
	return name.replace(/\.$/, '').toLowerCase();
}

function uniqueSorted(values: string[]): string[] {
	return [...new Set(values.map(normalizeName).filter(Boolean))].sort();
}

async function defaultRecursiveQuery(name: string, type: RecordTypeName): Promise<string[]> {
	const response = await queryDns(name, type, false, { timeoutMs: RECURSIVE_QUERY_TIMEOUT_MS, retries: 0 });
	return (response.Answer ?? [])
		.filter((answer) => answer.type === RecordType[type])
		.map((answer) => answer.data.replace(/\.$/, '').toLowerCase());
}

function frameMessage(message: Uint8Array): Uint8Array {
	const framed = new Uint8Array(message.length + 2);
	new DataView(framed.buffer).setUint16(0, message.length);
	framed.set(message, 2);
	return framed;
}

async function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		return await Promise.race([
			operation,
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => reject(new Error('Direct DNS query timed out')), timeoutMs);
			}),
		]);
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}

const defaultOpenAxfrSocket: AxfrSocketFactory = async (pinnedAddress) => {
	if (!isGloballyRoutableIp(pinnedAddress)) {
		throw new Error('AXFR probe socket requires a globally routable IP literal');
	}
	// Kept behind a dynamic import so Node-side tooling can import this module without
	// resolving `cloudflare:` URLs, matching dns-tcp.ts's own execution seam.
	const { connect } = await import('cloudflare:sockets');
	const socket = connect({ hostname: pinnedAddress, port: DNS_PORT }, { secureTransport: 'off', allowHalfOpen: true });
	void socket.closed.catch(() => undefined);
	return socket;
};

/**
 * Resolve the probe target per US-4 contract #8: a delegated zone (has NS records),
 * a known root server queried for zone '.', a bare host queried for its own SOA, or
 * no contact at all.
 */
async function resolveTarget(hostname: string, recursiveQuery: RecursiveDnsQuery): Promise<ProbeTarget | undefined> {
	let nsNames: string[] = [];
	try {
		nsNames = uniqueSorted(await recursiveQuery(hostname, 'NS'));
	} catch {
		// Fall through to the next target mode.
	}
	if (nsNames.length > 0) {
		return { zone: hostname, nameservers: nsNames.slice(0, MAX_NAMESERVERS), rootServerMode: false };
	}

	if ((ROOT_SERVER_NAMES as readonly string[]).includes(hostname)) {
		return { zone: '.', nameservers: [hostname], rootServerMode: true };
	}

	try {
		const [ipv4, ipv6] = await Promise.allSettled([recursiveQuery(hostname, 'A'), recursiveQuery(hostname, 'AAAA')]);
		const hasAddress =
			(ipv4.status === 'fulfilled' && ipv4.value.length > 0) || (ipv6.status === 'fulfilled' && ipv6.value.length > 0);
		if (hasAddress) return { zone: hostname, nameservers: [hostname], rootServerMode: false };
	} catch {
		// No contact established by any mode.
	}

	return undefined;
}

async function resolveNameserverAddresses(
	nameserver: string,
	rootServerMode: boolean,
	resolveAddresses: NameserverAddressResolver | undefined,
	timeoutMs: number,
): Promise<ResolvedNameserverAddress[]> {
	if (rootServerMode) {
		const hint = ROOT_HINTS.find((entry) => entry.name === nameserver);
		if (!hint) return [];
		const result: ResolvedNameserverAddress[] = [];
		if (isGloballyRoutableIp(hint.ipv4)) result.push({ nameserver, address: hint.ipv4, family: 'ipv4' });
		if (isGloballyRoutableIp(hint.ipv6)) result.push({ nameserver, address: hint.ipv6, family: 'ipv6' });
		return result;
	}

	try {
		// Bounded to 1 IPv4 + 1 IPv6 literal, both already SSRF-pinned by
		// `resolvePublicNameserverAddresses` (throws — and this nameserver is skipped,
		// never connected — when every resolved address is private).
		const addresses = await resolvePublicNameserverAddresses(nameserver, resolveAddresses, timeoutMs);
		const ipv4 = addresses.find((address) => !address.includes(':'));
		const ipv6 = addresses.find((address) => address.includes(':'));
		const result: ResolvedNameserverAddress[] = [];
		if (ipv4) result.push({ nameserver, address: ipv4, family: 'ipv4' });
		if (ipv6) result.push({ nameserver, address: ipv6, family: 'ipv6' });
		return result;
	} catch {
		return [];
	}
}

function classifyUnsupportedRefusal(response: DirectDnsResponse): boolean {
	// A positive answer to an unassigned qtype is the "malformed/odd" violation;
	// NOTIMP / REFUSED / NOERROR-NODATA (or any other empty-answer rcode) is a refusal.
	return response.answers.length === 0;
}

function classifyAxfrRefusal(response: DirectDnsResponse): boolean | undefined {
	if (AXFR_REFUSAL_RCODES.has(response.rcode)) return true;
	if (response.answers.length === 0) return true;
	if (response.answers.some((record) => record.type === RecordType.SOA)) return false;
	return undefined;
}

async function probeAxfrRefusal(
	address: string,
	zone: string,
	openAxfrSocket: AxfrSocketFactory,
	timeoutMs: number,
): Promise<boolean | undefined> {
	let socket: AxfrSocket;
	try {
		socket = await withTimeout(openAxfrSocket(address), timeoutMs);
	} catch {
		return undefined;
	}
	try {
		const id = crypto.getRandomValues(new Uint16Array(1))[0];
		const query = buildDirectDnsQuery(zone, AXFR_QTYPE, id);
		await withTimeout(socket.opened, timeoutMs);
		const writer = socket.writable.getWriter();
		try {
			await writer.write(frameMessage(query));
		} finally {
			writer.releaseLock();
		}
		// Reads ONLY the first frame and cancels the reader immediately after — never lets
		// zone data accumulate, whether the transfer is refused or actually allowed
		// (US-4 contract #3).
		const frame = await withTimeout(readFirstFramedResponse(socket.readable), timeoutMs);
		return classifyAxfrRefusal(parseDirectDnsResponse(frame, id));
	} catch {
		return undefined;
	} finally {
		await socket.close().catch(() => undefined);
	}
}

async function probeAddress(
	target: ResolvedNameserverAddress,
	zone: string,
	activeProbes: boolean,
	openSession: DnsTcpSessionFactory,
	openAxfrSocket: AxfrSocketFactory,
	deadline: number,
): Promise<AddressResult> {
	const result: AddressResult = { nameserver: target.nameserver, address: target.address, family: target.family, ok: false };

	let session: DnsTcpSession;
	try {
		session = await openSession(target.address, Math.max(1, deadline - Date.now()));
	} catch {
		result.connectError = 'tcp_connect_failed';
		return result;
	}

	const attempt = async (name: string, type: number, options?: DirectQueryOptions): Promise<DirectDnsResponse | undefined> => {
		try {
			const response = await session.query(name, type, options);
			result.ok = true;
			return response;
		} catch {
			return undefined;
		}
	};

	const soa = await attempt(zone, RecordType.SOA);
	if (!soa) {
		result.connectError = 'no_response';
		await session.close().catch(() => undefined);
		return result;
	}

	// AA=1 (an answer, or NODATA with SOA in authority) is the only thing that tells us this
	// session actually reached the zone's nameserver rather than a lame delegation or an
	// interception (e.g. a middlebox transparently answering TCP/53). A non-authoritative
	// answer is evidence about ITSELF (aaFlag: false, reachable) but never about the zone: no
	// other query is trustworthy evidence from it, so nothing else runs on this session
	// (orchestrator steering, extends contract #6 — "a probe that never reached a server is
	// never false").
	result.aaFlag = soa.aa;
	result.soaRcode = soa.rcode;
	if (soa.aa !== true) {
		await session.close().catch(() => undefined);
		return result;
	}

	const serialRecord = [...soa.answers, ...soa.authority].find((record) => record.type === RecordType.SOA && record.data);
	if (serialRecord) {
		const parsed = Number(serialRecord.data);
		if (Number.isFinite(parsed)) result.soaSerial = parsed;
	}

	const ns = await attempt(zone, RecordType.NS);
	if (ns) {
		result.nsNames = uniqueSorted(
			[...ns.answers, ...ns.authority].filter((record) => record.type === RecordType.NS && record.data).map((record) => record.data),
		);
	}

	const dnskey = await attempt(zone, RecordType.DNSKEY, { dnssecOk: true });
	if (dnskey) {
		result.dnskeyPresent = dnskey.answers.some((record) => record.type === RecordType.DNSKEY);
		result.rrsigPresent = dnskey.answers.some((record) => record.type === RecordType.RRSIG);
	}

	const recursionProbe = await attempt(RECURSION_CANARY_NAME, RecordType.A);
	if (recursionProbe) {
		result.recursionExposed = recursionProbe.ra === true || (recursionProbe.aa !== true && recursionProbe.answers.length > 0);
	}

	const unsupported = await attempt(zone, UNSUPPORTED_QTYPE);
	if (unsupported) {
		result.unsupportedRefused = classifyUnsupportedRefusal(unsupported);
	}

	if (activeProbes) {
		const version = await attempt('version.bind', RecordType.TXT, { qclass: CHAOS_QCLASS });
		if (version?.answers[0]?.data) result.chaosVersion = version.answers[0].data.slice(0, CHAOS_STRING_MAX_LENGTH);
		const id = await attempt('id.server', RecordType.TXT, { qclass: CHAOS_QCLASS });
		if (id?.answers[0]?.data) result.chaosId = id.answers[0].data.slice(0, CHAOS_STRING_MAX_LENGTH);
	}

	await session.close().catch(() => undefined);

	if (activeProbes && Date.now() < deadline) {
		result.axfrRefused = await probeAxfrRefusal(target.address, zone, openAxfrSocket, Math.max(1, deadline - Date.now()));
	}

	return result;
}

function aggregateBoolean(measurements: Array<boolean | undefined>): boolean | undefined {
	const answered = measurements.filter((value): value is boolean => value !== undefined);
	if (answered.length === 0) return undefined;
	// True only if every answering server satisfied it; false if any answering server violated it.
	return answered.every((value) => value === true);
}

function buildFamilyReachability(
	results: AddressResult[],
	family: 'ipv4' | 'ipv6',
): { addresses: string[]; reachable?: boolean; errors?: string[] } | undefined {
	const familyResults = results.filter((result) => result.family === family);
	if (familyResults.length === 0) return undefined;
	const errors = familyResults.filter((result) => result.connectError).map((result) => result.connectError as string);
	return {
		addresses: familyResults.map((result) => result.address),
		reachable: familyResults.some((result) => result.ok),
		...(errors.length > 0 ? { errors } : {}),
	};
}

function computeTransportParity(results: AddressResult[]): boolean | undefined {
	// Only an authoritative (AA=1) answer is trustworthy evidence about the zone; comparing a
	// lame/intercepted answer against a genuine one would misreport parity.
	const ipv4 = results.find((result) => result.family === 'ipv4' && result.aaFlag === true);
	const ipv6 = results.find((result) => result.family === 'ipv6' && result.aaFlag === true);
	if (!ipv4 || !ipv6) return undefined;
	return ipv4.soaRcode === ipv6.soaRcode && ipv4.soaSerial === ipv6.soaSerial;
}

function setsEqual(a: string[], b: string[]): boolean {
	if (a.length !== b.length) return false;
	const setB = new Set(b);
	return a.every((value) => setB.has(value));
}

function buildEvidence(hostname: string, checkedAt: string, target: ProbeTarget, results: AddressResult[]): AuthoritativeDnsInfraEvidence {
	const reachedResults = results.filter((result) => result.ok);
	if (reachedResults.length === 0) {
		return { hostname, checkedAt, errors: [NO_CONTACT_ERROR] };
	}

	// At least one session answered, but if NONE proved authoritative (AA=1) for the zone, a
	// single vantage cannot tell genuine lame delegation apart from an intercepting middlebox —
	// so no verdict-shaped field is published, not even aaFlag.
	if (!reachedResults.some((result) => result.aaFlag === true)) {
		return { hostname, checkedAt, errors: [NO_AUTHORITATIVE_ANSWER_ERROR] };
	}

	const evidence: AuthoritativeDnsInfraEvidence = { hostname, checkedAt };

	const ipv4 = buildFamilyReachability(results, 'ipv4');
	const ipv6 = buildFamilyReachability(results, 'ipv6');
	const tcp53Reachable = ipv4 || ipv6 ? ipv4?.reachable === true || ipv6?.reachable === true : undefined;
	if (ipv4 || ipv6 || tcp53Reachable !== undefined) {
		evidence.reachability = {
			...(ipv4 ? { ipv4 } : {}),
			...(ipv6 ? { ipv6 } : {}),
			...(tcp53Reachable !== undefined ? { tcp53Reachable } : {}),
		};
	}

	const aaFlag = aggregateBoolean(reachedResults.map((result) => result.aaFlag));
	const recursionRefused = aggregateBoolean(reachedResults.map((result) => (result.recursionExposed === undefined ? undefined : !result.recursionExposed)));
	const recursionAvailable = recursionRefused === undefined ? undefined : !recursionRefused;
	if (aaFlag !== undefined || recursionAvailable !== undefined || recursionRefused !== undefined) {
		evidence.authoritative = {
			...(aaFlag !== undefined ? { aaFlag } : {}),
			...(recursionAvailable !== undefined ? { recursionAvailable } : {}),
			...(recursionRefused !== undefined ? { recursionRefused } : {}),
		};
	}

	const serialsByNameserver: Record<string, number> = {};
	for (const result of reachedResults) {
		if (result.soaSerial !== undefined) serialsByNameserver[result.nameserver] = result.soaSerial;
	}
	if (Object.keys(serialsByNameserver).length > 0) {
		evidence.soaSerial = { serialsByNameserver, consistent: new Set(Object.values(serialsByNameserver)).size === 1 };
	}

	const dnskeyPresent = aggregateBoolean(reachedResults.map((result) => result.dnskeyPresent));
	const rrsigPresent = aggregateBoolean(reachedResults.map((result) => result.rrsigPresent));
	if (dnskeyPresent !== undefined || rrsigPresent !== undefined) {
		evidence.dnssec = {
			...(dnskeyPresent !== undefined ? { dnskeyPresent } : {}),
			...(rrsigPresent !== undefined ? { rrsigPresent } : {}),
		};
	}

	const axfrRefused = aggregateBoolean(reachedResults.map((result) => result.axfrRefused));
	if (axfrRefused !== undefined) {
		evidence.zoneTransfer = { axfrRefused };
	}

	const chaosVersion = reachedResults.find((result) => result.chaosVersion !== undefined)?.chaosVersion;
	const chaosId = reachedResults.find((result) => result.chaosId !== undefined)?.chaosId;
	const unsupportedQueriesRefused = aggregateBoolean(reachedResults.map((result) => result.unsupportedRefused));
	if (chaosVersion !== undefined || chaosId !== undefined || unsupportedQueriesRefused !== undefined) {
		evidence.operationalExposure = {
			...(chaosVersion !== undefined ? { chaosVersion } : {}),
			...(chaosId !== undefined ? { chaosId } : {}),
			...(unsupportedQueriesRefused !== undefined ? { unsupportedQueriesRefused } : {}),
		};
	}

	const ipv4Ipv6Parity = computeTransportParity(reachedResults);
	if (ipv4Ipv6Parity !== undefined) {
		evidence.transportParity = { ipv4Ipv6Parity };
	}

	if (target.rootServerMode) {
		const nsNames = uniqueSorted(reachedResults.flatMap((result) => result.nsNames ?? []));
		if (nsNames.length > 0) {
			evidence.rootPriming = { nsNames, matchesOfficialHints: setsEqual(nsNames, ROOT_SERVER_NAMES) };
		}
	}

	return evidence;
}

/**
 * Probe a hostname's authoritative DNS infrastructure directly over TCP/53, filling
 * only the fields actually measured. Dependency-injected exactly like
 * `probeDelegationConsistency`; every fan-out is hard-capped and every individual
 * failure remains explicit evidence rather than becoming a false finding.
 */
export async function probeAuthoritativeDns(
	hostname: string,
	dependencies: AuthoritativeProbeDependencies = {},
	options: AuthoritativeProbeOptions = { activeProbes: false },
): Promise<AuthoritativeDnsInfraEvidence> {
	const normalizedHostname = normalizeName(hostname);
	const recursiveQuery = dependencies.recursiveQuery ?? defaultRecursiveQuery;
	const openSession = dependencies.openSession ?? openDnsTcpSession;
	const openAxfrSocket = dependencies.openAxfrSocket ?? defaultOpenAxfrSocket;
	const activeProbes = options.activeProbes ?? false;
	const budgetMs = options.budgetMs ?? DEFAULT_BUDGET_MS;
	const checkedAt = (dependencies.now?.() ?? new Date()).toISOString();
	const deadline = Date.now() + budgetMs;

	const target = await resolveTarget(normalizedHostname, recursiveQuery);
	if (!target) {
		return { hostname: normalizedHostname, checkedAt, errors: [NO_CONTACT_ERROR] };
	}

	// Resolved CONCURRENTLY and clamped to what is left of the lane budget. Serially, three
	// slow-but-healthy resolutions (3 x NAMESERVER_RESOLUTION_TIMEOUT_MS) outlived both the
	// lane budget and the caller's 5 s client timeout before a single TCP session opened, so
	// a measurable zone abstained (SQ-131 S2). At most MAX_NAMESERVERS lookups run here and
	// no TCP session is open yet, so this stays inside the Workers connection limit.
	// `Promise.all` preserves nameserver order, which `buildEvidence` relies on.
	const resolutionTimeoutMs = Math.max(1, Math.min(NAMESERVER_RESOLUTION_TIMEOUT_MS, deadline - Date.now()));
	const resolved = await Promise.all(
		target.nameservers.map((nameserver) =>
			resolveNameserverAddresses(nameserver, target.rootServerMode, dependencies.resolveAddresses, resolutionTimeoutMs),
		),
	);
	const addressTargets: ResolvedNameserverAddress[] = resolved.flat();

	if (addressTargets.length === 0) {
		return { hostname: normalizedHostname, checkedAt, errors: [NO_CONTACT_ERROR] };
	}

	const semaphore = new Semaphore(MAX_CONCURRENT_SESSIONS);
	const settled = await Promise.all(
		addressTargets.map((addressTarget) =>
			semaphore.run(async () => {
				// Budget exhausted before this address got a slot: skip it entirely rather
				// than throw, so the probe returns whatever was measured (contract: partial
				// measured evidence, not a throw).
				if (Date.now() >= deadline) return undefined;
				return probeAddress(addressTarget, target.zone, activeProbes, openSession, openAxfrSocket, deadline);
			}),
		),
	);
	const results = settled.filter((result): result is AddressResult => result !== undefined);

	return buildEvidence(normalizedHostname, checkedAt, target, results);
}
