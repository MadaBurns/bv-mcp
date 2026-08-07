// SPDX-License-Identifier: BUSL-1.1
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';
import { resetProviderSignatureState } from '../src/lib/provider-signatures';

const fetchMock = setupFetchMock();

afterEach(() => {
	fetchMock.restore();
	resetProviderSignatureState();
	vi.restoreAllMocks();
});

interface RouteDnsInstrumentation {
	/** Called with `"<TYPE> <name>"` as each DoH query is DISPATCHED (before it resolves). */
	onQuery?: (key: string) => void;
	/** Artificial per-query latency, in ms, keyed by `"<TYPE> <name>"`. Default 0. */
	latencyFor?: (key: string) => number;
	/** Called with the number of queries in flight after each dispatch and each settle. */
	onInFlight?: (inFlight: number) => void;
}

/**
 * Route DoH GETs by `name`+`type`. `records` keys are `"<TYPE> <name>"` (name without
 * trailing dot); values are the `data` strings for that answer set. Unmatched → empty.
 *
 * The optional instrumentation hooks let a test observe DISPATCH order, in-flight
 * concurrency, and inject per-query latency (to prove output ordering does not depend on
 * which lookup finishes first).
 */
function routeDns(records: Record<string, string[]>, instrumentation: RouteDnsInstrumentation = {}) {
	const TYPE_CODE: Record<string, number> = { A: 1, MX: 15, PTR: 12, TXT: 16, NS: 2 };
	let inFlight = 0;
	globalThis.fetch = vi.fn().mockImplementation((input: string | Request) => {
		const raw = typeof input === 'string' ? input : (input as Request).url;
		const url = new URL(raw);
		const name = (url.searchParams.get('name') ?? '').replace(/\.$/, '');
		const type = url.searchParams.get('type') ?? '';
		const key = `${type} ${name}`;
		const data = records[key] ?? [];
		const answers = data.map((d) => ({ name, type: TYPE_CODE[type] ?? 0, TTL: 300, data: d }));
		const response = {
			ok: true,
			status: 200,
			json: () =>
				Promise.resolve({
					Status: 0,
					TC: false,
					RD: true,
					RA: true,
					AD: false,
					CD: false,
					Question: [{ name, type: TYPE_CODE[type] ?? 0 }],
					Answer: answers,
				}),
		} as unknown as Response;

		instrumentation.onQuery?.(key);
		inFlight++;
		instrumentation.onInFlight?.(inFlight);
		const latency = instrumentation.latencyFor?.(key) ?? 0;
		return new Promise<Response>((resolve) => {
			const settle = () => {
				inFlight--;
				instrumentation.onInFlight?.(inFlight);
				resolve(response);
			};
			if (latency > 0) setTimeout(settle, latency);
			else settle();
		});
	});
}

// Deterministic DNS: avoid secondary-resolver confirmation in unit tests.
const DNS = { skipSecondaryConfirmation: true } as const;

describe('checkPtr', () => {
	it('returns info (not applicable) when the domain has no MX records', async () => {
		routeDns({}); // no MX
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		expect(result.category).toBe('ptr');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/not applicable/i);
		expect(result.passed).toBe(true);
	});

	it('returns not-applicable (not a resolution failure) for an RFC 7505 null MX domain', async () => {
		// A null MX ("0 .") parses to an EMPTY exchange, so mx.length is 1 while there is
		// no mail host at all. Regression: the old code branched on mx.length, fell through
		// to the resolution loop and emitted "Could not resolve A records for 0 mail server
		// host(s)" — a degenerate claim that a lookup over zero hosts failed.
		routeDns({ 'MX example.com': ['0 .'] });
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		expect(result.findings).toHaveLength(1);
		const [finding] = result.findings;
		expect(finding.severity).toBe('info');
		expect(finding.title).toBe('PTR not applicable (no inbound mail)');
		expect(finding.detail).toMatch(/no usable MX records/i);
		expect(finding.detail).toMatch(/RFC 7505 null MX/i);
		expect(finding.detail).toMatch(/not applicable/i);
		// The degenerate wording must be gone.
		expect(finding.detail).not.toMatch(/could not resolve/i);
		expect(finding.detail).not.toMatch(/\b0 mail server host/i);
		expect(finding.metadata?.applicable).toBe(false);
		expect(finding.metadata?.nullMx).toBe(true);
		// Score is unchanged by this fix: info carries a 0 penalty.
		expect(result.score).toBe(100);
		expect(result.passed).toBe(true);
	});

	it('reports not-applicable (nullMx false) when the domain has no MX records at all', async () => {
		routeDns({}); // no MX
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		expect(result.findings[0].title).toBe('PTR not applicable (no inbound mail)');
		expect(result.findings[0].detail).toMatch(/publishes no usable MX records \(none\)/i);
		expect(result.findings[0].metadata?.nullMx).toBe(false);
		expect(result.score).toBe(100);
	});

	it('keeps the "could not resolve" wording when mail hosts EXIST but have no A records', async () => {
		// Real measurement failure — distinct from the not-applicable fork above.
		routeDns({ 'MX example.com': ['10 mail.example.com.'] }); // MX present, no A answer
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toBe('Mail server IPs unresolved');
		expect(result.findings[0].detail).toMatch(/could not resolve a records for 1 mail server host/i);
		expect(result.findings[0].detail).toContain('mail.example.com');
		expect(result.findings[0].metadata?.mailHostCount).toBe(1);
		expect(result.score).toBe(100);
	});

	it('credits managed providers (Google) as controlPresent without forward-confirming', async () => {
		routeDns({ 'MX example.com': ['10 aspmx.l.google.com.'] });
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/managed by mail provider/i);
		expect(result.controlPresent).toBe(true);
	});

	it('passes when all MX IPs forward-confirm (FCrDNS OK)', async () => {
		routeDns({
			'MX example.com': ['10 mail.example.com.'],
			'A mail.example.com': ['192.0.2.10'],
			'PTR 10.2.0.192.in-addr.arpa': ['mail.example.com.'],
			// forward-confirm reuses the 'A mail.example.com' key above (router strips the trailing dot).
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/forward-confirmed/i);
		expect(result.controlPresent).toBe(true);
		expect(result.passed).toBe(true);
	});

	it('flags low when a PTR exists but fails forward-confirmation (mismatch)', async () => {
		routeDns({
			'MX example.com': ['10 mail.example.com.'],
			'A mail.example.com': ['192.0.2.10'],
			'PTR 10.2.0.192.in-addr.arpa': ['wrong-host.example.net.'],
			'A wrong-host.example.net': ['198.51.100.5'], // does NOT contain 192.0.2.10
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		const low = result.findings.find((f) => f.severity === 'low');
		expect(low).toBeDefined();
		expect(low!.title).toMatch(/misconfigured/i);
	});

	it('reports info (no penalty) when PTR is missing entirely', async () => {
		routeDns({
			'MX example.com': ['10 mail.example.com.'],
			'A mail.example.com': ['192.0.2.10'],
			// no PTR answer
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
		expect(result.passed).toBe(true);
		expect(result.controlPresent).not.toBe(true);
	});

	it('flags low for partial coverage (one IP confirms, one missing)', async () => {
		routeDns({
			'MX example.com': ['10 mail.example.com.'],
			'A mail.example.com': ['192.0.2.10', '192.0.2.20'],
			'PTR 10.2.0.192.in-addr.arpa': ['mail.example.com.'],
			// 192.0.2.20 → PTR 20.2.0.192.in-addr.arpa has no answer
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		const low = result.findings.find((f) => f.severity === 'low');
		expect(low).toBeDefined();
		expect(low!.title).toMatch(/partial/i);
		expect(result.controlPresent).toBe(true);
	});

	it('flags low (misconfigured) when some IPs confirm and others fail forward-confirmation', async () => {
		routeDns({
			'MX example.com': ['10 mail.example.com.'],
			'A mail.example.com': ['192.0.2.10', '192.0.2.20'],
			'PTR 10.2.0.192.in-addr.arpa': ['mail.example.com.'], // 192.0.2.10 confirms (forward A contains it)
			'PTR 20.2.0.192.in-addr.arpa': ['wrong-host.example.net.'],
			'A wrong-host.example.net': ['198.51.100.5'], // 192.0.2.20 fails forward-confirmation
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		const low = result.findings.find((f) => f.severity === 'low');
		expect(low).toBeDefined();
		expect(low!.title).toMatch(/misconfigured/i);
		expect(result.controlPresent).toBe(true);
	});

	// --- Bounded-parallel resolution (#641) ---------------------------------------------
	//
	// The resolution phase used to be a nested serial `for` loop: 1 (MX) + |mxHosts| (A) +
	// 2 x |IPs| round-trips end-to-end. fastmail.com's shape (2 MX -> 12 IPs) is 27 serial
	// round-trips, ~8.1s at a ~300ms cold RTT, which blew the 8s per-check budget. These
	// tests pin the three properties that make parallelising it safe: the SAME queries are
	// issued, the output is order-independent, and the in-flight burst is bounded.

	/** fastmail.com's measured shape: 2 MX hosts, 12 IPs total (6 each). */
	const FASTMAIL_SHAPE_HOSTS = ['mx1.example.net', 'mx2.example.net'] as const;
	const FASTMAIL_SHAPE_IPS: Record<string, string[]> = {
		'mx1.example.net': ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4', '192.0.2.5', '192.0.2.6'],
		'mx2.example.net': ['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4', '198.51.100.5', '198.51.100.6'],
	};

	function reverseName(ip: string): string {
		return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
	}

	/**
	 * Records for the 2-MX / 12-IP shape where every IP forward-confirms.
	 * Each IP's PTR points at a per-IP hostname whose A record is that same IP.
	 */
	function fastmailShapeRecords(): Record<string, string[]> {
		const records: Record<string, string[]> = {
			'MX example.com': FASTMAIL_SHAPE_HOSTS.map((h, i) => `${(i + 1) * 10} ${h}.`),
		};
		for (const host of FASTMAIL_SHAPE_HOSTS) {
			records[`A ${host}`] = FASTMAIL_SHAPE_IPS[host];
			for (const ip of FASTMAIL_SHAPE_IPS[host]) {
				const ptrHost = `ptr-${ip.replace(/\./g, '-')}.example.net`;
				records[`PTR ${reverseName(ip)}`] = [`${ptrHost}.`];
				records[`A ${ptrHost}`] = [ip];
			}
		}
		return records;
	}

	/**
	 * The exact detail string the serial implementation produced for the shape above.
	 * Note `OK - ` rather than the source's `OK -> `: `createFinding()` auto-sanitizes
	 * `detail` and strips the `>`.
	 */
	const FASTMAIL_SHAPE_DETAIL = FASTMAIL_SHAPE_HOSTS.flatMap((host) =>
		FASTMAIL_SHAPE_IPS[host].map((ip) => `${host} (${ip}): FCrDNS OK - ptr-${ip.replace(/\./g, '-')}.example.net`),
	).join('; ');

	it('issues the same query set and produces the identical result for the 2-MX / 12-IP shape', async () => {
		// Golden: identical findings/severity/score/detail to the pre-parallel serial loop.
		// Parallelising must change SCHEDULING only, never the measurement.
		const dispatched: string[] = [];
		routeDns(fastmailShapeRecords(), { onQuery: (key) => dispatched.push(key) });
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, { retries: 0, skipSecondaryConfirmation: true });

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toBe('Forward-confirmed reverse DNS present');
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].detail).toBe(`All 12 mail-server IP(s) have forward-confirmed reverse DNS (PTR). ${FASTMAIL_SHAPE_DETAIL}`);
		expect(result.findings[0].metadata?.confirmed).toBe(12);
		expect(result.findings[0].metadata?.totalIps).toBe(12);
		expect(result.controlPresent).toBe(true);
		expect(result.passed).toBe(true);
		expect(result.score).toBe(100);

		// TOTAL lookup count is unchanged: 1 (MX) + 2 (A per MX host) + 2 x 12 (PTR +
		// forward-confirm A) = 27. Parallelism must not add or drop a single query.
		expect(dispatched).toHaveLength(27);
		const sorted = [...dispatched].sort();
		const expected = [
			'MX example.com',
			...FASTMAIL_SHAPE_HOSTS.map((h) => `A ${h}`),
			...FASTMAIL_SHAPE_HOSTS.flatMap((h) =>
				FASTMAIL_SHAPE_IPS[h].flatMap((ip) => [`PTR ${reverseName(ip)}`, `A ptr-${ip.replace(/\./g, '-')}.example.net`]),
			),
		].sort();
		expect(sorted).toEqual(expected);
	});

	it('keeps per-IP detail in MX/A order even when lookups complete out of order', async () => {
		// Order-dependence audit: the ONLY order-sensitive output in this check is the
		// per-IP `detailParts` sequence (the counters are order-free sums). Invert the
		// completion order — later IPs resolve FIRST — and the detail must be byte-identical
		// to the serial ordering.
		const allIps = FASTMAIL_SHAPE_HOSTS.flatMap((h) => FASTMAIL_SHAPE_IPS[h]);
		const latencyByIp = new Map(allIps.map((ip, index) => [ip, (allIps.length - index) * 3]));
		routeDns(fastmailShapeRecords(), {
			latencyFor: (key) => {
				for (const [ip, ms] of latencyByIp) {
					if (key === `PTR ${reverseName(ip)}` || key === `A ptr-${ip.replace(/\./g, '-')}.example.net`) return ms;
				}
				return 0;
			},
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, { retries: 0, skipSecondaryConfirmation: true });
		expect(result.findings[0].detail).toBe(`All 12 mail-server IP(s) have forward-confirmed reverse DNS (PTR). ${FASTMAIL_SHAPE_DETAIL}`);
	});

	it('bounds concurrent DNS lookups (never an unbounded Promise.all over the IP list)', async () => {
		// The Free-plan subrequest ceiling is 50 per invocation and a cold scan_domain
		// already spends ~20, so the PEAK in-flight count is the thing that must stay
		// bounded — an unbounded fan-out over an arbitrary-length IP list would not.
		let maxInFlight = 0;
		routeDns(fastmailShapeRecords(), {
			latencyFor: () => 5,
			onInFlight: (n) => {
				maxInFlight = Math.max(maxInFlight, n);
			},
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, { retries: 0, skipSecondaryConfirmation: true });
		expect(result.findings[0].title).toBe('Forward-confirmed reverse DNS present');
		// PTR_LOOKUP_CONCURRENCY is 4: the pool must saturate it (proving the serial loop is
		// gone) and never exceed it (the Free-plan guarantee). Bump this alongside the
		// constant if it is ever retuned.
		expect(maxInFlight).toBe(4);
	});

	it('short-circuits a null-MX domain before issuing ANY resolution lookup', async () => {
		// Guards the 9a88e324 null-MX early return against the parallel rewrite: the
		// resolution phase must not be reached at all, so no A/PTR query is dispatched.
		const dispatched: string[] = [];
		routeDns({ 'MX example.com': ['0 .'] }, { onQuery: (key) => dispatched.push(key) });
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, { retries: 0, skipSecondaryConfirmation: true });
		expect(result.findings[0].title).toBe('PTR not applicable (no inbound mail)');
		expect(result.findings[0].metadata?.nullMx).toBe(true);
		expect(dispatched).toEqual(['MX example.com']);
	});

	it('surfaces a mid-resolution DNS failure as a transient-error result', async () => {
		// The serial loop let a throw inside the loop propagate to the top-level catch.
		// The bounded pool must preserve that: a single failing PTR lookup still yields the
		// checkStatus:'error' shape (not a silently-degraded partial measurement).
		const records = fastmailShapeRecords();
		globalThis.fetch = vi.fn().mockImplementation((input: string | Request) => {
			const raw = typeof input === 'string' ? input : (input as Request).url;
			const url = new URL(raw);
			const name = (url.searchParams.get('name') ?? '').replace(/\.$/, '');
			const type = url.searchParams.get('type') ?? '';
			if (type === 'PTR' && name === reverseName('198.51.100.3')) {
				return Promise.reject(new DOMException('The operation timed out', 'AbortError'));
			}
			const TYPE_CODE: Record<string, number> = { A: 1, MX: 15, PTR: 12 };
			const data = records[`${type} ${name}`] ?? [];
			return Promise.resolve({
				ok: true,
				status: 200,
				json: () =>
					Promise.resolve({
						Status: 0,
						Question: [{ name, type: TYPE_CODE[type] ?? 0 }],
						Answer: data.map((d) => ({ name, type: TYPE_CODE[type] ?? 0, TTL: 300, data: d })),
					}),
			} as unknown as Response);
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, { retries: 0, skipSecondaryConfirmation: true });
		expect(result.checkStatus).toBe('error');
		expect(result.partial).toBe(true);
		expect(result.findings[0].metadata?.errorKind).toBe('dns_error');
	});

	it('returns a transient-error result on DNS failure (excluded from score, scan retry fires)', async () => {
		// Real timeouts surface as a DOMException AbortError; the transport rethrows as
		// DnsQueryError. buildDnsErrorResult converts that to a `checkStatus: 'error'` +
		// score 0 + passed false result (NOT missingControl) so scan_domain's transient-zero
		// retry fires and the scoring engine EXCLUDES ptr as transient rather than zeroing it.
		globalThis.fetch = vi.fn().mockRejectedValue(new DOMException('The operation timed out', 'AbortError'));
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, { retries: 0, skipSecondaryConfirmation: true });
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.partial).toBe(true);
		expect(result.findings[0].severity).toBe('high');
		expect(result.findings[0].metadata?.errorKind).toBe('dns_error');
	});
});
