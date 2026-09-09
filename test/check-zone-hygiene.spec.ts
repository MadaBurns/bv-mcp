// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, nsResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Build an empty DoH response (no answers). */
function emptyResponse(name: string, type: number) {
	return createDohResponse([{ name, type }], []);
}

/** Build a DoH response containing a SOA record. */
function soaResponse(domain: string, soaData: string) {
	return createDohResponse([{ name: domain, type: 6 }], [{ name: domain, type: 6, TTL: 300, data: soaData }]);
}

/** Build a DoH response containing A records. */
function aResponse(domain: string, ips: string[]) {
	return createDohResponse(
		[{ name: domain, type: 1 }],
		ips.map((ip) => ({ name: domain, type: 1, TTL: 300, data: ip })),
	);
}

describe('checkZoneHygiene', () => {
	async function run(domain = 'example.com') {
		const { checkZoneHygiene } = await import('../src/tools/check-zone-hygiene');
		return checkZoneHygiene(domain);
	}

	it('should return info findings when zone is consistent and no sensitive subdomains resolve', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// NS query
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}
			// SOA query
			if (url.includes('type=SOA') || url.includes('type=6')) {
				return Promise.resolve(soaResponse('example.com', 'ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 300'));
			}
			// A record queries for sensitive subdomains — all return empty
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('zone_hygiene');
		expect(result.passed).toBe(true);

		// Should have SOA details info finding
		const soaDetails = result.findings.find((f) => f.title === 'SOA record details');
		expect(soaDetails).toBeDefined();
		expect(soaDetails!.metadata?.serial).toBe(2024010101);

		// Should have "no sensitive subdomains" finding
		const noSensitive = result.findings.find((f) => f.title === 'No sensitive subdomains resolve publicly');
		expect(noSensitive).toBeDefined();
	});

	it('should detect sensitive subdomains that resolve publicly', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}
			if (url.includes('type=SOA') || url.includes('type=6')) {
				return Promise.resolve(soaResponse('example.com', 'ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 300'));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				// vpn.example.com resolves
				if (name === 'vpn.example.com') {
					return Promise.resolve(aResponse('vpn.example.com', ['203.0.113.10']));
				}
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('zone_hygiene');
		const vpnFinding = result.findings.find((f) => f.title.includes('vpn.example.com'));
		expect(vpnFinding).toBeDefined();
		expect(vpnFinding!.severity).toBe('medium');
	});

	it('should flag excessive subdomain exposure when 3+ resolve', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.']));
			}
			if (url.includes('type=SOA') || url.includes('type=6')) {
				return Promise.resolve(soaResponse('example.com', 'ns1.example.com. admin.example.com. 100 7200 3600 1209600 300'));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				const resolving = ['vpn.example.com', 'admin.example.com', 'staging.example.com'];
				if (resolving.includes(name)) {
					return Promise.resolve(aResponse(name, ['203.0.113.1']));
				}
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const excessive = result.findings.find((f) => f.title.includes('Excessive internal subdomain exposure'));
		expect(excessive).toBeDefined();
		expect(excessive!.severity).toBe('medium');
	});

	it('should handle DNS query failure gracefully', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('DNS failure'));

		const result = await run();
		expect(result.category).toBe('zone_hygiene');
		expect(result.findings.length).toBeGreaterThan(0);

		// Should have a zone consistency failure note
		const failNote = result.findings.find((f) => f.title === 'Zone consistency check failed');
		expect(failNote).toBeDefined();
		expect(failNote!.severity).toBe('info');
	});

	it('should report SOA serial in findings metadata', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}
			if (url.includes('type=SOA') || url.includes('type=6')) {
				return Promise.resolve(soaResponse('example.com', 'ns1.example.com. hostmaster.example.com. 9999 7200 3600 1209600 300'));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const soaDetails = result.findings.find((f) => f.title === 'SOA record details');
		expect(soaDetails).toBeDefined();
		expect(soaDetails!.metadata?.serial).toBe(9999);
		expect(soaDetails!.metadata?.primaryNs).toBe('ns1.example.com');
	});

	it('should report medium finding when no NS records found', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(emptyResponse('example.com', 2));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const noNs = result.findings.find((f) => f.title === 'No NS records found');
		expect(noNs).toBeDefined();
		expect(noNs!.severity).toBe('medium');
	});

	it('should flag short SOA expire value', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}
			if (url.includes('type=SOA') || url.includes('type=6')) {
				// expire = 86400 (1 day, less than 604800 = 1 week)
				return Promise.resolve(soaResponse('example.com', 'ns1.example.com. admin.example.com. 2024010101 7200 3600 86400 300'));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const shortExpire = result.findings.find((f) => f.title === 'SOA expire value is short');
		expect(shortExpire).toBeDefined();
		expect(shortExpire!.severity).toBe('low');
		expect(shortExpire!.metadata?.expire).toBe(86400);
		// #807: template must not use a bare `<` — createFinding()'s markdown
		// sanitizer strips it and garbles the prose.
		expect(shortExpire!.detail).toContain('SOA expire value is 86400s, below the recommended 604800s (1 week).');
		expect(shortExpire!.detail).not.toContain('<');
	});

	it('should handle missing SOA record', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.']));
			}
			if (url.includes('type=SOA') || url.includes('type=6')) {
				return Promise.resolve(emptyResponse('example.com', 6));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const noSoa = result.findings.find((f) => f.title === 'No SOA record found');
		expect(noSoa).toBeDefined();
		expect(noSoa!.severity).toBe('medium');
	});

	// #930: a wildcard record answers for EVERY name, so a sensitive-name sweep on such a
	// zone "finds" all ten hosts. The canary (`_bv-probe-<nonce>.<domain>`) is what tells
	// a wildcard-synthetic answer from a real host.
	describe('wildcard zone (#930)', () => {
		const WILDCARD_IP = '198.51.100.94';

		/** DoH response for an alias: CNAME to `target` plus the A records reached through it (possibly none). */
		function cnameResponse(name: string, target: string, ips: string[]) {
			return createDohResponse(
				[{ name, type: 1 }],
				[{ name, type: 5, TTL: 300, data: target }, ...ips.map((ip) => ({ name: target, type: 1, TTL: 300, data: ip }))],
			);
		}

		function wildcardMock(
			opts: {
				realHosts?: Record<string, string[]>;
				canaryIps?: string[][];
				canaryThrows?: boolean;
				/** Wildcard is `*.zone CNAME <target>`; each canary/hit gets `[target, ips]`. */
				cnamePool?: { target: string; canaryIps: string[]; hitIps: string[] };
				soaExpire?: number;
			} = {},
		) {
			const canaryAnswers = opts.canaryIps ?? [[WILDCARD_IP]];
			let canaryCalls = 0;
			const aQueries: string[] = [];
			const fetchMock = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.includes('type=NS') || url.includes('type=2')) {
					return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
				}
				if (url.includes('type=SOA') || url.includes('type=6')) {
					return Promise.resolve(
						soaResponse('example.com', `ns1.example.com. admin.example.com. 2024010101 7200 3600 ${opts.soaExpire ?? 1209600} 300`),
					);
				}
				if (url.includes('type=A') || url.includes('type=1')) {
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
					aQueries.push(name);
					if (name.startsWith('_bv-probe-')) {
						if (opts.canaryThrows) return Promise.reject(new Error('DNS query timed out after 3000ms'));
						canaryCalls++;
						if (opts.cnamePool) return Promise.resolve(cnameResponse(name, opts.cnamePool.target, opts.cnamePool.canaryIps));
						const ips = canaryAnswers[Math.min(canaryCalls - 1, canaryAnswers.length - 1)];
						return Promise.resolve(aResponse(name, ips));
					}
					if (opts.realHosts?.[name]) return Promise.resolve(aResponse(name, opts.realHosts[name]));
					// Everything else under the zone is answered by the wildcard.
					if (opts.cnamePool) return Promise.resolve(cnameResponse(name, opts.cnamePool.target, opts.cnamePool.hitIps));
					return Promise.resolve(aResponse(name, [WILDCARD_IP]));
				}
				return Promise.resolve(emptyResponse('example.com', 1));
			});
			globalThis.fetch = fetchMock;
			return { aQueries, canaryCalls: () => canaryCalls };
		}

		it('suppresses every wildcard-synthetic hit into a single info observation and does not zero the category', async () => {
			const { aQueries } = wildcardMock();
			const result = await run();

			expect(result.category).toBe('zone_hygiene');
			// Not one scored finding: ten mediums + "Excessive" used to floor this to 0.
			expect(result.findings.filter((f) => f.severity !== 'info')).toEqual([]);
			expect(result.findings.find((f) => f.title.startsWith('Internal subdomain resolves publicly'))).toBeUndefined();
			expect(result.findings.find((f) => f.title.startsWith('Excessive internal subdomain exposure'))).toBeUndefined();
			// ...and NOT the clean "none resolve" verdict either — a wildcard zone cannot support it.
			expect(result.findings.find((f) => f.title === 'No sensitive subdomains resolve publicly')).toBeUndefined();
			expect(result.score).toBe(100);
			expect(result.passed).toBe(true);

			const note = result.findings.find((f) => f.title === 'Wildcard DNS masks sensitive subdomain probing');
			expect(note).toBeDefined();
			expect(note!.severity).toBe('info');
			expect(note!.metadata?.wildcardDetected).toBe(true);
			expect(note!.metadata?.wildcardIps).toEqual([WILDCARD_IP]);
			expect(note!.metadata?.wildcardSyntheticSubdomains).toHaveLength(10);
			expect(note!.metadata?.wildcardSyntheticSubdomains).toContain('vpn.example.com');
			// The wildcard note is a measurement, not an abstention.
			expect(note!.metadata?.inconclusive).toBeUndefined();
			expect(note!.metadata?.missingControl).toBeUndefined();
			expect(note!.detail).toContain('wildcard');
			expect(note!.detail).not.toContain('<');

			// Budget: exactly one canary on top of the ten-name sweep.
			expect(aQueries.filter((n) => n.startsWith('_bv-probe-'))).toHaveLength(1);
			expect(aQueries.filter((n) => !n.startsWith('_bv-probe-'))).toHaveLength(10);
		});

		it('still reports a real host whose answer differs from the wildcard answer', async () => {
			const { aQueries } = wildcardMock({ realHosts: { 'vpn.example.com': ['203.0.113.10'] } });
			const result = await run();

			const vpn = result.findings.find((f) => f.title === 'Internal subdomain resolves publicly: vpn.example.com');
			expect(vpn).toBeDefined();
			expect(vpn!.severity).toBe('medium');
			expect(vpn!.metadata?.ips).toEqual(['203.0.113.10']);
			// Only the one real host counts — the nine synthetic hits must not trip "Excessive".
			expect(result.findings.find((f) => f.title.startsWith('Excessive internal subdomain exposure'))).toBeUndefined();
			expect(result.findings.filter((f) => f.severity === 'medium')).toHaveLength(1);

			const note = result.findings.find((f) => f.title === 'Wildcard DNS masks sensitive subdomain probing');
			expect(note!.metadata?.wildcardSyntheticSubdomains).toHaveLength(9);
			expect(note!.metadata?.wildcardSyntheticSubdomains).not.toContain('vpn.example.com');

			// A differing hit costs ONE confirming canary — never more than two in total.
			expect(aQueries.filter((n) => n.startsWith('_bv-probe-'))).toHaveLength(2);
		});

		it('treats a hit as synthetic when the confirming canary answers with its address (round-robin wildcard)', async () => {
			// First canary → .94, second → .95; the "hits" all answer .95, so they are the wildcard.
			wildcardMock({
				canaryIps: [['198.51.100.94'], ['198.51.100.95']],
				realHosts: Object.fromEntries(
					['vpn', 'admin', 'staging', 'dev', 'test', 'corp', 'intranet', 'internal', 'portal', 'owa'].map((l) => [
						`${l}.example.com`,
						['198.51.100.95'],
					]),
				),
			});
			const result = await run();

			expect(result.findings.filter((f) => f.severity !== 'info')).toEqual([]);
			const note = result.findings.find((f) => f.title === 'Wildcard DNS masks sensitive subdomain probing');
			expect(note!.metadata?.wildcardIps).toEqual(['198.51.100.94', '198.51.100.95']);
			expect(note!.metadata?.wildcardSyntheticSubdomains).toHaveLength(10);
		});

		it('abstains (inconclusive, not a pass) when the canary itself fails, and skips the sweep', async () => {
			const { aQueries } = wildcardMock({ canaryThrows: true });
			const result = await run();

			// No confident verdict in either direction.
			expect(result.findings.filter((f) => f.severity !== 'info')).toEqual([]);
			expect(result.findings.find((f) => f.title === 'No sensitive subdomains resolve publicly')).toBeUndefined();
			expect(result.findings.find((f) => f.title === 'Wildcard DNS masks sensitive subdomain probing')).toBeUndefined();

			const note = result.findings.find((f) => f.title === 'Sensitive subdomain probe not assessed');
			expect(note).toBeDefined();
			expect(note!.severity).toBe('info');
			expect(note!.metadata?.inconclusive).toBe(true);
			expect(note!.metadata?.errorKind).toBe('dns_error');
			expect(note!.metadata?.missingControl).toBeUndefined();

			// The sweep never ran: its ten answers could not have been interpreted.
			expect(aQueries.filter((n) => !n.startsWith('_bv-probe-'))).toEqual([]);
			// Not cached as if complete...
			expect(result.partial).toBe(true);
			// ...and EXCLUDED from scoring: `partial` never reaches the engine, an absent
			// `checkStatus` counts as measured (isCheckMeasured), and all-info would have
			// entered the weighted score as a clean 100 the withheld sweep cannot support.
			expect(result.checkStatus).toBe('error');
			expect(result.score).toBe(0);
			expect(result.passed).toBe(false);
		});

		it("keeps the SOA half's scored evidence when the canary fails (abstains on the sweep only)", async () => {
			// expire 86400 < 604800 → a real, measured `low` from Phase 1.
			wildcardMock({ canaryThrows: true, soaExpire: 86400 });
			const result = await run();

			expect(result.findings.find((f) => f.title === 'SOA expire value is short')?.severity).toBe('low');
			expect(result.findings.find((f) => f.title === 'Sensitive subdomain probe not assessed')).toBeDefined();
			// Measured evidence stands: the category is NOT excluded, only left uncached.
			expect(result.checkStatus).toBeUndefined();
			expect(result.partial).toBe(true);
			expect(result.score).toBe(95);
			expect(result.passed).toBe(true);
		});

		it('recognises a CNAME-pool wildcard whose CDN hands each label a different address subset', async () => {
			// `*.example.com CNAME pool.cdn.example.net.`; the canary sees .10/.11, the hits see .12/.13.
			const { aQueries } = wildcardMock({
				cnamePool: {
					target: 'Pool.cdn.example.net.',
					canaryIps: ['198.51.100.10', '198.51.100.11'],
					hitIps: ['198.51.100.12', '198.51.100.13'],
				},
			});
			const result = await run();

			expect(result.findings.filter((f) => f.severity !== 'info')).toEqual([]);
			const note = result.findings.find((f) => f.title === 'Wildcard DNS masks sensitive subdomain probing');
			expect(note!.metadata?.wildcardCnameTarget).toBe('pool.cdn.example.net');
			expect(note!.metadata?.wildcardSyntheticSubdomains).toHaveLength(10);
			expect(note!.detail).toContain('via pool.cdn.example.net');
			// Every hit was explained by the CNAME target, so no confirming canary was needed.
			expect(aQueries.filter((n) => n.startsWith('_bv-probe-'))).toHaveLength(1);
		});

		it('treats a dangling wildcard alias (CNAME, no address) as a wildcard and withholds the clean verdict', async () => {
			wildcardMock({ cnamePool: { target: 'gone.example.net.', canaryIps: [], hitIps: [] } });
			const result = await run();

			expect(result.findings.filter((f) => f.severity !== 'info')).toEqual([]);
			expect(result.findings.find((f) => f.title === 'No sensitive subdomains resolve publicly')).toBeUndefined();
			const note = result.findings.find((f) => f.title === 'Wildcard DNS masks sensitive subdomain probing');
			expect(note).toBeDefined();
			expect(note!.metadata?.wildcardIps).toEqual([]);
			expect(note!.metadata?.wildcardCnameTarget).toBe('gone.example.net');
			expect(note!.detail).toContain('is an alias for gone.example.net that yields no address');
		});

		it('keeps the non-wildcard sweep byte-identical apart from the single canary query', async () => {
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.includes('type=NS') || url.includes('type=2')) {
					return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
				}
				if (url.includes('type=SOA') || url.includes('type=6')) {
					return Promise.resolve(soaResponse('example.com', 'ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 300'));
				}
				if (url.includes('type=A') || url.includes('type=1')) {
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
					if (name === 'vpn.example.com') return Promise.resolve(aResponse(name, ['203.0.113.10']));
					return Promise.resolve(emptyResponse(name, 1));
				}
				return Promise.resolve(emptyResponse('example.com', 1));
			});

			const result = await run();
			const vpn = result.findings.find((f) => f.title === 'Internal subdomain resolves publicly: vpn.example.com');
			expect(vpn!.severity).toBe('medium');
			expect(result.findings.find((f) => f.title === 'Wildcard DNS masks sensitive subdomain probing')).toBeUndefined();
			expect(result.findings.find((f) => f.title === 'Sensitive subdomain probe not assessed')).toBeUndefined();
			// Distinct canary NAMES, not fetches: an empty answer falls through the resolver
			// chain (empty → secondary DoH), so one query can be two fetches — for the canary
			// exactly as for each of the ten sweep names.
			const probes = new Set(
				(globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls
					.map((c) => String(c[0] instanceof Request ? c[0].url : c[0]))
					.map((u) => u.match(/name=([^&]+)/)?.[1] ?? '')
					.filter((n) => n.includes('_bv-probe-')),
			);
			expect(probes.size).toBe(1);
		});
	});
});
