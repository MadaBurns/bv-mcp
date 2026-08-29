// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { ROOT_HINTS, ROOT_SERVER_NAMES } from '../src/lib/authoritative-dns-infra/root-hints';
import { checkRootServerSet } from '../src/tools/check-root-server-set';

describe('checkRootServerSet', () => {
	it('returns embedded official root hints when the infra probe binding is absent', async () => {
		const result = await checkRootServerSet();

		// #696 — see the twin assertion in test/check-authoritative-dns-infra.spec.ts.
		expect(result).toMatchObject({
			category: 'authoritative_dns_infra',
			passed: false,
			score: 0,
			checkStatus: 'error',
			partial: true,
			metadata: {
				evidenceMode: 'worker_only',
				rootServers: ROOT_SERVER_NAMES,
			},
		});
		// The check compares its own embedded ROOT_SERVER_NAMES constant against itself, so
		// `official_root_hints_match` cannot be reported as PASSED without a live query.
		const summary = result.metadata?.capabilitySummary as { passed: string[]; inconclusive: string[] };
		expect(summary.passed).toEqual([]);
		expect(summary.inconclusive).toContain('official_root_hints_match');
		expect(result.findings).toContainEqual(
			expect.objectContaining({
				title: 'Official root hints embedded',
				severity: 'info',
			}),
		);
	});

	it('degrades gracefully (does not throw) when the infra probe returns HTTP 503', async () => {
		const fetch = vi.fn(async () => new Response('upstream unavailable', { status: 503 }));

		const result = await checkRootServerSet({
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(fetch).toHaveBeenCalledOnce();
		expect(result).toMatchObject({
			category: 'authoritative_dns_infra',
			checkStatus: 'error',
			partial: true,
			metadata: { evidenceMode: 'probe_unavailable', rootServers: ROOT_SERVER_NAMES },
		});
		expect(result.findings).toContainEqual(
			expect.objectContaining({
				title: 'Root server set probe unavailable',
				severity: 'info',
			}),
		);
	});

	it('degrades gracefully when the infra probe fetch rejects (network error)', async () => {
		const fetch = vi.fn(async () => {
			throw new Error('Connection reset');
		});

		const result = await checkRootServerSet({
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(result.checkStatus).toBe('error');
		expect(result.metadata?.evidenceMode).toBe('probe_unavailable');
		expect(result.findings).toContainEqual(
			expect.objectContaining({
				title: 'Root server set probe unavailable',
				severity: 'info',
			}),
		);
	});

	it('posts to the root-server-set probe and fails mismatched root infrastructure evidence', async () => {
		const fetch = vi.fn(async () => new Response(JSON.stringify({
			hostname: '.',
			checkedAt: '2026-05-21T00:00:00.000Z',
			rootHints: ROOT_HINTS,
			observedRootServers: ROOT_SERVER_NAMES.slice(0, -1),
			parentChildDelegationMatches: false,
			glueMatchesHints: false,
			serialsByRoot: {
				'a.root-servers.net': 2026052101,
				'b.root-servers.net': 2026052102,
			},
			dnskeyDigestsByRoot: {
				'a.root-servers.net': 'sha256:a',
				'b.root-servers.net': 'sha256:b',
			},
		})));

		const result = await checkRootServerSet({
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(fetch).toHaveBeenCalledOnce();
		const [url, init] = fetch.mock.calls[0];
		expect(url).toBe('https://infra-probe.internal/probe/root-server-set');
		expect(init).toMatchObject({
			method: 'POST',
			headers: { 'content-type': 'application/json' },
		});
		expect(JSON.parse(String(init?.body))).toEqual({});
		expect(result.passed).toBe(false);
		expect(result.score).toBe(0);
		expect(result.metadata?.capabilitySummary).toMatchObject({
			failed: expect.arrayContaining([
				'root_priming_ns_set',
				'root_glue_records',
				'root_servers_parent_child_delegation',
				'root_server_ns_soa_dnskey_cross_compare',
				'stale_root_zone_serial_detection',
			]),
		});
		expect(result.findings.map((finding) => finding.title)).toEqual(expect.arrayContaining([
			'Root server set mismatch',
			'Root glue does not match official hints',
			'Root parent/child delegation mismatch',
			'Root DNSKEY digests differ across roots',
			'Root zone serials differ across roots',
		]));
	});

	// #828 — the probe body is an unchecked generic cast (`readJsonResponse<T>`), and
	// `rootHintsMatchOfficial` dereferences `evidence.rootHints.length` unconditionally.
	// A 200 response omitting `rootHints` used to throw an uncaught TypeError out of
	// `checkRootServerSet` (the try/catch only covers the fetch). The shape is now
	// validated at the fetchRootServerSetEvidence boundary so a malformed body degrades
	// through the same probe-unavailable inconclusive path as a 5xx.
	it('degrades gracefully when a 200 probe response omits rootHints (#828)', async () => {
		const fetch = vi.fn(async () => new Response(JSON.stringify({
			hostname: '.',
			checkedAt: '2026-05-21T00:00:00.000Z',
		})));

		const result = await checkRootServerSet({
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(result.checkStatus).toBe('error');
		expect(result.partial).toBe(true);
		expect(result.metadata?.evidenceMode).toBe('probe_unavailable');
		expect(result.findings).toContainEqual(
			expect.objectContaining({
				title: 'Root server set probe unavailable',
				severity: 'info',
			}),
		);
	});

	it('degrades gracefully when rootHints contains non-object entries (#828)', async () => {
		const fetch = vi.fn(async () => new Response(JSON.stringify({
			hostname: '.',
			checkedAt: '2026-05-21T00:00:00.000Z',
			rootHints: [null, 'a.root-servers.net'],
		})));

		const result = await checkRootServerSet({
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(result.checkStatus).toBe('error');
		expect(result.metadata?.evidenceMode).toBe('probe_unavailable');
	});

	// The subtler half of #828: shapes that pass a naive "is an array of objects" check but
	// would flow into `rootHintsMatchOfficial` and score as a MEASURED critical mismatch
	// ("Root hints do not match official constants", missingControl) — a scored claim
	// manufactured from a probe defect. They must degrade to inconclusive instead.
	it('degrades gracefully when rootHints is an empty array (#828)', async () => {
		const fetch = vi.fn(async () => new Response(JSON.stringify({
			hostname: '.',
			checkedAt: '2026-05-21T00:00:00.000Z',
			rootHints: [],
		})));

		const result = await checkRootServerSet({
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(result.checkStatus).toBe('error');
		expect(result.partial).toBe(true);
		expect(result.metadata?.evidenceMode).toBe('probe_unavailable');
		expect(result.findings.map((finding) => finding.title)).not.toContain(
			'Root hints do not match official constants',
		);
	});

	it('degrades gracefully when rootHints entries are missing required fields (#828)', async () => {
		const fetch = vi.fn(async () => new Response(JSON.stringify({
			hostname: '.',
			checkedAt: '2026-05-21T00:00:00.000Z',
			// 13 well-typed objects, none carrying the ipv4/ipv6/operator strings the
			// analyzer compares — schema-invalid per RootHintEntryEvidence.
			rootHints: ROOT_SERVER_NAMES.map((name) => ({ name })),
		})));

		const result = await checkRootServerSet({
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(result.checkStatus).toBe('error');
		expect(result.metadata?.evidenceMode).toBe('probe_unavailable');
		expect(result.findings.map((finding) => finding.title)).not.toContain(
			'Root hints do not match official constants',
		);
	});

	// Non-regression for the guard: a shape-VALID hint set with wrong values is a genuine
	// measurement and must still score as a critical mismatch, not be routed to inconclusive.
	it('still scores a shape-valid but mismatched root hint set as a real failure (#828)', async () => {
		const fetch = vi.fn(async () => new Response(JSON.stringify({
			hostname: '.',
			checkedAt: '2026-05-21T00:00:00.000Z',
			rootHints: ROOT_HINTS.map((hint) => ({ ...hint, ipv4: '192.0.2.1' })),
		})));

		const result = await checkRootServerSet({
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(result.checkStatus).toBeUndefined();
		expect(result.metadata?.evidenceMode).toBe('infra_probe');
		expect(result.findings.map((finding) => finding.title)).toContain(
			'Root hints do not match official constants',
		);
	});

	// Sibling of #812 / PR #824 (analyze.ts). `analyzeRootServerSetEvidence`
	// (analyze-root-server-set.ts) had the identical unconditional
	// `if (findings.length === 0) push "checks passed"` shape: `findings.length
	// === 0` proves no FAILURE finding fired, not that anything was
	// CONCLUSIVE — with every capability inconclusive it is reached on zero
	// evidence either way. The gate now requires `capabilitySummary.passed.length
	// > 0`, mirroring #824 exactly.
	//
	// Unlike analyze.ts's capabilities, this file's `official_root_hints_match`
	// is a synchronous comparison against the REQUIRED `evidence.rootHints`
	// field (`rootHintsMatchOfficial`) and always resolves to a definite
	// boolean — it can never be `undefined`/inconclusive. That means
	// `findings.length === 0` structurally implies `official_root_hints_match`
	// resolved `true` (a genuine conclusive pass), so the true "every capability
	// inconclusive" vacuous state #812/#824 hit is not reachable through this
	// analyzer's public evidence contract today (verified empirically). This
	// test instead locks in the reachable boundary the new gate must not
	// regress: root hints conclusively matching, with every other cross-root
	// check inconclusive, must still report a genuine pass — not the new
	// "inconclusive" branch.
	it('still reports a genuine pass when root hints are the only conclusive capability (#812 sibling)', async () => {
		const fetch = vi.fn(async () => new Response(JSON.stringify({
			hostname: '.',
			checkedAt: '2026-05-21T00:00:00.000Z',
			rootHints: ROOT_HINTS,
			// No observedRootServers/glueMatchesHints/parentChildDelegationMatches/
			// serialsByRoot/dnskeyDigestsByRoot at all — every cross-root check
			// besides the root-hints comparison is inconclusive.
		})));

		const result = await checkRootServerSet({
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		const summary = result.metadata?.capabilitySummary as { passed: string[]; failed: string[]; inconclusive: string[] };
		expect(summary.passed).toEqual(['official_root_hints_match']);
		expect(summary.failed).toEqual([]);
		expect(summary.inconclusive).toEqual(expect.arrayContaining([
			'root_priming_ns_set',
			'root_glue_records',
			'root_servers_parent_child_delegation',
			'root_server_ns_soa_dnskey_cross_compare',
			'stale_root_zone_serial_detection',
		]));

		const titles = result.findings.map((finding) => finding.title);
		expect(titles).toContain('Root server set checks passed');
		expect(titles).not.toContain('Root server set checks inconclusive');
	});
});
