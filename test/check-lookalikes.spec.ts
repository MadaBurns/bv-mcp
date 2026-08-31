import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Helper to parse the DoH query name and type from a fetch URL */
function parseDohQuery(input: string | URL | Request): { name: string; type: string } {
	const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
	const parsed = new URL(url);
	return {
		name: parsed.searchParams.get('name') ?? '',
		type: parsed.searchParams.get('type') ?? '',
	};
}

describe('checkLookalikes', () => {
	async function run(domain = 'example.com') {
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		return checkLookalikes(domain);
	}

	it('should return info finding when no active lookalikes found', async () => {
		// All DNS queries return empty
		globalThis.fetch = vi.fn().mockImplementation(() => {
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');
		expect(result.category).toBe('lookalikes');
		const info = result.findings.find((f) => /No active lookalike/i.test(f.title));
		expect(info).toBeDefined();
		expect(info!.severity).toBe('info');
	});

	// D4 fixture repair (2026-07-26 correctness-defects design): these
	// candidates' NS ('ns1.registrar.com.') carries no ownership signal —
	// third_party under classifyOwnership() — so the calibrated #264
	// mail-infra-alone MEDIUM is now capped to info by the ownership gate
	// (a third_party verdict can never exceed info). The #264 calibration
	// still runs internally (it drives wording/metadata), it just no longer
	// surfaces as an elevated `.severity` for a domain the scanner cannot
	// attribute to the scanned organisation. The `describeCorroborators`
	// hedge stays observable in `.detail`.
	it('caps mail-infra-alone lookalikes with no ownership signal at info, never elevates them (issue #264 matrix, D4-capped)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Make one specific lookalike have MX records
			if (name === 'twst.com' || name === 'tst.com' || name === 'tes.com' || name === 'testt.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.example.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');
		// Task 7b: the two axes are pinned SEPARATELY. Axis 1 (attribution) is
		// still capped at info for every non-owned candidate — D4 unchanged.
		const attribution = result.findings.filter((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution.length).toBeGreaterThan(0);
		expect(attribution.every((f) => f.severity === 'info')).toBe(true);
		expect(attribution.every((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(true);
		// Axis 2 (threat observation) carries the #264 mail-infra-alone MEDIUM
		// that Task 7 used to discard.
		const threat = result.findings.filter((f) => f.metadata?.findingAxis === 'threat_observation');
		expect(threat.length).toBeGreaterThan(0);
		expect(threat.every((f) => f.severity === 'medium')).toBe(true);
		// Still no HIGH: mail infrastructure alone, with no corroborator.
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('caps web-only lookalikes with no ownership signal at info (web-only, no corroborator, D4-capped)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// One lookalike with A record but no MX
			if (name === 'tst.com' || name === 'tes.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');
		// Axis 1 — attribution capped at info.
		const attribution = result.findings.filter(
			(f) => f.metadata?.findingAxis === 'attribution' && f.metadata?.ownershipVerdict === 'third_party' && f.metadata?.hasMX === false,
		);
		expect(attribution.length).toBeGreaterThan(0);
		expect(attribution.every((f) => f.severity === 'info')).toBe(true);
		// Axis 2 — web-only with no corroborator is the matrix's LOW tier, and
		// never more than that.
		const threat = result.findings.filter((f) => f.metadata?.findingAxis === 'threat_observation');
		expect(threat.length).toBeGreaterThan(0);
		expect(threat.every((f) => f.severity === 'low')).toBe(true);
		expect(result.findings.some((f) => f.severity === 'medium' || f.severity === 'high')).toBe(false);
	});

	it('surfaces a registered combosquat (brand + lure affix) that edit-distance generation misses, capped at info (no ownership signal)', async () => {
		// `paypal-login.com` is a combosquat of `paypal.com`: generateLookalikes
		// (edit-distance mutators) never produces it — generateCombosquats does.
		// It has mail infrastructure and would calibrate to MEDIUM per the #264
		// matrix, but carries no ownership signal (third_party) so the D4 gate
		// caps it at info — proving Part 3 generation still feeds the same
		// ownership-gated pipeline as every other detection path.
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'paypal-login.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.attacker.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('paypal.com');
		const surfaced = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'paypal-login.com');
		expect(surfaced.length).toBeGreaterThan(0);
		// Task 7b: attribution capped at info; the #264 mail-infra MEDIUM now
		// surfaces on the threat axis instead of being discarded.
		expect(surfaced.filter((f) => f.metadata?.findingAxis === 'attribution').every((f) => f.severity === 'info')).toBe(true);
		expect(surfaced.filter((f) => f.metadata?.findingAxis === 'threat_observation').every((f) => f.severity === 'medium')).toBe(true);
		expect(JSON.stringify(result.findings)).toContain('paypal-login.com');
	});

	it('should handle individual query failures gracefully via Promise.allSettled', async () => {
		let callCount = 0;
		globalThis.fetch = vi.fn().mockImplementation(() => {
			callCount++;
			// Every other call fails
			if (callCount % 3 === 0) {
				return Promise.reject(new Error('DNS timeout'));
			}
			return Promise.resolve(createDohResponse([], []));
		});
		// Should not throw
		const result = await run('test.com');
		expect(result.category).toBe('lookalikes');
		expect(result.findings.length).toBeGreaterThan(0);
	});

	it('should handle all probe failures without crashing', async () => {
		globalThis.fetch = vi.fn().mockImplementation(() => {
			return Promise.reject(new Error('DNS timeout'));
		});
		const result = await run('test.com');
		expect(result.category).toBe('lookalikes');
		// Should still produce a finding (info: no active lookalikes)
		expect(result.findings.length).toBeGreaterThan(0);
		const info = result.findings.find((f) => /No active lookalike/i.test(f.title));
		expect(info).toBeDefined();
	});

	it('exports adaptive batching constants', async () => {
		const mod = await import('../src/tools/check-lookalikes');
		expect(mod.INITIAL_BATCH_SIZE).toBe(10);
		expect(mod.MIN_BATCH_SIZE).toBe(3);
		expect(mod.BACKOFF_DELAY_MS).toBe(500);
		expect(mod.FAILURE_THRESHOLD).toBe(2);
	});

	it('exports Phase 1 lean DNS options', async () => {
		const mod = await import('../src/tools/check-lookalikes');
		expect(mod.PHASE1_DNS_OPTS).toEqual({
			timeoutMs: 2000,
			retries: 0,
			skipSecondaryConfirmation: true,
		});
	});

	it('should not report lookalikes that have no NS records (Phase 1 filter)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// tst.com has A + MX but NO NS records — should be filtered by Phase 1
			if (name === 'tst.com') {
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.tst.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeUndefined();
	});

	it('should report lookalikes that pass Phase 1 NS check', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// tst.com has NS + A records (no MX) — should pass Phase 1 and be reported as low
			// (web-only baseline per issue #264 matrix; was MEDIUM under the old rule).
			if (name === 'tst.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		// D4-capped: no ownership signal (ns1.registrar.com) → third_party → info,
		// not the raw web-only LOW the #264 calibrator computes internally.
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('third_party');
	});
});

describe('checkLookalikes - null MX filtering', () => {
	async function run(domain = 'example.com') {
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		return checkLookalikes(domain);
	}

	it('should not flag null MX (0 .) as mail infrastructure', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Make a lookalike resolve with A + null MX
			if (name === 'tst.com' || name === 'tes.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '0 .' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');

		// D4-capped: no ownership signal, so severity is 'info' regardless — the
		// title-based "mail infrastructure" check no longer discriminates null-MX
		// filtering (every capped finding is retitled "Unrelated domain,
		// confusable label: X"). The actual point — null MX must NOT register as
		// real mail infra — is now pinned on the preserved `hasMX` metadata.
		const gated = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'tst.com' || f.metadata?.lookalikeDomain === 'tes.com');
		expect(gated.length).toBeGreaterThan(0);
		expect(gated.every((f) => f.metadata?.hasMX === false)).toBe(true);
		// Task 7b: severity is axis-scoped — attribution stays info; the threat
		// axis reports the web-only LOW tier (NOT a mail-infra MEDIUM/HIGH,
		// which is the null-MX point this test exists for).
		expect(gated.filter((f) => f.metadata?.findingAxis === 'attribution').every((f) => f.severity === 'info')).toBe(true);
		expect(gated.filter((f) => f.metadata?.findingAxis === 'threat_observation').every((f) => f.severity === 'low')).toBe(true);
	});

	it('should not flag legacy null MX (0 localhost.) as mail infrastructure', async () => {
		// Empirical case: opejai.com (an OpenAI typosquat) declares `MX 0 localhost.`
		// — the legacy null-MX convention. Before this fix the lookalikes tool reported it
		// as a HIGH mail-active phishing risk, inflating the count.
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'tst.com' || name === 'tes.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '0 localhost.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');
		// D4-capped (third_party, no ownership signal): title no longer carries
		// "mail infrastructure" wording for ANY capped finding, so the actual
		// point — legacy null MX must not register as real mail infra — is
		// pinned on the preserved `hasMX` metadata instead.
		const gated = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'tst.com' || f.metadata?.lookalikeDomain === 'tes.com');
		expect(gated.length).toBeGreaterThan(0);
		expect(gated.every((f) => f.metadata?.hasMX === false)).toBe(true);
	});

	it('should flag real MX but ignore null MX in mixed responses', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			if (name === 'testt.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
				}
				// This domain has a real MX record → HIGH
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.testt.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}
			if (name === 'tes.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
				}
				// This domain has null MX → should NOT be flagged as HIGH
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '0 .' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '2.3.4.5' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');

		// D4-capped (neither has an ownership signal — third_party): the raw
		// #264 calibration (testt.com → MEDIUM mail-infra, tes.com → LOW
		// web-only) still runs internally but is capped to info. What this test
		// actually still needs to prove — real MX registers, null MX does not —
		// is pinned on the `hasMX` metadata rather than the severity/title.
		const testtFinding = result.findings.find(
			(f) => f.metadata?.lookalikeDomain === 'testt.com' && f.metadata?.findingAxis === 'attribution',
		);
		expect(testtFinding).toBeDefined();
		expect(testtFinding!.metadata?.hasMX).toBe(true);
		expect(testtFinding!.severity).toBe('info');

		const tesFinding = result.findings.find((f) => f.metadata?.lookalikeDomain === 'tes.com' && f.metadata?.findingAxis === 'attribution');
		expect(tesFinding).toBeDefined();
		expect(tesFinding!.metadata?.hasMX).toBe(false);
		expect(tesFinding!.severity).toBe('info');

		// Task 7b: the threat axis is where the null-MX distinction now shows up
		// numerically — real MX → mail-infra MEDIUM, null MX → web-only LOW.
		// Neither reaches HIGH (no corroborator on either).
		const threatFor = (d: string) =>
			result.findings.find((f) => f.metadata?.lookalikeDomain === d && f.metadata?.findingAxis === 'threat_observation');
		expect(threatFor('testt.com')!.severity).toBe('medium');
		expect(threatFor('tes.com')!.severity).toBe('low');
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
	});
});

describe('checkLookalikes - wildcard DNS filtering', () => {
	async function run(domain = 'example.com') {
		const { checkLookalikes, WILDCARD_CANARY_LABEL } = await import('../src/tools/check-lookalikes');
		return { result: await checkLookalikes(domain), WILDCARD_CANARY_LABEL };
	}

	it('should filter out dot-insertion permutations when parent has wildcard DNS', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Wildcard: any subdomain of "st.com" resolves (including the canary)
			if (name.endsWith('.st.com')) {
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.parked.com.' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});

		const { result } = await run('test.com');

		// "te.st.com" is a dot-insertion permutation of "test.com" under parent "st.com"
		// Since st.com has wildcard DNS, it should be filtered out
		const teStFinding = result.findings.find((f) => f.title.includes('te.st.com'));
		expect(teStFinding).toBeUndefined();
	});

	it('should keep dot-insertion permutations when parent has no wildcard DNS', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Only the actual dot-insertion domain resolves, canary does NOT
			if (name === 'te.st.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '5.6.7.8' }]));
				}
			}
			// Everything else (including canary probes) returns empty
			return Promise.resolve(createDohResponse([], []));
		});

		const { result } = await run('test.com');

		// te.st.com should remain because st.com has no wildcard
		const teStFinding = result.findings.find((f) => f.title.includes('te.st.com'));
		expect(teStFinding).toBeDefined();
		// D4-capped: no ownership signal → third_party → info (the web-only LOW
		// baseline still computes internally but is capped at the tool boundary).
		expect(teStFinding!.severity).toBe('info');
	});

	it('should not affect non-dot-insertion permutations regardless of wildcard', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// tst.com (character omission, not dot-insertion) resolves
			if (name === 'tst.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '9.8.7.6' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});

		const { result } = await run('test.com');

		// tst.com is a same-label-count permutation (char omission), not dot-insertion — should be kept
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		// D4-capped: no ownership signal → third_party → info.
		expect(tstFinding!.severity).toBe('info');
	});

	it('exports WILDCARD_CANARY_LABEL constant', async () => {
		const { WILDCARD_CANARY_LABEL } = await import('../src/tools/check-lookalikes');
		expect(WILDCARD_CANARY_LABEL).toBe('_bv-wc-probe');
	});
});

describe('checkLookalikes - shared nameserver detection', () => {
	async function run(domain = 'example.com') {
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		return checkLookalikes(domain);
	}

	it('should downgrade to info when lookalike shares nameservers with primary domain', async () => {
		const sharedNs = 'ns1.cloudflare.com.';
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Primary domain NS
			if (name === 'test.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 2 }],
						[
							{ name, type: 2, TTL: 300, data: sharedNs },
							{ name, type: 2, TTL: 300, data: 'ns2.cloudflare.com.' },
						],
					),
				);
			}

			// tst.com (char omission) — shares NS with primary
			if (name === 'tst.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							[
								{ name, type: 2, TTL: 300, data: sharedNs },
								{ name, type: 2, TTL: 300, data: 'ns2.cloudflare.com.' },
							],
						),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.tst.com.' }]));
				}
			}

			return Promise.resolve(createDohResponse([], []));
		});

		const result = await run('test.com');

		// tst.com should be info (2/2 dedicated NS match = owned_by_seed under
		// classifyOwnership), NOT high.
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.title).toContain('likely owned by same entity');
		expect(tstFinding!.detail).toContain('dedicated nameservers');
		expect(tstFinding!.detail).toContain('mail infrastructure');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('owned_by_seed');

		// Should NOT appear in the high count summary
		const highSummary = result.findings.find((f) => /mail capability detected/i.test(f.title));
		expect(highSummary).toBeUndefined();
	});

	// D4-capped (2026-07-26 correctness-defects design): tst.com's NS
	// ('ns1.attacker-dns.com.') carries no ownership signal against the
	// primary — third_party. What USED to be described as "keep high
	// severity" is now capped at info by the ownership gate: a domain the
	// scanner cannot attribute to the scanned organisation can never surface
	// above info, regardless of how threatening its raw MX signal looks. The
	// underlying #264 calibration (MX-alone → medium) still runs internally,
	// preserved in `hasMX` metadata, but the visible severity is capped.
	it('caps a lookalike with different (unrelated) nameservers at info despite active MX (D4 ownership cap)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Primary domain NS
			if (name === 'test.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.cloudflare.com.' }]));
			}

			// tst.com has DIFFERENT (unrelated) nameservers + MX — no ownership
			// signal against the primary.
			if (name === 'tst.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.attacker-dns.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '6.6.6.6' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.evil.com.' }]));
				}
			}

			return Promise.resolve(createDohResponse([], []));
		});

		const result = await run('test.com');

		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		// D4-capped: third_party (unrelated NS) — capped at info regardless of
		// the raw #264 MX-alone MEDIUM the calibrator computes internally.
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('third_party');
		expect(tstFinding!.metadata?.hasMX).toBe(true);
	});

	// D4 fixture repair: classifyOwnership()'s dedicated NS-set-match rule
	// (rule 5) requires >= 2 matching dedicated hosts, not a single host — a
	// SINGLE arbitrary hostname match is exactly the naive threshold=1
	// coincidence this design closes off (§3.3). Two dedicated hosts here
	// keeps the scenario genuinely owned_by_seed.
	it('should downgrade medium to info when lookalike with A record shares a 2-host dedicated NS pair', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Primary domain NS
			if (name === 'test.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 2 }],
						[
							{ name, type: 2, TTL: 300, data: 'ns1.example-dns.com.' },
							{ name, type: 2, TTL: 300, data: 'ns2.example-dns.com.' },
						],
					),
				);
			}

			// tst.com shares the same 2-host dedicated NS pair, has an A record but no MX
			if (name === 'tst.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							[
								{ name, type: 2, TTL: 300, data: 'ns1.example-dns.com.' },
								{ name, type: 2, TTL: 300, data: 'ns2.example-dns.com.' },
							],
						),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}

			return Promise.resolve(createDohResponse([], []));
		});

		const result = await run('test.com');

		// Should be info, not medium
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.title).toContain('likely owned by same entity');
		expect(tstFinding!.detail).toContain('web presence');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('owned_by_seed');
	});

	// D4 fixture repair: same 2-host minimum as above — a single normalized
	// hostname match doesn't clear classifyOwnership()'s rule-5 threshold, so
	// a second host is added to both sides. Casing/trailing-dot variation is
	// kept on one host pair to still exercise the normalization this test is
	// actually about.
	it('should handle NS comparison case-insensitively and strip trailing dots', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Primary domain NS with trailing dot and mixed case
			if (name === 'test.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 2 }],
						[
							{ name, type: 2, TTL: 300, data: 'NS1.CloudFlare.COM.' },
							{ name, type: 2, TTL: 300, data: 'NS2.CloudFlare.COM.' },
						],
					),
				);
			}

			// tst.com has the same NS but different casing/trailing dot
			if (name === 'tst.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							[
								{ name, type: 2, TTL: 300, data: 'ns1.cloudflare.com' },
								{ name, type: 2, TTL: 300, data: 'ns2.cloudflare.com' },
							],
						),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}

			return Promise.resolve(createDohResponse([], []));
		});

		const result = await run('test.com');

		// Despite case/dot differences, NS should match
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
	});

	it('should not downgrade when primary NS query fails (empty set)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Primary domain NS query fails (returns empty)
			if (name === 'test.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([], []));
			}

			// tst.com has NS + MX
			if (name === 'tst.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.cloudflare.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.tst.com.' }]));
				}
			}

			return Promise.resolve(createDohResponse([], []));
		});

		const result = await run('test.com');

		// Primary NS unknown (empty set — can't compare) → third_party (no
		// ownership signal at all) → D4-capped at info, same numeric outcome as
		// an explicit ownership downgrade would produce, but via the "no
		// evidence" path rather than a same-owner claim.
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('third_party');
		// And must NOT carry the same-owner claim (no shared NS detected).
		expect(tstFinding!.title).not.toContain('likely owned by same entity');
	});

	it('should handle mixed scenario: some shared NS, some different', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Primary domain NS
			if (name === 'test.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 2 }],
						[
							{ name, type: 2, TTL: 300, data: 'ns1.cloudflare.com.' },
							{ name, type: 2, TTL: 300, data: 'ns2.cloudflare.com.' },
						],
					),
				);
			}

			// tst.com — shares NS (defensive registration) with MX
			if (name === 'tst.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							[
								{ name, type: 2, TTL: 300, data: 'ns1.cloudflare.com.' },
								{ name, type: 2, TTL: 300, data: 'ns2.cloudflare.com.' },
							],
						),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.tst.com.' }]));
				}
			}

			// testt.com — different NS (attacker) with MX
			if (name === 'testt.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.evil-registrar.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '6.6.6.6' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.evil.com.' }]));
				}
			}

			return Promise.resolve(createDohResponse([], []));
		});

		const result = await run('test.com');

		// tst.com should be info (2/2 dedicated NS match = owned_by_seed)
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('owned_by_seed');

		// testt.com has different (unrelated) NS + MX — third_party — D4-capped
		// at info regardless of the raw #264 MX-alone MEDIUM computed internally.
		const testtFinding = result.findings.find((f) => f.title.includes('testt.com'));
		expect(testtFinding).toBeDefined();
		expect(testtFinding!.severity).toBe('info');
		expect(testtFinding!.metadata?.ownershipVerdict).toBe('third_party');

		// No HIGH summary fires because nothing surfaces above info.
		const summary = result.findings.find((f) => /mail capability detected/i.test(f.title));
		expect(summary).toBeUndefined();
	});
});

describe('checkLookalikes - timeout partial flag', () => {
	it('marks result as partial when check times out', async () => {
		// Make all DNS queries hang indefinitely so the timeout fires
		globalThis.fetch = vi.fn().mockImplementation(() => {
			return new Promise(() => {
				// Never resolves — forces the LOOKALIKE_TIMEOUT_MS race to win
			});
		});

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com');

		// Timeout path should mark result as partial
		expect(result.partial).toBe(true);
		expect(result.findings.length).toBe(1);
		expect(result.findings[0].title).toBe('Lookalike check incomplete');
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].detail).toContain('did not complete within the time limit');
	}, 25_000);

	it('does not mark successful results as partial', async () => {
		// All DNS queries return empty — check completes normally
		globalThis.fetch = vi.fn().mockImplementation(() => {
			return Promise.resolve(createDohResponse([], []));
		});

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com');

		expect(result.partial).toBeUndefined();
	});
});

describe('checkLookalikes - issue #264 severity calibration wiring', () => {
	async function run(domain = 'example.com') {
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		return checkLookalikes(domain);
	}

	/**
	 * Helper that mocks DoH for the lookalike probes AND mocks an RDAP server
	 * fetch to return a registration event N days ago. The HEAD probe defaults
	 * to ok:true (fail-soft → hasWebContent=true) unless the test overrides
	 * the URL to be parked/refused.
	 */
	function mockWithRdap(opts: { mailDomain: string; mxExchange?: string; registrationDaysAgo?: number | null; hasWebContent?: boolean }) {
		const { mailDomain, mxExchange = 'mail.example.com.', registrationDaysAgo, hasWebContent = true } = opts;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DoH queries
			if (url.includes('cloudflare-dns.com')) {
				const { name, type } = parseDohQuery(input);
				if (name === mailDomain) {
					if (type === 'NS' || type === '2') {
						return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
					}
					if (type === 'MX' || type === '15') {
						return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: `10 ${mxExchange}` }]));
					}
					if (type === 'A' || type === '1') {
						return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
					}
				}
				return Promise.resolve(createDohResponse([], []));
			}

			// RDAP queries — match /domain/<domain> on the RDAP-server path
			if (url.includes('rdap') && url.includes(`/domain/${mailDomain}`)) {
				if (registrationDaysAgo == null) {
					return Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({}) } as unknown as Response);
				}
				const eventDate = new Date(Date.now() - registrationDaysAgo * 24 * 60 * 60 * 1000).toISOString();
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve({ events: [{ eventAction: 'registration', eventDate }] }),
				} as unknown as Response);
			}

			// HEAD probe — return ok or "no content" per opts
			if (url.startsWith('https://') || url.startsWith('http://')) {
				if (!hasWebContent) {
					return Promise.reject(new Error('connection refused'));
				}
				return Promise.resolve({
					ok: true,
					status: 200,
					headers: new Headers(),
					text: () => Promise.resolve(''),
					json: () => Promise.resolve({}),
				} as unknown as Response);
			}

			return Promise.resolve(createDohResponse([], []));
		});
	}

	// D4-capped (2026-07-26 correctness-defects design): 'ns1.registrar.com.'
	// carries no ownership signal against the (unmocked, empty) primary NS —
	// third_party. Every RDAP-driven elevation in this describe block still
	// runs internally (it is what produces the `registrationDays`/
	// `mxOnDisposable`/`hasWebContent` metadata pinned below, proving the
	// wiring is intact), but the OUTPUT severity is now capped at info for a
	// domain the scanner cannot attribute to the scanned organisation — a
	// domain that genuinely calibrates to HIGH under #264 is exactly the
	// riskiest case for a false-attribution claim, so it is not exempted.
	it('caps mail-infra + recent registration at info despite calibrating internally to HIGH', async () => {
		mockWithRdap({ mailDomain: 'tst.com', registrationDaysAgo: 30 });
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.metadata?.lookalikeDomain === 'tst.com');
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('third_party');
		expect(tstFinding!.metadata?.registrationDays).toBe(30);
	});

	it('caps mail-infra at info when registration is old (≥90d) — internal calibration stays MEDIUM-shaped in metadata', async () => {
		mockWithRdap({ mailDomain: 'tst.com', registrationDaysAgo: 1500 });
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.metadata?.lookalikeDomain === 'tst.com');
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.registrationDays).toBe(1500);
	});

	it('caps mail-infra + disposable MX at info despite calibrating internally to HIGH', async () => {
		mockWithRdap({ mailDomain: 'tst.com', mxExchange: 'smtp.mailgun.org.', registrationDaysAgo: null });
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.metadata?.lookalikeDomain === 'tst.com');
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.mxOnDisposable).toBe(true);
	});

	it('caps mail-infra + no web content (parked/refused) at info despite calibrating internally to HIGH', async () => {
		mockWithRdap({ mailDomain: 'tst.com', registrationDaysAgo: null, hasWebContent: false });
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.metadata?.lookalikeDomain === 'tst.com');
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.hasWebContent).toBe(false);
	});

	it('caps web-only + recent registration at info despite calibrating internally to MEDIUM', async () => {
		// Build a slightly different mock — no MX, A only, recent registration.
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				const { name, type } = parseDohQuery(input);
				if (name === 'tst.com') {
					if (type === 'NS' || type === '2') {
						return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
					}
					if (type === 'A' || type === '1') {
						return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
					}
				}
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('rdap') && url.includes('/domain/tst.com')) {
				const eventDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve({ events: [{ eventAction: 'registration', eventDate }] }),
				} as unknown as Response);
			}
			if (url.startsWith('https://') || url.startsWith('http://')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					headers: new Headers(),
					text: () => Promise.resolve(''),
					json: () => Promise.resolve({}),
				} as unknown as Response);
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('third_party');
		expect(tstFinding!.metadata?.registrationDays).toBe(30);
	});
});

describe('checkLookalikes - issue #263 same-entity RDAP registrant correlation', () => {
	async function run(domain = 'example.com') {
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		return checkLookalikes(domain);
	}

	/** Build an RDAP domain response carrying a registrant entity with the given org via a vCard `org` property. */
	function rdapWithRegistrant(org: string | null, registrationDaysAgo: number | null = 1500) {
		const events =
			registrationDaysAgo == null
				? []
				: [{ eventAction: 'registration', eventDate: new Date(Date.now() - registrationDaysAgo * 24 * 60 * 60 * 1000).toISOString() }];
		const entities =
			org == null
				? []
				: [
						{
							objectClassName: 'entity',
							roles: ['registrant'],
							vcardArray: [
								'vcard',
								[
									['version', {}, 'text', '4.0'],
									['org', {}, 'text', org],
								],
							],
						},
					];
		return { events, entities };
	}

	/**
	 * Mock that serves DoH probes for one lookalike (NS/A/MX, DIFFERENT NS from
	 * the primary so the shared-NS pass does NOT short-circuit), the primary
	 * domain's NS, and RDAP responses for BOTH the lookalike and the primary.
	 * Registrant orgs are injected per-domain so the same-entity correlation can
	 * be exercised. HEAD probes default to ok (hasWebContent=true).
	 */
	function mockSameEntity(opts: {
		lookalike: string;
		lookalikeRdap: ReturnType<typeof rdapWithRegistrant> | { fail: true };
		primaryRdap: ReturnType<typeof rdapWithRegistrant>;
	}) {
		const { lookalike, lookalikeRdap, primaryRdap } = opts;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DoH queries
			if (url.includes('cloudflare-dns.com')) {
				const { name, type } = parseDohQuery(input);
				if (name === 'test.com' && (type === 'NS' || type === '2')) {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]));
				}
				if (name === lookalike) {
					if (type === 'NS' || type === '2') {
						// DIFFERENT NS provider — shared-NS pass must NOT fire (forces the RDAP path).
						return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.other-dns.com.' }]));
					}
					if (type === 'MX' || type === '15') {
						return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.example.com.' }]));
					}
					if (type === 'A' || type === '1') {
						return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
					}
				}
				return Promise.resolve(createDohResponse([], []));
			}

			// RDAP for the lookalike
			if (url.includes('rdap') && url.includes(`/domain/${lookalike}`)) {
				if ('fail' in lookalikeRdap) {
					return Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) } as unknown as Response);
				}
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(lookalikeRdap) } as unknown as Response);
			}
			// RDAP for the primary domain
			if (url.includes('rdap') && url.includes('/domain/test.com')) {
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(primaryRdap) } as unknown as Response);
			}

			// HEAD probe — reachable web content (fail-soft true)
			if (url.startsWith('https://') || url.startsWith('http://')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					headers: new Headers(),
					text: () => Promise.resolve(''),
					json: () => Promise.resolve({}),
				} as unknown as Response);
			}
			return Promise.resolve(createDohResponse([], []));
		});
	}

	it('downgrades a mail-infra lookalike to info when its RDAP registrant org matches the scan domain (the xero.co.nz case)', async () => {
		// Models a vendor whose regional subsidiary uses a different DNS provider
		// (so shared-NS misses it) but shares the registrant org in RDAP.
		mockSameEntity({
			lookalike: 'tst.com',
			lookalikeRdap: rdapWithRegistrant('<Vendor> Limited'),
			primaryRdap: rdapWithRegistrant('<Vendor> Limited'),
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		// F2 (2026-07-27 fix round 2): retitled from "likely owned by same
		// entity" — the structural verdict at this branch is always
		// third_party (RDAP registrant-org matching is deliberately NOT fed
		// into classifyOwnership()), so the title no longer claims ownership
		// outright, and the verdict now travels in metadata alongside it.
		expect(tstFinding!.title).toContain('shares registrant organisation');
		expect(tstFinding!.title).not.toContain('likely owned by same entity');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('third_party');
		expect(tstFinding!.detail).toContain('registrant organisation');
		expect(tstFinding!.detail).toContain('not structural ownership evidence');
		// `createFinding` now sanitizes metadata strings at the chokepoint (F7 / issue
		// #389): the `< >` in the placeholder org are neutralized to spaces. The match
		// logic itself runs pre-sanitize on the raw RDAP value, so the same-entity
		// downgrade is unaffected — only the emitted metadata is normalized.
		expect(tstFinding!.metadata?.sharedRegistrantOrg).toBe('vendor limited');
		// And it must NOT contribute to the HIGH summary.
		const summary = result.findings.find((f) => /mail capability detected/i.test(f.title));
		expect(summary).toBeUndefined();
	});

	// D4-capped: tst.com's NS ('ns1.other-dns.com.', deliberately distinct
	// from the primary's 'ns1.primary-dns.com.' per mockSameEntity) carries no
	// ownership signal — third_party — so even a genuine "Phishing Co"
	// registrant with a recent-registration HIGH calibration is capped at
	// info. This is the deliberately conservative D4 trade-off: the tool no
	// longer distinguishes a real phishing lookalike's threat tier in
	// `.severity` once ownership can't be established, but it is still
	// reported (never suppressed) with the calibration preserved in metadata.
	it('caps a real third-party phishing lookalike at info even when its RDAP registrant org differs (D4 ownership cap)', async () => {
		mockSameEntity({
			lookalike: 'tst.com',
			lookalikeRdap: rdapWithRegistrant('Phishing Co', 30), // recent reg + mail-infra → HIGH internally
			primaryRdap: rdapWithRegistrant('<Vendor> Limited'),
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('third_party');
		expect(tstFinding!.title).not.toContain('likely owned by same entity');
		expect(tstFinding!.metadata?.registrationDays).toBe(30);
	});

	it('caps at info when RDAP fails for the lookalike, never suppresses (fail-soft)', async () => {
		mockSameEntity({
			lookalike: 'tst.com',
			lookalikeRdap: { fail: true }, // RDAP unavailable → registrantOrg unknown
			primaryRdap: rdapWithRegistrant('<Vendor> Limited'),
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		// Mail-infra, no corroborator, RDAP age unknown → MEDIUM internally
		// (issue #264 default), but third_party → D4-capped at info. Present,
		// not suppressed, and not carrying the same-owner claim.
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('third_party');
		expect(tstFinding!.title).not.toContain('likely owned by same entity');
	});

	// D4 fixture repair: a SINGLE shared NS host (not flagged as a shared
	// provider) no longer clears classifyOwnership()'s rule-5 threshold
	// (>= 2 dedicated hosts) — that single-host coincidence is exactly the
	// naive threshold=1 bug this design closes. A second shared host is added
	// so the scenario is genuinely owned_by_seed, keeping this test's actual
	// subject (the cheap shared-NS path skips RDAP entirely) observable.
	it('detects a 2-host dedicated-NS same-entity lookalike WITHOUT issuing any RDAP fetch (cheap path preserved)', async () => {
		const sharedNs = ['ns1.shared-dns.com.', 'ns2.shared-dns.com.'];
		const rdapCalls: string[] = [];
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('rdap')) rdapCalls.push(url);
			if (url.includes('cloudflare-dns.com')) {
				const { name, type } = parseDohQuery(input);
				if (name === 'test.com' && (type === 'NS' || type === '2')) {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							sharedNs.map((d) => ({ name, type: 2, TTL: 300, data: d })),
						),
					);
				}
				if (name === 'tst.com') {
					if (type === 'NS' || type === '2') {
						return Promise.resolve(
							createDohResponse(
								[{ name, type: 2 }],
								sharedNs.map((d) => ({ name, type: 2, TTL: 300, data: d })),
							),
						);
					}
					if (type === 'MX' || type === '15') {
						return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.tst.com.' }]));
					}
					if (type === 'A' || type === '1') {
						return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
					}
				}
				return Promise.resolve(createDohResponse([], []));
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.title).toContain('likely owned by same entity');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('owned_by_seed');
		// The cheaper shared-NS path must short-circuit BEFORE any RDAP call.
		expect(rdapCalls.length).toBe(0);
	});

	it('matches the registrant org case-insensitively and whitespace-normalized', async () => {
		mockSameEntity({
			lookalike: 'tst.com',
			lookalikeRdap: rdapWithRegistrant('  XERO   LIMITED  '),
			primaryRdap: rdapWithRegistrant('xero limited'),
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.title).toContain('shares registrant organisation');
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('third_party');
		expect(tstFinding!.metadata?.sharedRegistrantOrg).toBe('xero limited');
	});

	// F2 pin (2026-07-27 fix round 2): the reviewer's exact defect — a
	// third_party structural verdict must not be titled as owned-by-same-
	// entity without the metadata saying so. Proves BOTH halves of the fix
	// together: the verdict travels in metadata, AND the title no longer
	// overclaims common ownership from an unverified RDAP org-name match
	// alone.
	it('F2: carries the third_party ownershipVerdict on the RDAP same-entity finding and does not title it as owned-by-same-entity', async () => {
		mockSameEntity({
			lookalike: 'tst.com',
			lookalikeRdap: rdapWithRegistrant('<Vendor> Limited'),
			primaryRdap: rdapWithRegistrant('<Vendor> Limited'),
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.metadata?.ownershipVerdict).toBe('third_party');
		expect(tstFinding!.metadata?.sharedRegistrantOrg).toBe('vendor limited');
		expect(tstFinding!.title).not.toContain('likely owned by same entity');
	});
});

describe('probeHasWebContent - SSRF redirect-follow guard (OWASP A10)', () => {
	afterEach(() => restore());

	/**
	 * The candidate lookalike host is attacker-influenced. An actor can serve a
	 * 302 → internal Cloudflare host. The probe must NOT auto-follow that
	 * redirect (which `redirect:'follow'` would, reaching the internal host),
	 * yet must still report the 3xx as reachable web content.
	 *
	 * The mock models the Workers runtime contract: redirect resolution happens
	 * BELOW the fetch surface, so `redirect:'follow'` is emulated by the mock
	 * resolving the Location target itself (recording the internal host as
	 * contacted); `redirect:'manual'` returns the 302 untouched. Branching on
	 * `init.redirect` is what makes this test discriminate buggy vs fixed.
	 */
	it('does not follow a candidate 302 to an internal host, but still reports reachable', async () => {
		const candidate = 'examp1e.com'; // public lookalike — passes validateOutboundUrl
		const internalHost = 'metadata.cloudflare.internal';
		const internalLocation = `https://${internalHost}/`;
		const contactedHosts: string[] = [];

		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
			contactedHosts.push(new URL(url).host);

			// The candidate serves a redirect toward an internal host.
			if (new URL(url).host === candidate) {
				const redirectResp = {
					ok: false,
					status: 302,
					headers: new Headers({ Location: internalLocation }),
				} as unknown as Response;

				// Emulate the runtime: 'follow' resolves the redirect below the
				// fetch surface, so the internal host IS contacted.
				if (init?.redirect === 'follow') {
					contactedHosts.push(new URL(internalLocation).host);
					return { ok: true, status: 200, headers: new Headers() } as unknown as Response;
				}
				// 'manual' (or default) returns the 302 untouched.
				return redirectResp;
			}

			// Any other host contacted = the redirect was followed by the code.
			return { ok: true, status: 200, headers: new Headers() } as unknown as Response;
		}) as unknown as typeof fetch;

		const { probeHasWebContent } = await import('../src/tools/check-lookalikes');
		const reachable = await probeHasWebContent(candidate);

		// (a) the internal Location host must never be contacted
		expect(contactedHosts).not.toContain(internalHost);
		// (b) a 3xx still proves reachability
		expect(reachable).toBe(true);
	});
});

describe('checkLookalikes - probeRdap routes through safeFetch (SSRF parity, P3 defense-in-depth)', () => {
	afterEach(() => {
		vi.restoreAllMocks();
		restore();
	});

	/**
	 * The RDAP host comes from the FALLBACK_RDAP_SERVERS map and is not statically
	 * trusted as a class (the sibling fetchRdapResponse path derives the same host
	 * from the network-sourced IANA bootstrap). probeRdap MUST route its fetch
	 * through safeFetch so validateOutboundUrl() re-validates the destination host
	 * (the SSRF gate), matching the reference path in check-rdap-lookup.ts. These
	 * tests assert (1) the RDAP probe goes through safeFetch, (2) a normal RDAP
	 * response still parses (legitimate path preserved), and (3) a blocked host
	 * (safeFetch throwing) degrades fail-soft and never throws out of the tool.
	 */
	function mockDohWithMailLookalike(mailDomain: string) {
		return (input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				const { name, type } = parseDohQuery(input);
				if (name === mailDomain) {
					if (type === 'NS' || type === '2') {
						return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
					}
					if (type === 'MX' || type === '15') {
						return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.example.com.' }]));
					}
					if (type === 'A' || type === '1') {
						return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
					}
				}
				return Promise.resolve(createDohResponse([], []));
			}
			// HEAD web-content probe — reachable (fail-soft true).
			return Promise.resolve({
				ok: true,
				status: 200,
				headers: new Headers(),
				text: () => Promise.resolve(''),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		};
	}

	it('routes the RDAP probe through safeFetch AND still parses a legitimate RDAP response', async () => {
		const safeFetchModule = await import('../src/lib/safe-fetch');
		const recentReg = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
		const rdapUrls: string[] = [];

		// Spy on the SSRF-validated path. Delegate to the real safeFetch for DoH +
		// HEAD; intercept the RDAP /domain/ request to return registration data.
		const realSafeFetch = safeFetchModule.safeFetch;
		const baseFetch = vi.fn(mockDohWithMailLookalike('tst.com'));
		globalThis.fetch = baseFetch as unknown as typeof fetch;

		const spy = vi.spyOn(safeFetchModule, 'safeFetch').mockImplementation(async (input, init) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
			if (url.includes('rdap') && url.includes('/domain/tst.com')) {
				rdapUrls.push(url);
				return {
					ok: true,
					status: 200,
					json: () => Promise.resolve({ events: [{ eventAction: 'registration', eventDate: recentReg }] }),
				} as unknown as Response;
			}
			return realSafeFetch(input, init);
		});

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com');

		// (1) the RDAP probe was issued through safeFetch (the SSRF-validated path)
		expect(spy).toHaveBeenCalled();
		expect(rdapUrls.length).toBeGreaterThan(0);
		// the validated URL is the hardcoded public RDAP host — proves it passes validateOutboundUrl
		expect(rdapUrls.some((u) => u.startsWith('https://rdap.verisign.com/'))).toBe(true);

		// (2) the legitimate RDAP response still parses → recent registration is
		// captured in metadata (registrationDays). Severity itself is D4-capped
		// at info: 'ns1.registrar.com.' carries no ownership signal
		// (third_party), so even the internally-HIGH calibration this recent
		// registration would produce is capped.
		const tstFinding = result.findings.find((f) => f.metadata?.lookalikeDomain === 'tst.com');
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.registrationDays).toBe(30);
	});

	it('degrades fail-soft (no throw, registration unknown) when safeFetch blocks the RDAP host', async () => {
		const safeFetchModule = await import('../src/lib/safe-fetch');
		const realSafeFetch = safeFetchModule.safeFetch;
		globalThis.fetch = vi.fn(mockDohWithMailLookalike('tst.com')) as unknown as typeof fetch;

		// Simulate an SSRF-blocked RDAP host: safeFetch throws (its native semantics).
		vi.spyOn(safeFetchModule, 'safeFetch').mockImplementation(async (input, init) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
			if (url.includes('rdap')) {
				throw new TypeError('Outbound fetch blocked: blocked host');
			}
			return realSafeFetch(input, init);
		});

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		// Must not throw out of the tool — the probe's try/catch absorbs the block.
		const result = await checkLookalikes('test.com');

		// Registration age is unknown (probe blocked) → mail-infra stays
		// MEDIUM-shaped internally, not HIGH — and third_party (no ownership
		// signal) caps the OUTPUT severity at info regardless.
		const tstFinding = result.findings.find((f) => f.metadata?.lookalikeDomain === 'tst.com');
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.metadata?.registrationDays).toBeNull();
	});
});

describe('checkLookalikes - D4 ownership-gated severity (2026-07-26 correctness-defects design)', () => {
	async function run(domain = 'example.com') {
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		return checkLookalikes(domain);
	}

	// CALL SITE 2 (main classification loop). Old sharesNameservers()/
	// SHARED_NS_THRESHOLD=1 fired on a SINGLE shared Akamai host and would
	// have relabelled this "likely owned by same entity" at info. Under
	// classifyOwnership(), a partial overlap confined to a shared-provider
	// host (a1-97.akam.net) is explicitly NOT ownership evidence (§3.3), so
	// the verdict is third_party. DEMOTE, NEVER DELETE: the finding must
	// still be present (a real measurement, never suppressed) but capped at
	// info with neutral wording — never the ownership-framed title.
	it('does not mark a lookalike as same-owner off a single shared Akamai NS host — demotes to info, never suppresses', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'testco.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 2 }],
						['a1-97.akam.net.', 'a3-67.akam.net.'].map((d) => ({ name, type: 2, TTL: 300, data: d })),
					),
				);
			}
			if (name === 'twstco.com') {
				if (type === 'NS' || type === '2') {
					// Shares exactly ONE Akamai host (a1-97) with the primary — the
					// old SHARED_NS_THRESHOLD=1 bug would call this "same owner".
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							['a1-97.akam.net.', 'a99-99.akam.net.'].map((d) => ({ name, type: 2, TTL: 300, data: d })),
						),
					);
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.example.com.' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});

		const result = await run('testco.com');
		const twstFindings = result.findings.filter((f) => f.detail.includes('twstco.com'));
		// DEMOTE, NEVER DELETE: a real, positively-probed candidate (has MX) is
		// always present in the output.
		expect(twstFindings.length).toBeGreaterThan(0);
		expect(twstFindings.some((f) => f.title.includes('likely owned by same entity'))).toBe(false);
		// Task 7b: the ATTRIBUTION axis is capped at info (D4 unchanged). The
		// mail-infra MEDIUM the calibrator assigns now rides the threat axis.
		expect(twstFindings.filter((f) => f.metadata?.findingAxis === 'attribution').every((f) => f.severity === 'info')).toBe(true);
		expect(twstFindings.filter((f) => f.metadata?.findingAxis === 'threat_observation').every((f) => f.severity === 'medium')).toBe(true);
		const gated = twstFindings.find((f) => f.metadata?.severityCappedBy !== undefined);
		expect(gated).toBeDefined();
		expect(gated!.metadata?.ownershipVerdict).toBe('third_party');
		expect(gated!.metadata?.severityCappedBy).toBe('ownership_attribution');
	});

	// CALL SITE 2 + the load-bearing safety property: severity gates on the
	// VERDICT alone, never on attributionConfidence/label length/
	// corroboration. Brand label here is 7 chars (>= MIN_ATTRIBUTION_LABEL_LENGTH)
	// AND the candidate's MX exchange overlaps the primary's — both signals
	// that would make attributionConfidence() return 'corroborated'. If
	// severity were (wrongly) gated on attributionConfidence instead of
	// capAttributionSeverity(verdict), a 'third_party' + 'corroborated'
	// candidate would be treated as unbounded and surface above info. It
	// must not: third_party is capped at info regardless of corroboration.
	it('caps a third_party verdict at info even with a long brand label AND MX-overlap corroboration (verdict-only gate)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'contoso.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.shared-mx.com.' }]));
				}
			}
			if (name === 'contos0.com') {
				if (type === 'NS' || type === '2') {
					// Completely distinct NS from the primary — no ownership signal.
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.attacker-dns.com.' }]));
				}
				if (type === 'MX' || type === '15') {
					// Same MX exchange as the primary — a genuine MX-overlap
					// corroboration signal, wired for WORDING only.
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.shared-mx.com.' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});

		const result = await run('contoso.com');
		const findings = result.findings.filter((f) => f.detail.includes('contos0.com'));
		expect(findings.length).toBeGreaterThan(0);
		// Task 7b: the verdict-only cap applies to the ATTRIBUTION axis. A long
		// brand label plus MX-overlap corroboration must still not lift the
		// attribution finding above info.
		expect(findings.filter((f) => f.metadata?.findingAxis === 'attribution').every((f) => f.severity === 'info')).toBe(true);
		const gated = findings.find((f) => f.metadata?.findingAxis === 'attribution' && f.metadata?.ownershipVerdict === 'third_party');
		expect(gated).toBeDefined();
		// Corroboration affects wording (confidence), never the ceiling.
		expect(gated!.metadata?.attributionConfidence).toBe('corroborated');
	});

	// CALL SITE 2 (the demoted rung must be neutrally worded, not just
	// numerically capped). A split-surface bug (severity right, title still
	// ownership-framed) is exactly what bit Task 6's first review pass.
	it('never uses ownership-implying prose ("owned", "your domain") for a non-owned candidate at the capped severity', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'testco.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]));
			}
			if (name === 'twstco.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.attacker-dns.com.' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.evil.com.' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});

		const result = await run('testco.com');
		const gated = result.findings.find((f) => f.metadata?.ownershipVerdict === 'third_party' && f.detail.includes('twstco.com'));
		expect(gated).toBeDefined();
		expect(gated!.severity).toBe('info');
		expect(gated!.title).not.toMatch(/owned by same entity/i);
		expect(gated!.detail).not.toMatch(/is owned by the same organisation/i);
	});

	// CALL SITE 1 (the enrichment gate) AND CALL SITE 2 together, on the
	// OPPOSITE direction from the Akamai test: an in-bailiwick NS delegation
	// is ownership evidence with ZERO literal hostname overlap against the
	// primary's own NS set, so the OLD sharesNameservers()/threshold=1 check
	// (exact-hostname set intersection) would see NO overlap and treat this
	// as a third party — while classifyOwnership() correctly recognises
	// in-bailiwick delegation as owned_by_seed. This is the discriminator for
	// call site 1: with the old code, this candidate would NOT be excluded
	// from enrichment (an RDAP fetch would fire); with the fix, ownership is
	// resolved from the NS verdict alone and RDAP is never consulted for an
	// owned candidate.
	//
	// F3(b) (2026-07-27 fix round 2): renamed from "...and leaves severity
	// unclamped" — that name overstated the assertions. The `sameOwner`
	// branch in check-lookalikes.ts (`:485`) hardcodes severity to `'info'`
	// unconditionally; there is no medium/high value it is ever "unclamped"
	// from. What this test actually discriminates is that an owned_by_seed
	// candidate keeps its NATIVE same-owner finding (title + rationale-based
	// detail) rather than being routed through the D4 gate's non-owned
	// demotion template (`buildNonOwnedGateFinding`) — pinned below via the
	// explicit `severity === 'info'` assertion plus the title/verdict checks.
	it('recognises in-bailiwick NS delegation as owned_by_seed with zero literal NS-hostname overlap, skips RDAP enrichment, and keeps the native same-owner info finding (not the D4 demotion template)', async () => {
		const rdapCalls: string[] = [];
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('rdap')) rdapCalls.push(url);
			const { name, type } = parseDohQuery(input);
			// Primary's own NS is a totally distinct hostname from the candidate's.
			if (name === 'bnz.co.nz' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns-cloud1.googledomains.com.' }]));
			}
			if (name === 'bnz.com') {
				if (type === 'NS' || type === '2') {
					// In-bailiwick to the seed apex bnz.co.nz — zero literal overlap
					// with the primary's own NS hostname above.
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.bnz.co.nz.' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.bnz.co.nz.' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});

		const result = await run('bnz.co.nz');
		const bnzComFindings = result.findings.filter((f) => f.detail.includes('bnz.com') || f.metadata?.lookalikeDomain === 'bnz.com');
		expect(bnzComFindings.length).toBeGreaterThan(0);
		expect(bnzComFindings.some((f) => f.title.includes('likely owned by same entity'))).toBe(true);
		expect(bnzComFindings.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(true);
		// F3(b) (2026-07-27 fix round 2): the assertion the `:1516` comment
		// promised but this test never actually made — pins the native
		// same-owner finding's hardcoded 'info' severity explicitly.
		expect(bnzComFindings.every((f) => f.severity === 'info')).toBe(true);
		// Call site 1: an owned candidate must never trigger the RDAP enrichment
		// probe (the old exact-hostname-overlap check would have missed the
		// in-bailiwick relationship and enriched it anyway).
		expect(rdapCalls.length).toBe(0);
	});

	// CALL SITE 3 (computeSameEntityCandidates' RDAP-eligibility filter). Seed
	// TLD is deliberately .com (FALLBACK_RDAP_SERVERS has an entry — unlike
	// .nz, used elsewhere in this block, which has none and would make a
	// "no primary RDAP fetch" assertion pass trivially regardless of gating).
	// The ONLY candidate with mail infrastructure in this scan is the
	// in-bailiwick owned combosquat 'mail-contoso.com'; if call site 3 is left
	// on the old exact-hostname-overlap check it would (wrongly) treat this
	// owned candidate as eligible for the same-entity RDAP correlation and
	// fetch the PRIMARY's own registrant org even though nothing needs
	// correlating — an unnecessary RDAP fetch this test catches directly by
	// asserting no RDAP call for the primary domain occurs.
	it('excludes an owned_by_seed candidate from the same-entity RDAP-eligibility set (no primary RDAP fetch)', async () => {
		const primaryRdapCalls: string[] = [];
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('rdap') && url.includes('/domain/contoso.com')) primaryRdapCalls.push(url);
			const { name, type } = parseDohQuery(input);
			if (name === 'contoso.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]));
			}
			// mail-contoso.com — a combosquat, delegated in-bailiwick to the seed
			// apex contoso.com — owned_by_seed with zero literal NS-hostname
			// overlap against the primary's own NS above.
			if (name === 'mail-contoso.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.contoso.com.' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.contoso.com.' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});

		await run('contoso.com');
		expect(primaryRdapCalls.length).toBe(0);
	});

	// D4 spec row for this tool, BOTH directions pinned together (a test that
	// proves only one direction does not discriminate): a short (3-char)
	// brand label with a third_party verdict and no corroboration is
	// demoted to the neutral info template (`buildNonOwnedGateFinding`),
	// while a short (3-char) brand label with an owned_by_seed verdict (NS in
	// bailiwick — the strongest corroborating signal by construction) keeps
	// its native same-owner info finding instead.
	//
	// F3(b) (2026-07-27 fix round 2): renamed from "...owned_by_seed short
	// label surfaces unclamped" — both directions are 'info' by construction
	// (calibrateLookalikeSeverity never runs for the sameOwner branch), so
	// "unclamped" never meant medium/high. What differs is WHICH template
	// produced the info finding — the demotion template (neutral wording, no
	// ownership title) vs. the native same-owner finding (ownership title,
	// rationale-based detail). Both severities are now pinned explicitly.
	it('D4 short-label pin: third-party short label demoted to the neutral info template; owned_by_seed short label keeps its native same-owner info finding', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'bnz.co.nz' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns-cloud1.googledomains.com.' }]));
			}
			// hnz.co.nz — a homoglyph of bnz.co.nz (b -> h), registered on its own
			// unrelated NS. Brand label 'bnz' is 3 chars, below
			// MIN_ATTRIBUTION_LABEL_LENGTH, and there is no MX overlap with the
			// primary — third_party, uncorroborated.
			if (name === 'hnz.co.nz') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(
						createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.unrelated-registrar.com.' }]),
					);
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.hnz.co.nz.' }]));
				}
			}
			// bnz.com — a TLD-swap variant delegated in-bailiwick to bnz.co.nz.
			// Same 3-char brand label, but owned_by_seed via NS in-bailiwick.
			if (name === 'bnz.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.bnz.co.nz.' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.bnz.co.nz.' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});

		const result = await run('bnz.co.nz');

		// third-party direction: hnz.co.nz present, capped at info, neutral title.
		const hnzFindings = result.findings.filter((f) => f.detail.includes('hnz.co.nz') || f.metadata?.lookalikeDomain === 'hnz.co.nz');
		expect(hnzFindings.length).toBeGreaterThan(0);
		// Task 7b: axis-scoped — attribution info, threat axis free to calibrate.
		expect(hnzFindings.filter((f) => f.metadata?.findingAxis === 'attribution').every((f) => f.severity === 'info')).toBe(true);
		expect(hnzFindings.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(true);
		expect(hnzFindings.some((f) => f.title.includes('likely owned by same entity'))).toBe(false);

		// owned_by_seed direction: bnz.com present, unclamped, ownership title.
		const bnzComFindings = result.findings.filter((f) => f.detail.includes('bnz.com') || f.metadata?.lookalikeDomain === 'bnz.com');
		expect(bnzComFindings.length).toBeGreaterThan(0);
		expect(bnzComFindings.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(true);
		expect(bnzComFindings.some((f) => f.title.includes('likely owned by same entity'))).toBe(true);
		// F3(b): the promised severity assertion — 'unclamped' does not mean
		// medium/high here (the sameOwner branch hardcodes 'info'); it means the
		// finding is NOT routed through the D4 demotion template. Pin the actual
		// contract explicitly rather than leaving it implied by the title check.
		expect(bnzComFindings.every((f) => f.severity === 'info')).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Task 7b (human-partner ruling 2026-07-27): the two axes are SPLIT.
//   Axis 1 — attribution confidence (WHO owns it): still capped at `info` with
//            neutral wording for every non-`owned_by_seed` verdict (D4).
//   Axis 2 — observed-threat severity (WHAT it is doing): a NEW finding at the
//            already-computed #264 calibrated severity, asserting nothing about
//            ownership and demanding nothing of the customer on that domain.
// Both axes are machine-discriminable via `metadata.findingAxis`.
// ---------------------------------------------------------------------------
describe('checkLookalikes - Task 7b two-axis split (attribution vs threat observation)', () => {
	async function run(domain = 'example.com') {
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		return checkLookalikes(domain);
	}

	/**
	 * The textbook pre-phishing setup the opus review proved Task 7 had made
	 * invisible: a confusable label on unrelated nameservers (third_party) with
	 * LIVE mail infrastructure on a disposable provider — the #264 matrix's HIGH
	 * tier. `mailgun.org` is in DISPOSABLE_MX_PROVIDERS, so the HIGH is reached
	 * without needing an RDAP registration-age mock.
	 */
	function mockPrePhishingFixture(): void {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'testco.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]));
			}
			if (name === 'twstco.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.unrelated-dns.com.' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mx.mailgun.org.' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
	}

	/**
	 * #779 — the summary finding's TITLE named a strictly wider predicate than
	 * its COUNT applied. It said "N lookalike domains with mail capability
	 * detected" while N counted only mail-infra PLUS a #264 corroborator.
	 *
	 * Measured on real estates before the fix: openclaw.ai's rollup said 2 while
	 * six candidates in the SAME response carried `hasMX: true`; openclaw.org
	 * said 1 against 3. A consumer reading only the summary — which is what a
	 * summary is for — got a three-fold undercount, and it propagated into a
	 * client-facing report.
	 */
	describe('#779 summary finding: title matches the predicate it counts', () => {
		it('does not claim "mail capability" for the corroborated-staging subset', async () => {
			mockPrePhishingFixture();
			const result = await run('testco.com');
			const summary = result.findings.find((f) => f.metadata?.lookalikeDomainCount !== undefined);
			expect(summary).toBeDefined();
			expect(
				summary!.title,
				'the title must not name a wider set than the count applies',
			).not.toMatch(/mail capability/i);
			expect(summary!.title).toMatch(/pre-phishing staging signals/i);
		});

		it('exposes the wider mail-capable count alongside, so nobody re-derives it', async () => {
			mockPrePhishingFixture();
			const result = await run('testco.com');
			const summary = result.findings.find((f) => f.metadata?.lookalikeDomainCount !== undefined);
			// Both numbers present. Forcing consumers to re-derive the wider figure
			// from per-domain findings is what nobody did, and why the undercount
			// went unnoticed.
			expect(summary!.metadata?.mailCapableCount).toBeDefined();
			expect(summary!.metadata?.mailCapableDomains).toContain('twstco.com');
			expect(summary!.metadata?.mailCapableCount as number).toBeGreaterThanOrEqual(
				summary!.metadata?.lookalikeDomainCount as number,
			);
		});

		it('a null-MX candidate is not counted as mail-capable', async () => {
			// RFC 7505 `0 .` is the explicit way a domain DECLINES mail. A naive
			// MX-record count reads it as capability — the opposite of its meaning.
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const { name, type } = parseDohQuery(input);
				if (name === 'testco.com' && (type === 'NS' || type === '2')) {
					return Promise.resolve(
						createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]),
					);
				}
				if (name === 'twstco.com') {
					if (type === 'NS' || type === '2') {
						return Promise.resolve(
							createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.unrelated-dns.com.' }]),
						);
					}
					if (type === 'MX' || type === '15') {
						return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '0 .' }]));
					}
				}
				return Promise.resolve(createDohResponse([], []));
			});
			const result = await run('testco.com');
			for (const f of result.findings) {
				expect(f.metadata?.mailCapableDomains ?? []).not.toContain('twstco.com');
			}
		});
	});

	/**
	 * #781 — repeat `force_refresh` runs returned different candidate SETS with
	 * nothing in the response saying so, while every finding claimed
	 * `confidence: "deterministic"`. Measured on openclaw.ai: 12, then 10, then
	 * 13 candidates minutes apart, three names appearing only in the third run.
	 *
	 * Cause: a REJECTED NS lookup in `filterByNsExistence` was treated as
	 * "unregistered" and dropped. That phase gates everything downstream, so one
	 * timed-out query removed a registered domain from the results entirely.
	 */
	describe('#781 enumeration coverage is reported, not silently dropped', () => {
		it('reports complete coverage when every lookup resolves', async () => {
			mockPrePhishingFixture();
			const result = await run('testco.com');
			const withEnum = result.findings.find((f) => f.metadata?.enumeration !== undefined);
			expect(withEnum).toBeDefined();
			const e = withEnum!.metadata!.enumeration as { complete: boolean; unresolvedCount: number };
			expect(e.complete).toBe(true);
			expect(e.unresolvedCount).toBe(0);
			// No partial-coverage warning when nothing was dropped.
			expect(result.findings.some((f) => /enumeration was incomplete/i.test(f.title))).toBe(false);
		});

		it('emits a partial-coverage finding, and stops claiming deterministic, when a lookup fails', async () => {
			// A rejected NS query is UNKNOWN, not "unregistered".
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const { name, type } = parseDohQuery(input);
				if (name === 'testco.com' && (type === 'NS' || type === '2')) {
					return Promise.resolve(
						createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]),
					);
				}
				if (name === 'twstco.com') {
					if (type === 'NS' || type === '2') {
						return Promise.resolve(
							createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.unrelated-dns.com.' }]),
						);
					}
					if (type === 'MX' || type === '15') {
						return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mx.mailgun.org.' }]));
					}
				}
				// Every other permutation's lookup FAILS rather than answering empty.
				return Promise.reject(new Error('DNS timeout'));
			});

			const result = await run('testco.com');
			const warning = result.findings.find((f) => /enumeration was incomplete/i.test(f.title));
			expect(warning, 'a consumer reading only findings must still learn the set is a sample').toBeDefined();
			expect(warning!.severity).toBe('info');
			expect(warning!.detail).toMatch(/observed examples, not a complete inventory/i);

			const e = warning!.metadata!.enumeration as { complete: boolean; unresolvedCount: number };
			expect(e.complete).toBe(false);
			expect(e.unresolvedCount).toBeGreaterThan(0);

			// Set-level claims must not still say "deterministic" about a set that
			// was not exhaustively enumerated.
			for (const f of result.findings) {
				if (f.metadata?.enumeration && (f.metadata.enumeration as { complete: boolean }).complete === false) {
					expect(f.metadata.confidence).not.toBe('deterministic');
				}
			}
		});

		it('per-domain findings stay deterministic — only the SET is uncertain', async () => {
			mockPrePhishingFixture();
			const result = await run('testco.com');
			const perDomain = result.findings.filter((f) => f.metadata?.lookalikeDomain !== undefined);
			expect(perDomain.length).toBeGreaterThan(0);
			for (const f of perDomain) {
				// Each row is a real measurement of a real domain; incomplete
				// enumeration says nothing about the rows that DID resolve.
				expect(f.metadata?.confidence).toBe('deterministic');
			}
		});
	});

	it('6(a) emits BOTH axes for a live third-party typosquat: attribution capped at info, threat at the calibrated HIGH', async () => {
		mockPrePhishingFixture();
		const result = await run('testco.com');

		const attribution = result.findings.filter(
			(f) => f.metadata?.findingAxis === 'attribution' && f.metadata?.lookalikeDomain === 'twstco.com',
		);
		expect(attribution.length).toBe(1);
		// Axis 1 unchanged — D4's safety property preserved verbatim.
		expect(attribution[0].severity).toBe('info');
		expect(attribution[0].metadata?.ownershipVerdict).toBe('third_party');
		expect(attribution[0].metadata?.severityCappedBy).toBe('ownership_attribution');

		// Axis 2 — the observed threat, at the severity the #264 matrix computed.
		const threat = result.findings.filter(
			(f) => f.metadata?.findingAxis === 'threat_observation' && f.metadata?.lookalikeDomain === 'twstco.com',
		);
		expect(threat.length).toBe(1);
		expect(threat[0].severity).toBe('high');
		// The verdict travels on EVERY classified finding — a consumer must be
		// able to read "high threat, NOT owned by the customer" off one object.
		expect(threat[0].metadata?.ownershipVerdict).toBe('third_party');
	});

	it('6(a) un-deadens scoring: the lookalikes category no longer scores 100/passed on a live typosquat', async () => {
		mockPrePhishingFixture();
		const result = await run('testco.com');
		expect(result.score).toBeLessThan(100);
		// A HIGH threat observation is a -25 penalty; the summary finding adds
		// another. Pin the direction, not a brittle exact number.
		expect(result.score).toBeLessThanOrEqual(75);
	});

	it('un-deadens the summary path: the previously-unreachable HIGH staging summary finding fires again', async () => {
		mockPrePhishingFixture();
		const result = await run('testco.com');
		// Retitled by #779: it used to say "with mail capability detected", a
		// strictly WIDER predicate than the mail-infra-PLUS-corroborator matrix it
		// actually counts. The count is unchanged; only the claim is now honest.
		const summary = result.findings.find((f) =>
			/lookalike domains? showing pre-phishing staging signals/i.test(f.title),
		);
		expect(summary).toBeDefined();
		expect(summary!.severity).toBe('high');
		expect(summary!.metadata?.findingAxis).toBe('threat_observation');
		expect(summary!.metadata?.lookalikeDomainCount).toBe(1);
	});

	it('3. the threat finding states what was OBSERVED and uses no ownership/control framing', async () => {
		mockPrePhishingFixture();
		const result = await run('testco.com');
		const threat = result.findings.find(
			(f) => f.metadata?.findingAxis === 'threat_observation' && f.metadata?.lookalikeDomain === 'twstco.com',
		);
		expect(threat).toBeDefined();
		// States the observation.
		expect(threat!.title).toMatch(/^Impersonation-shaped .*observed: twstco\.com$/);
		expect(threat!.detail).toMatch(/mail infrastructure/i);
		expect(threat!.detail).toMatch(/disposable MX provider/i);
		// Explicitly disclaims ownership, per the ruling.
		expect(threat!.detail).toMatch(/does not appear to belong to the scanned organisation/i);
		// Banned framing — title AND detail (a split surface where the prose
		// contradicts the axis marker is the failure mode this pins).
		for (const text of [threat!.title, threat!.detail]) {
			expect(text).not.toMatch(/\byour\b/i);
			expect(text).not.toMatch(/shadow domain/i);
			expect(text).not.toMatch(/\bowned by\b/i);
			expect(text).not.toMatch(/\bmalicious\b/i);
			expect(text).not.toMatch(/\battacker\b/i);
		}
	});

	it('6(b) a benign parked third-party lookalike (web only, no MX) yields NO high/medium threat finding', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'testco.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]));
			}
			if (name === 'twstco.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.unrelated-dns.com.' }]));
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('testco.com');
		expect(result.findings.some((f) => f.severity === 'high' || f.severity === 'medium')).toBe(false);
		const threat = result.findings.find(
			(f) => f.metadata?.findingAxis === 'threat_observation' && f.metadata?.lookalikeDomain === 'twstco.com',
		);
		expect(threat).toBeDefined();
		// Matrix LOW tier — web-only, no corroborator.
		expect(threat!.severity).toBe('low');
	});

	it('6(c) an owned_by_seed candidate gets NO threat-observation finding (a domain is not an impersonation threat to itself)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'bnz.co.nz' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns-cloud1.googledomains.com.' }]));
			}
			if (name === 'bnz.com') {
				if (type === 'NS' || type === '2') {
					// In-bailiwick to the seed apex — owned_by_seed.
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.bnz.co.nz.' }]));
				}
				if (type === 'MX' || type === '15') {
					// Live mail infra on a DISPOSABLE provider — the #264 HIGH tier.
					// If ownership were ignored on the threat axis this would surface
					// as a HIGH against the customer's own domain.
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mx.mailgun.org.' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('bnz.co.nz');
		const owned = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'bnz.com');
		expect(owned.length).toBe(1);
		expect(owned[0].metadata?.ownershipVerdict).toBe('owned_by_seed');
		expect(owned[0].metadata?.findingAxis).toBe('attribution');
		// No threat axis anywhere in this scan — including no HIGH summary.
		expect(result.findings.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(false);
		expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
	});

	it('2. every finding this tool emits carries a findingAxis marker with one of the three exact literals', async () => {
		mockPrePhishingFixture();
		const result = await run('testco.com');
		expect(result.findings.length).toBeGreaterThan(0);
		for (const finding of result.findings) {
			expect(['attribution', 'threat_observation', 'scan_status']).toContain(finding.metadata?.findingAxis);
		}
		// Both axes are actually represented (a non-discriminating "all axes are
		// 'attribution'" world would otherwise satisfy the loop above).
		expect(result.findings.some((f) => f.metadata?.findingAxis === 'attribution')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(true);
	});

	it('the scan-level "no active lookalikes" notice is tagged scan_status, not threat_observation', async () => {
		globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createDohResponse([], [])));
		const result = await run('test.com');
		const notice = result.findings.find((f) => /No active lookalike/i.test(f.title));
		expect(notice).toBeDefined();
		expect(notice!.metadata?.findingAxis).toBe('scan_status');
		expect(notice!.severity).toBe('info');
	});
});

// ---------------------------------------------------------------------------
// Task 7b FIX ROUND 1 (review findings F1/F2).
//   F1 — the issue #263 RDAP registrant-org match must NOT suppress the threat
//        axis, and every use of that match must be gated behind a
//        privacy-proxy / redaction filter (the string is free text the
//        registrant types, is unverified, and collides trivially).
//   F2 — a third axis literal, `scan_status`, plus the two invariants Task 8
//        will audit: scan_status findings are always `info`; threat_observation
//        findings never carry `owned_by_seed` and always name a domain.
// ---------------------------------------------------------------------------
describe('checkLookalikes - Task 7b fix round 1 (RDAP org gating + scan_status axis)', () => {
	async function run(domain = 'example.com') {
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		return checkLookalikes(domain);
	}

	/**
	 * The axis invariants Task 8's cross-cutting audit will key on. Applied to
	 * every fixture in this block, clean scans included — a check that only ever
	 * ran against candidate-bearing scans would pass vacuously on exactly the
	 * finding shapes (status notices with no domain in metadata) the invariants
	 * exist to keep off the threat axis.
	 */
	function assertAxisInvariants(findings: Awaited<ReturnType<typeof run>>['findings']): void {
		expect(findings.length).toBeGreaterThan(0);
		for (const finding of findings) {
			expect(['attribution', 'threat_observation', 'scan_status']).toContain(finding.metadata?.findingAxis);
			if (finding.metadata?.findingAxis === 'scan_status') {
				expect(finding.severity).toBe('info');
			}
			if (finding.metadata?.findingAxis === 'threat_observation') {
				// Never about a domain the scanned organisation owns.
				expect(finding.metadata?.ownershipVerdict).not.toBe('owned_by_seed');
				// Always names what it observed: a single candidate, the aggregate
				// candidate list, or (recon corroboration) the scanned domain.
				const named =
					finding.metadata?.lookalikeDomain ??
					(finding.metadata?.lookalikeDomains as string[] | undefined)?.[0] ??
					finding.metadata?.domain;
				expect(named).toBeTruthy();
			}
		}
	}

	/** RDAP payload with a registrant vCard `org` of the caller's choosing. */
	function rdapOrg(org: string) {
		return {
			events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 1500 * 86400_000).toISOString() }],
			entities: [
				{
					objectClassName: 'entity',
					roles: ['registrant'],
					vcardArray: [
						'vcard',
						[
							['version', {}, 'text', '4.0'],
							['org', {}, 'text', org],
						],
					],
				},
			],
		};
	}

	/**
	 * Seed `test.com` on its own NS; candidate `tst.com` on UNRELATED NS with
	 * live MX (third_party, #264 mail-infra-alone MEDIUM). Both domains' RDAP
	 * returns `org` — same string on both sides, so the #263 same-entity
	 * correlation fires whenever the string survives the redaction filter.
	 */
	function mockSharedOrg(org: string): void {
		const payload = rdapOrg(org);
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				const { name, type } = parseDohQuery(input);
				if (name === 'test.com' && (type === 'NS' || type === '2')) {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]));
				}
				if (name === 'tst.com') {
					if (type === 'NS' || type === '2') {
						return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.other-dns.com.' }]));
					}
					if (type === 'MX' || type === '15') {
						return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.example.com.' }]));
					}
				}
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('rdap')) {
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(payload) } as unknown as Response);
			}
			return Promise.resolve(createDohResponse([], []));
		});
	}

	/**
	 * F1(1) — a GENUINE shared registrant org still produces the #263
	 * observation, but it may no longer switch the threat axis off. An
	 * unverified string earns a sentence, not a severity discount.
	 */
	it('F1: a genuine shared registrant org keeps the #263 observation AND still emits the threat finding at the full calibrated severity', async () => {
		mockSharedOrg('Contoso Limited');
		const result = await run('test.com');

		const attribution = result.findings.filter(
			(f) => f.metadata?.findingAxis === 'attribution' && f.metadata?.lookalikeDomain === 'tst.com',
		);
		expect(attribution.length).toBe(1);
		expect(attribution[0].title).toMatch(/shares registrant organisation/i);
		expect(attribution[0].metadata?.sharedRegistrantOrg).toBe('contoso limited');
		expect(attribution[0].severity).toBe('info');

		const threat = result.findings.filter(
			(f) => f.metadata?.findingAxis === 'threat_observation' && f.metadata?.lookalikeDomain === 'tst.com',
		);
		expect(threat.length).toBe(1);
		// NOT tiered down for the org match — mail-infra-alone is MEDIUM.
		expect(threat[0].severity).toBe('medium');
		// The observation is noted in the detail, flagged as unverified.
		expect(threat[0].detail).toMatch(/registrant/i);
		expect(threat[0].detail).toMatch(/self-declared|unverified/i);
		expect(threat[0].metadata?.sharedRegistrantOrg).toBe('contoso limited');
		assertAxisInvariants(result.findings);
	});

	/**
	 * F1(2)/(3) — the ZERO-EFFORT collision. Both domains sit behind the same
	 * privacy service, so their normalised registrant strings are equal for
	 * reasons that carry no identity information at all. No same-entity
	 * observation may be produced, and the threat axis must be untouched.
	 */
	it.each(['REDACTED FOR PRIVACY', 'Domains By Proxy, LLC', 'Privacy service provided by Withheld for Privacy ehf', 'Whois Privacy Corp.'])(
		'F1: privacy-proxy collision (%s) produces NO same-entity observation and still emits the threat finding',
		async (org) => {
			mockSharedOrg(org);
			const result = await run('test.com');

			// No same-entity observation anywhere — neither the title nor the metadata.
			expect(result.findings.some((f) => /shares registrant organisation/i.test(f.title))).toBe(false);
			expect(result.findings.some((f) => f.metadata?.sharedRegistrantOrg !== undefined)).toBe(false);

			// The attribution finding falls back to the neutral D4 gate template.
			const attribution = result.findings.filter(
				(f) => f.metadata?.findingAxis === 'attribution' && f.metadata?.lookalikeDomain === 'tst.com',
			);
			expect(attribution.length).toBe(1);
			expect(attribution[0].severity).toBe('info');
			expect(attribution[0].metadata?.severityCappedBy).toBe('ownership_attribution');

			// The threat axis is unaffected by the collision.
			const threat = result.findings.filter(
				(f) => f.metadata?.findingAxis === 'threat_observation' && f.metadata?.lookalikeDomain === 'tst.com',
			);
			expect(threat.length).toBe(1);
			expect(threat[0].severity).toBe('medium');
			assertAxisInvariants(result.findings);
		},
	);

	/** F2 — the scan-status axis, and both Task 8 invariants, on a clean scan. */
	it('F2: a clean scan emits only scan_status findings, all at info', async () => {
		globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createDohResponse([], [])));
		const result = await run('test.com');
		// Invariants first: a mis-tagged status notice must be reported as the
		// invariant violation it is (a threat finding naming no domain), not
		// merely as "this scan isn't all scan_status".
		assertAxisInvariants(result.findings);
		expect(result.findings.length).toBeGreaterThan(0);
		expect(result.findings.every((f) => f.metadata?.findingAxis === 'scan_status')).toBe(true);
		expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
	});

	/**
	 * F2 — the two invariants Task 8's cross-cutting audit will key on, asserted
	 * on a scan that emits ALL THREE axes' shapes at once (per-candidate
	 * attribution + per-candidate threat + the aggregate HIGH summary).
	 */
	it('F2: axis invariants — scan_status is always info; threat_observation never carries owned_by_seed and always names a domain', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'testco.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]));
			}
			if (name === 'twstco.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.unrelated-dns.com.' }]));
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mx.mailgun.org.' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('testco.com');

		const axes = result.findings.map((f) => f.metadata?.findingAxis);
		expect(axes.every((a) => a === 'attribution' || a === 'threat_observation' || a === 'scan_status')).toBe(true);
		// The fixture really does exercise both non-status axes, including the
		// aggregate summary (which names no single candidate) — otherwise the
		// invariant loops below would pass vacuously.
		expect(axes.filter((a) => a === 'attribution').length).toBe(1);
		expect(axes.filter((a) => a === 'threat_observation').length).toBe(2);

		assertAxisInvariants(result.findings);

		// The aggregate summary specifically: it names the counted candidates and
		// declares their (non-owned) verdict rather than leaving both blank.
		const summary = result.findings.find((f) => /showing pre-phishing staging signals/i.test(f.title));
		expect(summary).toBeDefined();
		expect(summary!.metadata?.lookalikeDomains).toEqual(['twstco.com']);
		expect(summary!.metadata?.ownershipVerdict).toBe('third_party');
	});
});

// ---------------------------------------------------------------------------
// Task 7b FIX ROUND 2 — residual: the both-sides redaction gate was UNPINNED.
//
// The re-reviewer mutated `isSameEntityOrgMatch` to check `isRedactedRegistrantOrg`
// on the CANDIDATE side only and the whole suite stayed green. Analysis, confirmed
// by re-running that mutation: NO fixture can discriminate. The final comparison is
// strict equality (`primaryOrg === candidateOrg`), and `isRedactedRegistrantOrg` is a
// pure function of its string, so whenever the two orgs are equal the predicate
// returns the SAME verdict for both — a one-sided check is currently EXACTLY
// equivalent to a two-sided one. For a one-sided check to wrongly match, the two
// strings would have to differ in redaction status while still being equal, which is
// impossible under equality matching.
//
// The correct pins are therefore semantic rather than fixture-based:
//   (a) these direct unit tests on `isSameEntityOrgMatch` (exported for the purpose),
//       which DO die when the redaction gate is removed altogether; and
//   (b) the equality-matching invariant recorded on the function's JSDoc, obliging any
//       future fuzzy/containment matcher to re-establish both-sides gating WITH a
//       discriminating test — at which point a fixture becomes constructible.
// ---------------------------------------------------------------------------
describe('isSameEntityOrgMatch - fix round 2 residual (direct semantic pin)', () => {
	async function load() {
		const [{ isSameEntityOrgMatch }, { isRedactedRegistrantOrg }] = await Promise.all([
			import('../src/tools/check-lookalikes'),
			import('../src/tools/check-rdap-lookup'),
		]);
		return { isSameEntityOrgMatch, isRedactedRegistrantOrg };
	}

	it('rejects an IDENTICAL redacted string on both sides (the privacy-proxy collision, pinned at the predicate)', async () => {
		const { isSameEntityOrgMatch } = await load();
		expect(isSameEntityOrgMatch('redacted for privacy', 'redacted for privacy')).toBe(false);
		expect(isSameEntityOrgMatch('domains by proxy, llc', 'domains by proxy, llc')).toBe(false);
		expect(
			isSameEntityOrgMatch('privacy service provided by withheld for privacy ehf', 'privacy service provided by withheld for privacy ehf'),
		).toBe(false);
	});

	it('accepts an identical GENUINE org string — the gate suppresses redaction, not correlation', async () => {
		const { isSameEntityOrgMatch } = await load();
		expect(isSameEntityOrgMatch('contoso limited', 'contoso limited')).toBe(true);
	});

	it('rejects a null on either side, and rejects two different genuine orgs', async () => {
		const { isSameEntityOrgMatch } = await load();
		expect(isSameEntityOrgMatch(null, 'contoso limited')).toBe(false);
		expect(isSameEntityOrgMatch('contoso limited', null)).toBe(false);
		expect(isSameEntityOrgMatch(null, null)).toBe(false);
		expect(isSameEntityOrgMatch('contoso limited', 'fabrikam limited')).toBe(false);
	});

	/**
	 * THE invariant that makes a one-sided check equivalent TODAY, asserted rather
	 * than assumed. If a future change makes matching fuzzy (containment, token
	 * overlap, edit distance), this test keeps passing while the equivalence it
	 * documents silently stops holding — which is exactly why the JSDoc on
	 * `isSameEntityOrgMatch` obliges that change to re-establish both-sides gating
	 * with its own discriminating fixture.
	 */
	it('equality invariant: for any org string, a self-match is allowed iff the string is not redacted', async () => {
		const { isSameEntityOrgMatch, isRedactedRegistrantOrg } = await load();
		const corpus = [
			'contoso limited',
			'fabrikam nz limited',
			'redacted for privacy',
			'domains by proxy, llc',
			'whois privacy corp.',
			'withheld for privacy ehf',
			'gdpr masked',
			'n/a',
			'unknown',
			'private',
			'',
		];
		// The corpus must exercise BOTH outcomes, else the biconditional below is
		// satisfiable by a predicate that always returns one value.
		expect(corpus.some((org) => isRedactedRegistrantOrg(org))).toBe(true);
		expect(corpus.some((org) => !isRedactedRegistrantOrg(org))).toBe(true);
		for (const org of corpus) {
			expect(isSameEntityOrgMatch(org, org)).toBe(!isRedactedRegistrantOrg(org));
		}
	});

	// #853 — the seed NS lookup gates EVERY ownership verdict: when it fails,
	// all candidates degrade to `unmeasured` and impersonation-shaped findings
	// are withheld wholesale. It was issued with PHASE1_DNS_OPTS (retries: 0,
	// timeoutMs: 2000) inside the SAME Promise.all as the 66-permutation
	// fan-out, so it competed with its own burst for resolver budget and had
	// no retry to survive losing. Measured against the live resolver on
	// 2026-08-31: meta.com reported `seedNsUnresolved: true` on 2/2 idle runs
	// while a standalone DoH NS query for meta.com returned 4 answers.
	// The seed must survive ONE transient failure; the fan-out may not need to.
	it('retries the seed NS lookup so one transient failure does not void every ownership verdict (#853)', async () => {
		let seedNsAttempts = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			const isNs = type === 'NS' || type === '2';

			// The scanned domain's own NS query: fail once, then succeed.
			if (name === 'test.com' && isNs) {
				seedNsAttempts += 1;
				if (seedNsAttempts === 1) return Promise.reject(new Error('transient resolver throttle'));
				return Promise.resolve(
					createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.seedowner.com.' }]),
				);
			}

			// One registered candidate sharing the seed's nameservers — it can
			// only be attributed if the seed NS resolved.
			if (name === 'tes.com') {
				if (isNs) {
					return Promise.resolve(
						createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.seedowner.com.' }]),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com');

		// The seed was retried rather than abandoned on first failure.
		expect(seedNsAttempts).toBeGreaterThan(1);

		// No wholesale "attribution unmeasured this run" summary finding.
		const seedFailure = result.findings.find((f) => f.metadata?.seedNsUnresolved === true);
		expect(seedFailure).toBeUndefined();

		// And no candidate was degraded to `unmeasured` by a seed failure.
		const unmeasured = result.findings.filter((f) => f.metadata?.ownershipVerdict === 'unmeasured');
		expect(unmeasured).toHaveLength(0);
		const attributedCandidate = result.findings.find((f) => f.metadata?.lookalikeDomain === 'tes.com');
		expect(attributedCandidate).toBeDefined();
		expect(attributedCandidate?.metadata?.ownershipVerdict).not.toBe('unmeasured');
	});

});
