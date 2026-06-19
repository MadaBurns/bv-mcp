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

	it('should return medium finding for lookalike with mail-infra but no corroborator (issue #264 matrix)', async () => {
		// Updated for issue #264: mail-infra alone is MEDIUM, not HIGH.
		// HIGH requires a corroborator (recent registration, disposable MX, or no web content).
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
		const mediumFindings = result.findings.filter((f) => f.severity === 'medium');
		expect(mediumFindings.length).toBeGreaterThan(0);
		const mxFinding = mediumFindings.find((f) => /mail infrastructure/i.test(f.title));
		expect(mxFinding).toBeDefined();
		// And no HIGH should be emitted (no corroborating signal)
		const highFindings = result.findings.filter((f) => f.severity === 'high');
		expect(highFindings.length).toBe(0);
	});

	it('should return low finding for lookalike with A but no MX (web-only, no corroborator)', async () => {
		// Updated for issue #264: web-only lookalikes default to LOW.
		// MEDIUM is reserved for web-only + recent registration (<90d).
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
		const lowFindings = result.findings.filter((f) => f.severity === 'low');
		expect(lowFindings.length).toBeGreaterThan(0);
		const registeredFinding = lowFindings.find((f) => /Lookalike domain registered/i.test(f.title));
		expect(registeredFinding).toBeDefined();
	});

	it('surfaces a registered combosquat (brand + lure affix) that edit-distance generation misses', async () => {
		// `paypal-login.com` is a combosquat of `paypal.com`: generateLookalikes
		// (edit-distance mutators) never produces it — generateCombosquats does.
		// Give it mail infrastructure so it surfaces at MEDIUM per the #264 matrix,
		// proving Part 3 generation feeds the same severity pipeline.
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
		const surfaced = result.findings.filter((f) => f.severity === 'medium' || f.severity === 'high');
		expect(surfaced.length).toBeGreaterThan(0);
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
		expect(tstFinding!.severity).toBe('low');
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

		// Should NOT have any high findings (null MX is not real mail infra)
		const mxFindings = result.findings.filter((f) => /mail infrastructure/i.test(f.title));
		expect(mxFindings.length).toBe(0);

		// Should have low findings (A record present, but no real MX → web-only LOW under #264)
		const lowFindings = result.findings.filter((f) => f.severity === 'low');
		expect(lowFindings.length).toBeGreaterThan(0);
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
		const mxFindings = result.findings.filter((f) => /mail infrastructure/i.test(f.title));
		expect(mxFindings.length).toBe(0);
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

		// testt.com has real MX but no corroborating signal → MEDIUM under #264 matrix
		const testtMedium = result.findings.find((f) => f.severity === 'medium' && f.title.includes('testt.com'));
		expect(testtMedium).toBeDefined();

		// tes.com has only A record (web-only, no MX) — LOW under #264 matrix.
		// (Previously MEDIUM; the calibrator now reserves MEDIUM for web-only + recent registration.)
		const tesLow = result.findings.find((f) => f.severity === 'low' && f.title.includes('tes.com'));
		expect(tesLow).toBeDefined();

		// Neither should be HIGH
		const tesHigh = result.findings.find((f) => f.severity === 'high' && f.title.includes('tes.com'));
		expect(tesHigh).toBeUndefined();
		const testtHigh = result.findings.find((f) => f.severity === 'high' && f.title.includes('testt.com'));
		expect(testtHigh).toBeUndefined();
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
		expect(teStFinding!.severity).toBe('low'); // web-only baseline (#264)
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
		expect(tstFinding!.severity).toBe('low'); // web-only baseline (#264)
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

		// tst.com should be info (shared NS = likely same owner), NOT high
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');
		expect(tstFinding!.title).toContain('likely owned by same entity');
		expect(tstFinding!.detail).toContain('shares nameservers');
		expect(tstFinding!.detail).toContain('mail infrastructure');
		expect(tstFinding!.metadata?.sharedNs).toBe(true);

		// Should NOT appear in the high count summary
		const highSummary = result.findings.find((f) => /mail capability detected/i.test(f.title));
		expect(highSummary).toBeUndefined();
	});

	it('should keep high severity when lookalike has different nameservers', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Primary domain NS
			if (name === 'test.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.cloudflare.com.' }]));
			}

			// tst.com has DIFFERENT nameservers + MX → should remain HIGH
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
		// MX present but no corroborator → MEDIUM under issue #264 matrix.
		expect(tstFinding!.severity).toBe('medium');
		expect(tstFinding!.title).toContain('mail infrastructure');
	});

	it('should downgrade medium to info when lookalike with A record shares NS', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Primary domain NS
			if (name === 'test.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.example-dns.com.' }]));
			}

			// tst.com shares NS, has A record but no MX
			if (name === 'tst.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.example-dns.com.' }]));
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
	});

	it('should handle NS comparison case-insensitively and strip trailing dots', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Primary domain NS with trailing dot and mixed case
			if (name === 'test.com' && (type === 'NS' || type === '2')) {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'NS1.CloudFlare.COM.' }]));
			}

			// tst.com has same NS but different casing/trailing dot
			if (name === 'tst.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.cloudflare.com' }]));
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

		// Primary NS unknown (empty set — can't compare). Mail-infra present without
		// corroborator → MEDIUM under issue #264 matrix. The shared-NS gate is
		// independent of the severity calibration.
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('medium');
		// And must NOT be downgraded to info (no shared NS detected)
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

		// tst.com should be info (shared NS)
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('info');

		// testt.com has different NS + MX but no corroborator → MEDIUM under #264 matrix
		// (was HIGH under the old "any MX → high" rule).
		const testtFinding = result.findings.find((f) => f.severity === 'medium' && f.title.includes('testt.com'));
		expect(testtFinding).toBeDefined();

		// No HIGH summary fires because no lookalike scored HIGH under the new matrix.
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
	function mockWithRdap(opts: {
		mailDomain: string;
		mxExchange?: string;
		registrationDaysAgo?: number | null;
		hasWebContent?: boolean;
	}) {
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
				return Promise.resolve({ ok: true, status: 200, headers: new Headers(), text: () => Promise.resolve(''), json: () => Promise.resolve({}) } as unknown as Response);
			}

			return Promise.resolve(createDohResponse([], []));
		});
	}

	it('elevates mail-infra + recent registration to HIGH', async () => {
		mockWithRdap({ mailDomain: 'tst.com', registrationDaysAgo: 30 });
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com') && /mail infrastructure/i.test(f.title));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('high');
	});

	it('keeps mail-infra at MEDIUM when registration is old (≥90d)', async () => {
		mockWithRdap({ mailDomain: 'tst.com', registrationDaysAgo: 1500 });
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com') && /mail infrastructure/i.test(f.title));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('medium');
	});

	it('elevates mail-infra + disposable MX to HIGH', async () => {
		mockWithRdap({ mailDomain: 'tst.com', mxExchange: 'smtp.mailgun.org.', registrationDaysAgo: null });
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com') && /mail infrastructure/i.test(f.title));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('high');
	});

	it('elevates mail-infra + no web content (parked/refused) to HIGH', async () => {
		mockWithRdap({ mailDomain: 'tst.com', registrationDaysAgo: null, hasWebContent: false });
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com') && /mail infrastructure/i.test(f.title));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('high');
	});

	it('elevates web-only + recent registration to MEDIUM', async () => {
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
				return Promise.resolve({ ok: true, status: 200, headers: new Headers(), text: () => Promise.resolve(''), json: () => Promise.resolve({}) } as unknown as Response);
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('medium');
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
							vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['org', {}, 'text', org]]],
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
				return Promise.resolve({ ok: true, status: 200, headers: new Headers(), text: () => Promise.resolve(''), json: () => Promise.resolve({}) } as unknown as Response);
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
		expect(tstFinding!.title).toContain('likely owned by same entity');
		expect(tstFinding!.detail).toContain('registrant organisation');
		// `createFinding` now sanitizes metadata strings at the chokepoint (F7 / issue
		// #389): the `< >` in the placeholder org are neutralized to spaces. The match
		// logic itself runs pre-sanitize on the raw RDAP value, so the same-entity
		// downgrade is unaffected — only the emitted metadata is normalized.
		expect(tstFinding!.metadata?.sharedRegistrantOrg).toBe('vendor limited');
		// And it must NOT contribute to the HIGH summary.
		const summary = result.findings.find((f) => /mail capability detected/i.test(f.title));
		expect(summary).toBeUndefined();
	});

	it('keeps the calibrated threat severity when the registrant org differs (real third-party lookalike preserved)', async () => {
		mockSameEntity({
			lookalike: 'tst.com',
			lookalikeRdap: rdapWithRegistrant('Phishing Co', 30), // recent reg + mail-infra → HIGH
			primaryRdap: rdapWithRegistrant('<Vendor> Limited'),
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('high');
		expect(tstFinding!.title).not.toContain('likely owned by same entity');
		expect(tstFinding!.title).toContain('mail infrastructure');
	});

	it('falls back to the threat severity when RDAP fails for the lookalike (fail-soft, never suppresses)', async () => {
		mockSameEntity({
			lookalike: 'tst.com',
			lookalikeRdap: { fail: true }, // RDAP unavailable → registrantOrg unknown
			primaryRdap: rdapWithRegistrant('<Vendor> Limited'),
		});
		const result = await run('test.com');
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		// Mail-infra, no corroborator, RDAP age unknown → MEDIUM (issue #264 default). NOT downgraded to info.
		expect(tstFinding!.severity).toBe('medium');
		expect(tstFinding!.title).not.toContain('likely owned by same entity');
	});

	it('detects a shared-NS same-entity lookalike WITHOUT issuing any RDAP fetch (cheap path preserved)', async () => {
		const sharedNs = 'ns1.shared-dns.com.';
		const rdapCalls: string[] = [];
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('rdap')) rdapCalls.push(url);
			if (url.includes('cloudflare-dns.com')) {
				const { name, type } = parseDohQuery(input);
				if (name === 'test.com' && (type === 'NS' || type === '2')) {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: sharedNs }]));
				}
				if (name === 'tst.com') {
					if (type === 'NS' || type === '2') {
						return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: sharedNs }]));
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
		expect(tstFinding!.detail).toContain('shares nameservers');
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
		expect(tstFinding!.title).toContain('likely owned by same entity');
		expect(tstFinding!.metadata?.sharedRegistrantOrg).toBe('xero limited');
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
			return Promise.resolve({ ok: true, status: 200, headers: new Headers(), text: () => Promise.resolve(''), json: () => Promise.resolve({}) } as unknown as Response);
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

		// (2) the legitimate RDAP response still parses → recent registration elevates to HIGH
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com') && /mail infrastructure/i.test(f.title));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('high');
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

		// Registration age is unknown (probe blocked) → mail-infra stays MEDIUM, not HIGH.
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com') && /mail infrastructure/i.test(f.title));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('medium');
	});
});
