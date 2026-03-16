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

	it('should return high finding for lookalike with MX records', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// Make one specific lookalike have MX records
			if (name === 'twst.com' || name === 'tst.com' || name === 'tes.com' || name === 'testt.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							[{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }],
						),
					);
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 15 }],
							[{ name, type: 15, TTL: 300, data: '10 mail.example.com.' }],
						),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 1 }],
							[{ name, type: 1, TTL: 300, data: '1.2.3.4' }],
						),
					);
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');
		const highFindings = result.findings.filter((f) => f.severity === 'high');
		expect(highFindings.length).toBeGreaterThan(0);
		const mxFinding = highFindings.find((f) => /mail infrastructure/i.test(f.title));
		expect(mxFinding).toBeDefined();
	});

	it('should return medium finding for lookalike with A but no MX', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// One lookalike with A record but no MX
			if (name === 'tst.com' || name === 'tes.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							[{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }],
						),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 1 }],
							[{ name, type: 1, TTL: 300, data: '1.2.3.4' }],
						),
					);
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');
		const mediumFindings = result.findings.filter((f) => f.severity === 'medium');
		expect(mediumFindings.length).toBeGreaterThan(0);
		const registeredFinding = mediumFindings.find((f) => /Lookalike domain registered/i.test(f.title));
		expect(registeredFinding).toBeDefined();
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
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							[{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }],
						),
					);
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 15 }],
							[{ name, type: 15, TTL: 300, data: '0 .' }],
						),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 1 }],
							[{ name, type: 1, TTL: 300, data: '1.2.3.4' }],
						),
					);
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');

		// Should NOT have any high findings (null MX is not real mail infra)
		const mxFindings = result.findings.filter((f) => /mail infrastructure/i.test(f.title));
		expect(mxFindings.length).toBe(0);

		// Should have medium findings (A record present, but no real MX)
		const mediumFindings = result.findings.filter((f) => f.severity === 'medium');
		expect(mediumFindings.length).toBeGreaterThan(0);
	});

	it('should flag real MX but ignore null MX in mixed responses', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			if (name === 'testt.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							[{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }],
						),
					);
				}
				// This domain has a real MX record → HIGH
				if (type === 'MX' || type === '15') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 15 }],
							[{ name, type: 15, TTL: 300, data: '10 mail.testt.com.' }],
						),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 1 }],
							[{ name, type: 1, TTL: 300, data: '1.2.3.4' }],
						),
					);
				}
			}
			if (name === 'tes.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							[{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }],
						),
					);
				}
				// This domain has null MX → should NOT be flagged as HIGH
				if (type === 'MX' || type === '15') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 15 }],
							[{ name, type: 15, TTL: 300, data: '0 .' }],
						),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 1 }],
							[{ name, type: 1, TTL: 300, data: '2.3.4.5' }],
						),
					);
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await run('test.com');

		// testt.com should produce a HIGH finding (real MX)
		const testtHigh = result.findings.find(
			(f) => f.severity === 'high' && f.title.includes('testt.com'),
		);
		expect(testtHigh).toBeDefined();

		// tes.com should produce a MEDIUM finding (A record, no real MX)
		const tesMedium = result.findings.find(
			(f) => f.severity === 'medium' && f.title.includes('tes.com'),
		);
		expect(tesMedium).toBeDefined();

		// tes.com should NOT produce a HIGH finding
		const tesHigh = result.findings.find(
			(f) => f.severity === 'high' && f.title.includes('tes.com'),
		);
		expect(tesHigh).toBeUndefined();
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
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 1 }],
							[{ name, type: 1, TTL: 300, data: '1.2.3.4' }],
						),
					);
				}
				if (type === 'MX' || type === '15') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 15 }],
							[{ name, type: 15, TTL: 300, data: '10 mail.parked.com.' }],
						),
					);
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
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							[{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }],
						),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 1 }],
							[{ name, type: 1, TTL: 300, data: '5.6.7.8' }],
						),
					);
				}
			}
			// Everything else (including canary probes) returns empty
			return Promise.resolve(createDohResponse([], []));
		});

		const { result } = await run('test.com');

		// te.st.com should remain because st.com has no wildcard
		const teStFinding = result.findings.find((f) => f.title.includes('te.st.com'));
		expect(teStFinding).toBeDefined();
		expect(teStFinding!.severity).toBe('medium');
	});

	it('should not affect non-dot-insertion permutations regardless of wildcard', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);

			// tst.com (character omission, not dot-insertion) resolves
			if (name === 'tst.com') {
				if (type === 'NS' || type === '2') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 2 }],
							[{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }],
						),
					);
				}
				if (type === 'A' || type === '1') {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 1 }],
							[{ name, type: 1, TTL: 300, data: '9.8.7.6' }],
						),
					);
				}
			}
			return Promise.resolve(createDohResponse([], []));
		});

		const { result } = await run('test.com');

		// tst.com is a same-label-count permutation (char omission), not dot-insertion — should be kept
		const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
		expect(tstFinding).toBeDefined();
		expect(tstFinding!.severity).toBe('medium');
	});

	it('exports WILDCARD_CANARY_LABEL constant', async () => {
		const { WILDCARD_CANARY_LABEL } = await import('../src/tools/check-lookalikes');
		expect(WILDCARD_CANARY_LABEL).toBe('_bv-wc-probe');
	});
});
