import { vi } from 'vitest';

let savedFetch: typeof globalThis.fetch;

/**
 * Saves `globalThis.fetch` and returns a `restore()` function.
 * Call at module scope or in `beforeEach`; call `restore()` in `afterEach`.
 */
export function setupFetchMock() {
	savedFetch = globalThis.fetch;
	return {
		restore() {
			globalThis.fetch = savedFetch;
		},
	};
}

interface DohResponseOptions {
	ad?: boolean;
}

/**
 * Builds a full DoH JSON response object with boilerplate fields.
 * Returns a mock `Response` that resolves to the JSON.
 */
export function createDohResponse(
	question: Array<{ name: string; type: number }>,
	answers: Array<{ name: string; type: number; TTL: number; data: string }>,
	options?: DohResponseOptions,
) {
	const json = {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: options?.ad ?? false,
		CD: false,
		Question: question,
		Answer: answers,
	};
	return {
		ok: true,
		status: 200,
		json: () => Promise.resolve(json),
	} as unknown as Response;
}

/**
 * Sets `globalThis.fetch` to return a DoH response with TXT answers.
 * Used by check-spf and check-dmarc tests.
 */
export function mockTxtRecords(records: string[], domain = 'example.com') {
	const answers = records.map((data) => ({
		name: domain,
		type: 16, // TXT
		TTL: 300,
		data: `"${data}"`,
	}));
	globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: domain, type: 16 }], answers));
}

/**
 * Generic mock for any JSON response. Used by dns.spec.ts.
 */
export function mockFetchResponse(response: object, ok = true, status = 200) {
	globalThis.fetch = vi.fn().mockResolvedValue({
		ok,
		status,
		json: () => Promise.resolve(response),
	} as unknown as Response);
}

/**
 * Sets `globalThis.fetch` to reject. Used by dns.spec.ts and check-dnssec.spec.ts.
 */
export function mockFetchError(error?: Error) {
	globalThis.fetch = vi.fn().mockRejectedValue(error ?? new Error('Network error'));
}

// ---------------------------------------------------------------------------
// Convenience response builders (shared across scan-domain and handler tests)
// ---------------------------------------------------------------------------

/** Build a DoH response containing TXT records for a domain. */
export function txtResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 16 }],
		records.map((data) => ({ name: domain, type: 16, TTL: 300, data: `"${data}"` })),
	);
}

/** Build a DoH response containing NS records for a domain. */
export function nsResponse(domain: string, nameservers: string[]) {
	return createDohResponse(
		[{ name: domain, type: 2 }],
		nameservers.map((data) => ({ name: domain, type: 2, TTL: 300, data })),
	);
}

/** Build a DoH response containing CAA records for a domain. */
export function caaResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 257 }],
		records.map((data) => ({ name: domain, type: 257, TTL: 300, data })),
	);
}

/** Build a DoH response for a DNSSEC check (A record with AD flag). */
export function dnssecResponse(domain: string, ad: boolean) {
	return createDohResponse([{ name: domain, type: 1 }], [{ name: domain, type: 1, TTL: 300, data: '1.2.3.4' }], {
		ad,
	});
}

/** Build a DoH response containing TLSA records for a name. */
export function tlsaResponse(
	name: string,
	records: Array<{ usage: number; selector: number; matchingType: number; certData: string }>,
) {
	return createDohResponse(
		[{ name, type: 52 }],
		records.map((r) => ({ name, type: 52, TTL: 300, data: `${r.usage} ${r.selector} ${r.matchingType} ${r.certData}` })),
	);
}

/** Build a DoH response containing PTR records for an IP (reverse DNS). */
export function ptrResponse(ip: string, hostnames: string[]) {
	const reverseName = ip.split('.').reverse().join('.') + '.in-addr.arpa';
	return createDohResponse(
		[{ name: reverseName, type: 12 }],
		hostnames.map((h) => ({ name: reverseName, type: 12, TTL: 300, data: `${h}.` })),
	);
}

/** Build a DoH response containing SRV records for a name. */
export function srvResponse(
	name: string,
	records: Array<{ priority: number; weight: number; port: number; target: string }>,
) {
	return createDohResponse(
		[{ name, type: 33 }],
		records.map((r) => ({ name, type: 33, TTL: 300, data: `${r.priority} ${r.weight} ${r.port} ${r.target}.` })),
	);
}

/** Build a mock HTTP Response with text body, status, and optional headers. */
export function httpResponse(body: string, status = 200, headers?: Headers) {
	return {
		ok: status >= 200 && status < 300,
		status,
		headers: headers ?? new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
		text: () => Promise.resolve(body),
		json: () => Promise.resolve({}),
	} as unknown as Response;
}
