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
