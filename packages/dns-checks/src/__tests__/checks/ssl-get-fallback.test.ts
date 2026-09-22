// SPDX-License-Identifier: BUSL-1.1

/**
 * check_ssl had no GET fallback while its sibling check-http-security has had one since
 * #806/#972. Both probe the SAME origin in the SAME scan, so on an origin that refuses HEAD
 * (403/405) or fails it server-side (5xx) but serves GET normally, http_security recovered and
 * reported real headers while ssl abstained — asymmetric coverage for one origin.
 *
 * The fix adopts a GET response ONLY when it is genuinely better evidence. These tests are
 * written to DISCRIMINATE: each recovery case is paired with a negative control where the
 * fallback must NOT rescue the probe, so reverting the fix fails the recovery arm and
 * over-applying it fails the abstention arm.
 *
 * Imports the SOURCE modules, not the built `@blackveil/dns-checks`.
 */

import { describe, it, expect } from 'vitest';
import { checkSSL } from '../../checks/check-ssl';
import type { FetchFunction } from '../../types';

const HSTS = 'max-age=31536000; includeSubDomains';

/**
 * Origin that answers the http:// leg with a real 301, refuses HEAD on https:// with
 * `headStatus`, and answers GET on https:// with `getResponse`. Records every method seen.
 */
function origin(headStatus: number, getResponse: () => Response) {
	const methods: string[] = [];
	const fetchFn: FetchFunction = async (url, init) => {
		const method = (init as { method?: string } | undefined)?.method ?? 'GET';
		if (url.startsWith('http://')) {
			return new Response(null, { status: 301, headers: { location: 'https://example.com/' } });
		}
		methods.push(method);
		return method === 'HEAD' ? new Response(null, { status: headStatus }) : getResponse();
	};
	return { fetchFn, methods };
}

describe('checkSSL — GET fallback recovers a HEAD-refusing origin', () => {
	// 403 is the #972 shape; 500 is the shape measured on www.vikingcruises.com.au
	// (HEAD 500 / GET 200) that prompted this fix.
	it.each([[403], [405], [500]])('HEAD %d then GET 200 with HSTS: MEASURED, not abstained', async (headStatus) => {
		const { fetchFn, methods } = origin(headStatus, () => new Response(null, { status: 200, headers: { 'strict-transport-security': HSTS } }));
		const result = await checkSSL('example.com', fetchFn);

		expect(methods).toContain('GET');
		// The whole point: the category is measured, so it is scored rather than excluded.
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.some((f) => f.title === 'HTTPS endpoint not assessable (status ' + headStatus + ')')).toBe(false);
		// And the HSTS header that IS served is not reported missing.
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
	});

	it('HEAD 403 then GET 200 WITHOUT HSTS reports the real gap (not an abstention)', async () => {
		const { fetchFn } = origin(403, () => new Response(null, { status: 200 }));
		const result = await checkSSL('example.com', fetchFn);

		// Recovering the probe must surface a genuine deficiency, not launder it into silence.
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(true);
		expect(result.checkStatus).toBeUndefined();
	});
});

describe('checkSSL — the fallback must NOT rescue a genuinely blocked origin (negative controls)', () => {
	it('HEAD 403 then GET 403 still abstains', async () => {
		const { fetchFn, methods } = origin(403, () => new Response(null, { status: 403 }));
		const result = await checkSSL('example.com', fetchFn);

		expect(methods).toContain('GET'); // the fallback was attempted
		expect(result.checkStatus).toBe('error'); // and correctly refused
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
		expect(result.score).toBe(0);
	});

	it('HEAD 403 then a 2xx-shaped block (GET 202) still abstains — #972 law', async () => {
		const { fetchFn } = origin(403, () => new Response(null, { status: 202, headers: { 'strict-transport-security': HSTS } }));
		const result = await checkSSL('example.com', fetchFn);

		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
	});

	it('HEAD 403 then a no-content GET 204 still abstains — #806 law', async () => {
		const { fetchFn } = origin(403, () => new Response(null, { status: 204 }));
		const result = await checkSSL('example.com', fetchFn);

		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
	});

	it('HEAD 405 then GET 405 abstains rather than scoring the refusal as a missing header', async () => {
		// Regression guard for the gap this suite exposed: 405 is absent from
		// isBlockedProbeStatus, so before needsGetFallback() a 405 fell through to the
		// analysis branch and its header-free body produced a confident "No HSTS header".
		const { fetchFn } = origin(405, () => new Response(null, { status: 405 }));
		const result = await checkSSL('example.com', fetchFn);

		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
		expect(result.checkStatus).toBe('error');
	});

	it('releases the body of a GET fallback it does NOT adopt', async () => {
		// A HEAD response carries no body, but the GET fallback does. When the fallback is
		// refused we still hold its stream, so without an explicit release every still-blocked
		// origin leaks a stalled stream for the remainder of the scan.
		let cancelled = false;
		const body = new ReadableStream({
			start(controller) {
				controller.enqueue(new TextEncoder().encode('blocked challenge page'));
			},
			cancel() {
				cancelled = true;
			},
		});
		const fetchFn: FetchFunction = async (url, init) => {
			const method = (init as { method?: string } | undefined)?.method ?? 'GET';
			if (url.startsWith('http://')) return new Response(null, { status: 301, headers: { location: 'https://example.com/' } });
			if (method === 'HEAD') return new Response(null, { status: 403 });
			return new Response(body, { status: 403 });
		};

		const result = await checkSSL('example.com', fetchFn);

		expect(result.checkStatus).toBe('error');
		await new Promise((resolve) => setTimeout(resolve, 0)); // let the void'd cancel settle
		expect(cancelled).toBe(true);
	});

	it('a fetch error on the fallback still abstains', async () => {
		const fetchFn: FetchFunction = async (url, init) => {
			const method = (init as { method?: string } | undefined)?.method ?? 'GET';
			if (url.startsWith('http://')) return new Response(null, { status: 301, headers: { location: 'https://example.com/' } });
			if (method === 'HEAD') return new Response(null, { status: 403 });
			throw new Error('SSRF rejected');
		};
		const result = await checkSSL('example.com', fetchFn);

		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
	});
});

describe('checkSSL — the happy path is unchanged (cost control)', () => {
	it('a HEAD 200 issues NO GET fallback', async () => {
		const { fetchFn, methods } = origin(200, () => {
			throw new Error('fallback must not be attempted on a measurable HEAD');
		});
		const result = await checkSSL('example.com', fetchFn);

		expect(methods).toEqual(['HEAD']);
		expect(result.checkStatus).toBeUndefined();
	});
});
