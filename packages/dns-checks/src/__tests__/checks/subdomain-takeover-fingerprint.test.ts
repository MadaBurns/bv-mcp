// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the subdomain-takeover HTTP/TLS fingerprint helpers (#1094b).
 *
 * `matchFingerprintOverHttp` and `fetchAndMatchFingerprint` are module-private,
 * so they are exercised only through the exported entry points
 * `probeHttpFingerprint` (CNAME vector) and `probeARecordUnclaimedFingerprint`
 * (A/AAAA-only vector, #973), each driven with a mocked `FetchFunction`.
 * `isTlsCertAltnameMismatch` is exported and tested directly.
 *
 * Imports the SOURCE module, not the built `@blackveil/dns-checks` — meaningful
 * without a dist rebuild (same convention as
 * `http-security-blocked-probe.test.ts`).
 */

import { describe, it, expect } from 'vitest';
import {
	probeHttpFingerprint,
	probeARecordUnclaimedFingerprint,
	isTlsCertAltnameMismatch,
	TLS_SNI_MISMATCH_DISPLAY,
} from '../../checks/subdomain-takeover-analysis';
import { checkSubdomainTakeover } from '../../checks/check-subdomain-takeover';
import type { DNSQueryFunction, FetchFunction } from '../../types';

// A CNAME target that matches the 'amazonaws.com' TAKEOVER_FINGERPRINTS entry
// (SERVICE_DISPLAY_NAMES['amazonaws.com'] === 'AWS S3').
const S3_CNAME = 'mybucket.s3.amazonaws.com';

describe('probeHttpFingerprint (CNAME vector)', () => {
	it('returns the service display name on a matching fingerprint body', async () => {
		const fetchFn: FetchFunction = async () => new Response('<Error><Code>NoSuchBucket</Code></Error>', { status: 404 });
		expect(await probeHttpFingerprint('dangling.example.com', S3_CNAME, fetchFn)).toBe('AWS S3');
	});

	it('returns null when the body does not match any fingerprint pattern', async () => {
		const fetchFn: FetchFunction = async () => new Response('<html><body>Hello world</body></html>', { status: 200 });
		expect(await probeHttpFingerprint('dangling.example.com', S3_CNAME, fetchFn)).toBeNull();
	});

	it('returns null without calling fetch when the CNAME matches no takeover-service entry', async () => {
		let called = false;
		const fetchFn: FetchFunction = async () => {
			called = true;
			return new Response('NoSuchBucket', { status: 404 });
		};
		const result = await probeHttpFingerprint('foo.example.com', 'origin.unlisted-hosting.example', fetchFn);
		expect(result).toBeNull();
		expect(called).toBe(false);
	});

	it('skips fingerprint matching on a redirect (3xx), even though the unread body would match', async () => {
		const fetchFn: FetchFunction = async () =>
			new Response('NoSuchBucket', { status: 301, headers: { location: 'https://example.com/' } });
		expect(await probeHttpFingerprint('dangling.example.com', S3_CNAME, fetchFn)).toBeNull();
	});

	it('treats a synthetic edge 525 (origin TLS handshake failure) as an inconclusive transport error, not a match', async () => {
		// #973 live-miss: the Cloudflare edge answers a failed origin TLS handshake as a
		// completed 525 Response rather than rejecting the fetch. Status is conditional
		// on scheme — the source only special-cases this for `https://`.
		const fetchFn: FetchFunction = async () => new Response('NoSuchBucket', { status: 525 });
		expect(await probeHttpFingerprint('dangling.example.com', S3_CNAME, fetchFn)).toBeNull();
	});

	it('treats a synthetic edge 526 (invalid origin certificate) as an inconclusive transport error, not a match', async () => {
		const fetchFn: FetchFunction = async () => new Response('NoSuchBucket', { status: 526 });
		expect(await probeHttpFingerprint('dangling.example.com', S3_CNAME, fetchFn)).toBeNull();
	});

	it('classifies a TLS cert altname/SNI mismatch thrown by fetchFn as the deprovision sentinel', async () => {
		const fetchFn: FetchFunction = async () => {
			throw new Error("Hostname/IP does not match certificate's altnames: Host: dangling.example.com. is not in the cert's altnames");
		};
		expect(await probeHttpFingerprint('dangling.example.com', S3_CNAME, fetchFn)).toBe(TLS_SNI_MISMATCH_DISPLAY);
	});

	it('stays silent (null) on a generic transport error, with no http fallback for the CNAME vector', async () => {
		let calls = 0;
		const fetchFn: FetchFunction = async () => {
			calls++;
			throw new Error('connect ECONNREFUSED 203.0.113.5:443');
		};
		const result = await probeHttpFingerprint('dangling.example.com', S3_CNAME, fetchFn);
		expect(result).toBeNull();
		expect(calls).toBe(1); // only the https:// leg is attempted — probeHttpFingerprint never falls back to http
	});

	it('stays silent (null) on a timeout (AbortError) from the fetch deadline', async () => {
		const fetchFn: FetchFunction = async () => {
			throw new DOMException('The operation was aborted', 'AbortError');
		};
		expect(await probeHttpFingerprint('dangling.example.com', S3_CNAME, fetchFn)).toBeNull();
	});

	it('stays silent (null) on an SSRF-guard-style TypeError ("Failed to fetch")', async () => {
		const fetchFn: FetchFunction = async () => {
			throw new TypeError('Failed to fetch');
		};
		expect(await probeHttpFingerprint('dangling.example.com', S3_CNAME, fetchFn)).toBeNull();
	});

	it('treats a body over the 64KB cap as unmatched via the declared Content-Length short-circuit', async () => {
		// Declared content-length alone (100000 > the 64KB MAX_BODY_BYTES cap) is enough to
		// short-circuit before the stream is even read, per readResponseTextCapped.
		const fetchFn: FetchFunction = async () =>
			new Response('NoSuchBucket', { status: 404, headers: { 'content-length': '100000' } });
		expect(await probeHttpFingerprint('dangling.example.com', S3_CNAME, fetchFn)).toBeNull();
	});

	it('stays silent (null) when the body stream errors mid-read', async () => {
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new TextEncoder().encode('NoSuch'));
				controller.error(new Error('stream reset'));
			},
		});
		const fetchFn: FetchFunction = async () => new Response(stream, { status: 404 });
		expect(await probeHttpFingerprint('dangling.example.com', S3_CNAME, fetchFn)).toBeNull();
	});
});

describe('probeARecordUnclaimedFingerprint (A/AAAA-only vector, #973)', () => {
	it('matches the Cloudways unmapped-domain fingerprint over https', async () => {
		const fetchFn: FetchFunction = async () =>
			new Response('The requested domain is not authorized on Cloudways server', { status: 403 });
		expect(await probeARecordUnclaimedFingerprint('dangling.example.com', fetchFn)).toBe('Cloudways');
	});

	it('returns null when the body does not match any A-record fingerprint', async () => {
		const fetchFn: FetchFunction = async () => new Response('<html><body>Hello world</body></html>', { status: 200 });
		expect(await probeARecordUnclaimedFingerprint('dangling.example.com', fetchFn)).toBeNull();
	});

	it('falls back to plain http when the https leg fails with a non-SNI transport error, and matches there', async () => {
		const calls: string[] = [];
		const fetchFn: FetchFunction = async (url) => {
			calls.push(url);
			if (url.startsWith('https://')) throw new Error('connect ECONNREFUSED');
			return new Response('the requested domain is not authorized on cloudways server', { status: 403 });
		};
		const result = await probeARecordUnclaimedFingerprint('dangling.example.com', fetchFn);
		expect(result).toBe('Cloudways');
		expect(calls).toEqual(['https://dangling.example.com', 'http://dangling.example.com']);
	});

	it('stays silent (null) when both the https and http legs fail', async () => {
		const fetchFn: FetchFunction = async () => {
			throw new Error('connect ECONNREFUSED');
		};
		expect(await probeARecordUnclaimedFingerprint('dangling.example.com', fetchFn)).toBeNull();
	});

	it('returns the TLS-SNI sentinel directly on an altname mismatch, without attempting the http fallback', async () => {
		let calls = 0;
		const fetchFn: FetchFunction = async () => {
			calls++;
			throw new Error("unable to verify the first certificate: no alternative certificate subject name matches target host name 'dangling.example.com'");
		};
		const result = await probeARecordUnclaimedFingerprint('dangling.example.com', fetchFn);
		expect(result).toBe(TLS_SNI_MISMATCH_DISPLAY);
		expect(calls).toBe(1); // the SNI-mismatch sentinel short-circuits before the #973 http fallback
	});
});

describe('isTlsCertAltnameMismatch', () => {
	it.each<[string, boolean]>([
		// Recognized variants across runtimes (see the source's JSDoc for the provenance of each).
		["Hostname/IP does not match certificate's altnames: Host: foo.com. is not in the cert's altnames", true],
		['ERR_TLS_CERT_ALTNAME_INVALID', true],
		["unable to verify the first certificate: no alternative certificate subject name matches target host name 'foo.com'", true],
		['Hostname mismatch', true],
		["Hostname/IP doesn't match the certificate's altnames", true],
		['does not match the certificate', true],
		['ALTNAME MISMATCH', true], // case-insensitive
		// Near-miss negatives — generic/unrelated certificate errors that must NOT classify
		// as an SNI/altname mismatch (the source deliberately avoids matching bare
		// "certificate" so expired/self-signed errors don't get read as a deprovision signal).
		['certificate has expired', false],
		['self signed certificate in certificate chain', false],
		['unable to verify the first certificate', false],
		['certificate is not yet valid', false],
		['unable to get local issuer certificate', false],
		['connect ECONNREFUSED 203.0.113.5:443', false],
		['', false],
	])('%s -> %s', (message, expected) => {
		expect(isTlsCertAltnameMismatch(message)).toBe(expected);
	});
});

describe('generic fingerprints are gated on the status the provider returns for an unclaimed host', () => {
	const RENDER_CNAME = 'my-api.onrender.com';
	const FASTLY_CNAME = 'example.global.ssl.fastly.net';

	it('does not read a live Render app answering {"detail":"Not Found"} as a takeover', async () => {
		const fetchFn: FetchFunction = async () =>
			new Response('{"detail":"Not Found"}', { status: 404, headers: { 'content-type': 'application/json' } });
		expect(await probeHttpFingerprint('api.example.com', RENDER_CNAME, fetchFn)).toBeNull();
	});

	it('does not read a bare 200 body containing "Not Found" on Render as a takeover', async () => {
		const fetchFn: FetchFunction = async () => new Response('<p>Item Not Found</p>', { status: 200 });
		expect(await probeHttpFingerprint('api.example.com', RENDER_CNAME, fetchFn)).toBeNull();
	});

	it('matches Render only when the platform marks the host as having no server', async () => {
		const fetchFn: FetchFunction = async () => new Response('Not Found', { status: 404, headers: { 'x-render-routing': 'no-server' } });
		expect(await probeHttpFingerprint('api.example.com', RENDER_CNAME, fetchFn)).toBe('Render');
	});

	it('still matches the Render "has not been deployed" page on a 404', async () => {
		const fetchFn: FetchFunction = async () => new Response('This service has not been deployed', { status: 404 });
		expect(await probeHttpFingerprint('api.example.com', RENDER_CNAME, fetchFn)).toBe('Render');
	});

	it('does not read the bare phrase "unknown domain" on a Fastly-fronted 200 as a takeover', async () => {
		const fetchFn: FetchFunction = async () => new Response('Enter an unknown domain to look up', { status: 200 });
		expect(await probeHttpFingerprint('www.example.com', FASTLY_CNAME, fetchFn)).toBeNull();
	});

	it('does not read the bare phrase "unknown domain" on a Fastly-fronted 404 as a takeover', async () => {
		const fetchFn: FetchFunction = async () => new Response('unknown domain', { status: 404 });
		expect(await probeHttpFingerprint('www.example.com', FASTLY_CNAME, fetchFn)).toBeNull();
	});

	it('matches the Fastly 500 "unknown domain" error page', async () => {
		const fetchFn: FetchFunction = async () => new Response('Fastly error: unknown domain: www.example.com.', { status: 500 });
		expect(await probeHttpFingerprint('www.example.com', FASTLY_CNAME, fetchFn)).toBe('Fastly');
	});
});

// #1201 — every result states its sweep denominator, and a caller list that was not fully
// used is a partial (uncacheable) answer instead of a silently substituted built-in sweep.
describe('checkSubdomainTakeover sweep descriptor (#1201)', () => {
	const emptyDns: DNSQueryFunction = async () => [];

	function names(count: number): string[] {
		return Array.from({ length: count }, (_, i) => `host-${i}.example.com`);
	}

	it('built-in sweep: states sweptCount 15 and sweepSource builtin on the clean finding', async () => {
		const result = await checkSubdomainTakeover('example.com', emptyDns);
		const meta = result.findings[0].metadata as Record<string, unknown>;
		expect(meta.sweptCount).toBe(15);
		expect(meta.sweepSource).toBe('builtin');
		expect(meta).not.toHaveProperty('requestedCount');
		expect(meta).not.toHaveProperty('truncatedTo');
		expect(result.findings[0].detail).toContain('among the 15 subdomains swept (built-in list)');
		expect(result.partial).toBeUndefined();
	});

	it('caller list of 3: states sweptCount 3, sweepSource caller, requestedCount 3', async () => {
		const result = await checkSubdomainTakeover('example.com', emptyDns, { subdomains: names(3) });
		const meta = result.findings[0].metadata as Record<string, unknown>;
		expect(meta.sweptCount).toBe(3);
		expect(meta.sweepSource).toBe('caller');
		expect(meta.requestedCount).toBe(3);
		expect(meta).not.toHaveProperty('truncatedTo');
		expect(result.findings[0].detail).toContain('among the 3 subdomains swept (caller-supplied list)');
		expect(result.partial).toBeUndefined();
	});

	it('1001-name caller list: truncatedTo 1000, partial true, and the detail says so', async () => {
		const result = await checkSubdomainTakeover('example.com', emptyDns, { subdomains: names(1001) });
		const meta = result.findings[0].metadata as Record<string, unknown>;
		expect(meta.sweptCount).toBe(1000);
		expect(meta.requestedCount).toBe(1001);
		expect(meta.truncatedTo).toBe(1000);
		expect(result.partial).toBe(true);
		expect(result.findings[0].detail).toContain('truncated to the first 1000');
	});

	it('whitespace-only caller list: not assessed, no built-in fallback, no DNS issued', async () => {
		let calls = 0;
		const countingDns: DNSQueryFunction = async () => {
			calls += 1;
			return [];
		};
		const result = await checkSubdomainTakeover('example.com', countingDns, { subdomains: ['  ', '', '\t'] });
		expect(calls).toBe(0);
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.partial).toBe(true);
		const meta = result.findings[0].metadata as Record<string, unknown>;
		expect(meta.reason).toBe('caller_list_unusable');
		expect(meta.inconclusive).toBe(true);
		expect(meta).not.toHaveProperty('missingControl');
		expect(meta.sweptCount).toBe(0);
		expect(meta.sweepSource).toBe('caller');
		expect(meta.requestedCount).toBe(3);
		expect(result.findings.some((f) => f.title === 'No dangling CNAME records found')).toBe(false);
	});

	it('an empty caller array is "no list supplied" and still sweeps the built-in names', async () => {
		const result = await checkSubdomainTakeover('example.com', emptyDns, { subdomains: [] });
		const meta = result.findings[0].metadata as Record<string, unknown>;
		expect(meta.sweepSource).toBe('builtin');
		expect(meta.sweptCount).toBe(15);
	});

	it('aRecordVectorSampleCap smaller than the sweep: states aRecordVectorSampledTo', async () => {
		const result = await checkSubdomainTakeover('example.com', emptyDns, { aRecordVectorSampleCap: 2 });
		expect((result.findings[0].metadata as Record<string, unknown>).aRecordVectorSampledTo).toBe(2);
	});

	it('aRecordVectorSampleCap at or above the sweep size is not a sample: no aRecordVectorSampledTo', async () => {
		const result = await checkSubdomainTakeover('example.com', emptyDns, { aRecordVectorSampleCap: 15 });
		expect(result.findings[0].metadata as Record<string, unknown>).not.toHaveProperty('aRecordVectorSampledTo');
	});

	it('the #948 abstention carries the descriptor', async () => {
		const failingDns: DNSQueryFunction = async () => {
			throw new Error('resolver down');
		};
		const result = await checkSubdomainTakeover('example.com', failingDns, { subdomains: names(2) });
		expect(result.checkStatus).toBe('error');
		const meta = result.findings[0].metadata as Record<string, unknown>;
		expect(meta.sweptCount).toBe(2);
		expect(meta.sweepSource).toBe('caller');
		expect(meta.requestedCount).toBe(2);
	});

	it('a dangling-CNAME finding carries the descriptor without changing its title or severity', async () => {
		const danglingDns: DNSQueryFunction = async (name, type) =>
			type === 'CNAME' && name === 'staging.example.com' ? ['old-app.herokuapp.com.'] : [];
		const result = await checkSubdomainTakeover('example.com', danglingDns, { subdomains: ['staging.example.com', 'www.example.com'] });
		const dangling = result.findings.find((f) => f.title.startsWith('Dangling CNAME'));
		expect(dangling).toBeDefined();
		expect(dangling?.severity).toBe('high');
		expect(dangling?.title).toBe('Dangling CNAME: staging.example.com → old-app.herokuapp.com');
		const meta = dangling?.metadata as Record<string, unknown>;
		expect(meta.sweptCount).toBe(2);
		expect(meta.sweepSource).toBe('caller');
		expect(meta.requestedCount).toBe(2);
	});

	it('a truncated caller list is partial even when a dangling finding makes the result non-clean', async () => {
		const danglingDns: DNSQueryFunction = async (name, type) =>
			type === 'CNAME' && name === 'host-0.example.com' ? ['old-app.herokuapp.com.'] : [];
		const result = await checkSubdomainTakeover('example.com', danglingDns, { subdomains: names(1001) });
		expect(result.partial).toBe(true);
		expect((result.findings[0].metadata as Record<string, unknown>).truncatedTo).toBe(1000);
	});
});
