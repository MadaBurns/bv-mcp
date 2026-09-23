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
import type { FetchFunction } from '../../types';

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
