// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

/**
 * One capped GET of a web page, shared by the non-scoring web checks.
 *
 * A caller can fetch each host once and hand the same {@link CappedPage} to every check
 * that reads it. Redirects are followed by hand, and only to HTTPS targets: an `http://`
 * hop is never followed, and the redirect that named it comes back as the final page so a
 * caller can still read its `Location`.
 *
 * Unlike `readResponseTextCapped` (../response-body), which returns `null` over the cap,
 * this keeps the first `maxBytes` bytes and sets `truncated: true`. An HTML scan wants the
 * head of the page, not nothing.
 *
 * Runtime-agnostic: no `node:` imports.
 */

import type { FetchFunction } from '../types';
import { SCANNER_USER_AGENT } from '../robots-gate';

/** Default byte cap on the body prefix kept (512 KiB). */
export const PAGE_FETCH_MAX_BYTES = 524_288;

/** Default number of redirects followed. Matches `HTTP_SECURITY_MAX_REDIRECT_HOPS`. */
export const PAGE_FETCH_MAX_REDIRECTS = 3;

/** Default time budget (ms) for the whole redirect chain, body included. */
export const PAGE_FETCH_TIMEOUT_MS = 5_000;

export interface CappedPage {
	/** The URL the caller asked for. */
	requestedUrl: string;
	/** The URL of the response returned: the last redirect target followed, or `requestedUrl`. */
	finalUrl: string;
	/** Status of the returned response. A 3xx means the chain stopped on a redirect (cap or non-HTTPS target). */
	status: number;
	headers: Headers;
	/** Every `Set-Cookie` header of the returned response, from `headers.getSetCookie()`; `[]` where unsupported. */
	setCookies: string[];
	/** The body, or its first `maxBytes` bytes when `truncated`. `null` only when the response carried no body. */
	body: string | null;
	/** True when the body was longer than `maxBytes` and was cut. */
	truncated: boolean;
	/** Redirect targets followed, in order. Empty when the first response was returned. */
	redirects: string[];
}

export interface PageFetchOptions {
	/** Time budget (ms) for the whole chain. Default {@link PAGE_FETCH_TIMEOUT_MS}. */
	timeout?: number;
	/** Bytes of body kept. Default {@link PAGE_FETCH_MAX_BYTES}. */
	maxBytes?: number;
	/** Redirects followed. Default {@link PAGE_FETCH_MAX_REDIRECTS}. */
	maxRedirects?: number;
}

/**
 * GET `url` and return the page, following at most `maxRedirects` HTTPS-only redirects.
 *
 * Returns `null` when any fetch in the chain throws (network failure, timeout, an SSRF
 * guard in the injected `fetchFn`) or the body stream fails. A non-2xx answer is still a
 * page, not `null`: the caller decides what a 403 or a 503 means.
 */
export async function fetchPageCapped(url: string, fetchFn: FetchFunction, opts: PageFetchOptions = {}): Promise<CappedPage | null> {
	const deadlineAt = Date.now() + (opts.timeout ?? PAGE_FETCH_TIMEOUT_MS);
	const maxRedirects = opts.maxRedirects ?? PAGE_FETCH_MAX_REDIRECTS;
	try {
		let currentUrl = url;
		let response = await getPage(currentUrl, fetchFn, deadlineAt);
		const redirects: string[] = [];
		for (let next = nextHop(response, currentUrl); next !== null && redirects.length < maxRedirects; next = nextHop(response, currentUrl)) {
			void response.body?.cancel().catch(() => undefined);
			currentUrl = next;
			redirects.push(next);
			response = await getPage(currentUrl, fetchFn, deadlineAt);
		}
		const { body, truncated } = await readBodyPrefix(response, opts.maxBytes ?? PAGE_FETCH_MAX_BYTES);
		return {
			requestedUrl: url,
			finalUrl: currentUrl,
			status: response.status,
			headers: response.headers,
			setCookies: readSetCookies(response.headers),
			body,
			truncated,
			redirects,
		};
	} catch {
		return null;
	}
}

function getPage(url: string, fetchFn: FetchFunction, deadlineAt: number): Promise<Response> {
	return fetchFn(url, {
		method: 'GET',
		redirect: 'manual',
		headers: { 'User-Agent': SCANNER_USER_AGENT },
		signal: AbortSignal.timeout(Math.max(1, deadlineAt - Date.now())),
	});
}

/**
 * The HTTPS URL a redirect response points at, or `null` when the response is final: not a
 * redirect, no usable `Location`, or a target that is not `https:`.
 *
 * Status 0 with a `Location` covers the opaque redirect some runtimes return for
 * `redirect: 'manual'`. A relative `Location` resolves against the URL that was requested,
 * because a mocked or opaque response can carry an empty `response.url`.
 */
function nextHop(response: Response, requestUrl: string): string | null {
	const location = response.headers.get('location');
	if (location === null || !isRedirectStatus(response.status)) return null;
	const target = URL.parse(location, response.url || requestUrl);
	return target?.protocol === 'https:' ? target.href : null;
}

function isRedirectStatus(status: number): boolean {
	return status === 0 || (status >= 300 && status < 400);
}

function readSetCookies(headers: Headers): string[] {
	return typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [];
}

/** Read at most `maxBytes` bytes of the body, cancelling the stream at the cap. */
async function readBodyPrefix(response: Response, maxBytes: number): Promise<{ body: string | null; truncated: boolean }> {
	if (!response.body) return { body: null, truncated: false };
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	let truncated = false;
	try {
		for (let read = await reader.read(); !read.done; read = await reader.read()) {
			const room = maxBytes - total;
			truncated = read.value.byteLength > room;
			const kept = truncated ? read.value.subarray(0, room) : read.value;
			chunks.push(kept);
			total += kept.byteLength;
			if (truncated) break;
		}
	} finally {
		if (truncated) await reader.cancel('page body exceeded byte cap').catch(() => undefined);
		reader.releaseLock();
	}
	// `stream: true` on a cut body drops a multi-byte character split at the cap instead of
	// ending the prefix with U+FFFD.
	return { body: new TextDecoder().decode(concatChunks(chunks, total), { stream: truncated }), truncated };
}

function concatChunks(chunks: Uint8Array[], total: number): Uint8Array {
	const bytes = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return bytes;
}
