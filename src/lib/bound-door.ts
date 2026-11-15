// SPDX-License-Identifier: BUSL-1.1

/**
 * The bound public door: how the Worker knows a request came in through the
 * `BoundPublicDoor` named entry point rather than the default handler.
 *
 * Recognition is by OBJECT IDENTITY, never by a header. The entry point adds the
 * `Request` it was handed to a module-private `WeakSet`; the public pipeline asks
 * whether the request it is serving is in that set. A caller on the public
 * internet arrives at the default handler, which never adds anything, so no
 * header, query string or body it sends can make this answer `true`.
 *
 * Why the door exists: a Worker-to-Worker call carries no `cf-connecting-ip`.
 * Sent through the default handler, such calls are logged as public-door rows
 * with no client IP and distort the client-IP presence audit
 * (`src/lib/client-ip-audit.ts`), which counts `source = 'public'` rows only.
 */

const BOUND_DOOR_REQUESTS = new WeakSet<Request>();

/** `mcp_access_log.source` value for a call that came in through the bound door. */
export const BOUND_DOOR_SOURCE = 'binding';

/** The only path the bound door serves. Exact match: no trailing slash, no case folding. */
export const BOUND_DOOR_PATH = '/mcp';

/** Whether the bound door serves this URL path. Everything else is "not found" there. */
export function isBoundDoorPath(pathname: string): boolean {
	return pathname === BOUND_DOOR_PATH;
}

/** Called by the named entry point only. */
export function markBoundDoorRequest(request: Request): void {
	BOUND_DOOR_REQUESTS.add(request);
}

/** True only for a `Request` object the named entry point marked. */
export function isBoundDoorRequest(request: Request): boolean {
	return BOUND_DOOR_REQUESTS.has(request);
}
