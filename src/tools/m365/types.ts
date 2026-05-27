// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared result type for all M365 proxy tool calls.
 *
 * ok=true  → data contains the parsed JSON from bv-web's internal M365 surface.
 * ok=false → one of: unprovisioned (binding absent), error (HTTP non-2xx or unreachable).
 */
export type M365ProxyResult =
	| { ok: true; data: unknown }
	| { ok: false; unprovisioned: true; tool: string }
	| { ok: false; error: string };
