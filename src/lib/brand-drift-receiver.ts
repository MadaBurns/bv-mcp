// SPDX-License-Identifier: BUSL-1.1

/**
 * BlackVeil's own Brand Drift receiver — the one watch webhook destination that
 * is delivered over the private BV_WEB service binding with the internal
 * BV_MCP_BRAND_WEBHOOK_KEY bearer (`src/queue/brand-audit-consumer.ts`).
 *
 * Because delivery to this origin+path carries an internal credential, only the
 * first-party service may register a watch that points at it. The register
 * tool refuses it on every other path, using {@link isBrandDriftReceiverTarget},
 * which matches on origin and path alone so no query string, fragment or
 * userinfo variant slips past the register-time check and is then treated as
 * trusted at delivery time.
 */

/** The sole customer webhook destination allowed to receive BlackVeil's internal capability. */
export const BLACKVEIL_BRAND_DRIFT_RECEIVER = 'https://www.blackveilsecurity.com/api/webhooks/brand-drift';

/** Parse `rawUrl` and return it when its origin and path are the Brand Drift receiver; `null` otherwise. */
export function isBrandDriftReceiverTarget(rawUrl: string): URL | null {
	let url: URL;
	try {
		url = new URL(rawUrl);
	} catch {
		return null;
	}
	const expected = new URL(BLACKVEIL_BRAND_DRIFT_RECEIVER);
	return url.origin === expected.origin && url.pathname === expected.pathname ? url : null;
}
