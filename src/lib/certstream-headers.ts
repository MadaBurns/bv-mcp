// SPDX-License-Identifier: BUSL-1.1
/**
 * Request headers for the BV_CERTSTREAM binding (the bv-ct-index query API). The index accepts a read key only
 * from the caller it was issued to, named in X-BV-Caller, so every request names bv-mcp. The bearer is added
 * when one is configured; without it the index answers 401 and the caller falls through to its public sources.
 */

export const CERTSTREAM_CALLER = 'bv-mcp';

export function certstreamHeaders(authToken: string | undefined): Record<string, string> {
	return authToken ? { 'X-BV-Caller': CERTSTREAM_CALLER, Authorization: `Bearer ${authToken}` } : { 'X-BV-Caller': CERTSTREAM_CALLER };
}
