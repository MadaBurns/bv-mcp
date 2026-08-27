// SPDX-License-Identifier: BUSL-1.1

import type { M365ProxyResult } from './types';

/**
 * @deprecated Retained as a compatibility tombstone. The tool has no supported
 * live-read implementation and must never send tenant data to the M365 proxy.
 */
export function queryUal(
	_args: { ms_tenant_id: string; operation?: string; user_principal_name?: string; since_hours?: number },
	_proxy?: { fetch: typeof fetch },
	_opts?: { authToken?: string; keyHash?: string },
): Promise<M365ProxyResult> {
	return Promise.resolve({ ok: false, error: 'query_ual_deprecated' });
}
