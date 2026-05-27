// SPDX-License-Identifier: BUSL-1.1

import type { M365ProxyResult } from './types';
import { callM365Proxy } from './proxy';

export async function queryUal(
	args: { ms_tenant_id: string; operation?: string; user_principal_name?: string; since_hours?: number },
	proxy?: { fetch: typeof fetch },
	opts?: { authToken?: string; keyHash?: string },
): Promise<M365ProxyResult> {
	return callM365Proxy(proxy, 'query-ual', args, opts);
}
