// SPDX-License-Identifier: BUSL-1.1

import type { M365ProxyResult } from './types';
import { callM365Proxy } from './proxy';

export async function querySignins(
	args: { ms_tenant_id: string; user_principal_name?: string; failures_only?: boolean; since_hours?: number },
	proxy?: { fetch: typeof fetch },
	opts?: { authToken?: string; keyHash?: string },
): Promise<M365ProxyResult> {
	return callM365Proxy(proxy, 'query-signins', args, opts);
}
