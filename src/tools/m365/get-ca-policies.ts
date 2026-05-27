// SPDX-License-Identifier: BUSL-1.1

import type { M365ProxyResult } from './types';
import { callM365Proxy } from './proxy';

export async function getCaPolicies(
	args: { ms_tenant_id: string },
	proxy?: { fetch: typeof fetch },
): Promise<M365ProxyResult> {
	return callM365Proxy(proxy, 'get-ca-policies', args);
}
