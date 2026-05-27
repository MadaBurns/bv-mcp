// SPDX-License-Identifier: BUSL-1.1

import type { M365ProxyResult } from './types';
import { callM365Proxy } from './proxy';

export async function assessCoverage(
	args: { ms_tenant_id: string },
	proxy?: { fetch: typeof fetch },
): Promise<M365ProxyResult> {
	return callM365Proxy(proxy, 'assess-coverage', args);
}
