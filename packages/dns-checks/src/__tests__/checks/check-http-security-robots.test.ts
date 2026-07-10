// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { checkHTTPSecurity } from '../../checks/check-http-security';
import { RobotsDisallowedError } from '../../robots-gate';

describe('checkHTTPSecurity — robots.txt disallow', () => {
	it('excludes the category and reports a distinct message when the initial fetch is robots-disallowed', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url);
		};
		const result = await checkHTTPSecurity('example.com', fetchFn);
		expect(result.checkStatus).toBe('error');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]!.detail).toContain('robots.txt');
		expect(result.findings[0]!.severity).toBe('info');
	});
});
