// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { checkSSL } from '../../checks/check-ssl';
import { RobotsDisallowedError } from '../../robots-gate';

describe('checkSSL — robots.txt disallow', () => {
	it('excludes the category instead of scoring a false pass or a false critical failure', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url);
		};
		const result = await checkSSL('example.com', fetchFn);
		expect(result.checkStatus).toBe('error');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]!.severity).toBe('info');
		expect(result.findings[0]!.detail).toContain('robots.txt');
		expect(result.controlPresent).toBeUndefined();
	});

	it('does not call the HTTP-redirect check when the HTTPS fetch was robots-disallowed', async () => {
		let redirectFetchCalled = false;
		const fetchFn = async (url: string) => {
			if (url.startsWith('http://')) redirectFetchCalled = true;
			throw new RobotsDisallowedError(url);
		};
		await checkSSL('example.com', fetchFn);
		expect(redirectFetchCalled).toBe(false);
	});
});
