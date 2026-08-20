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

	it('does not accuse a site of naming us when its robots.txt blocks every crawler', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url, 'blanket');
		};
		const result = await checkSSL('crt.sh', fetchFn);
		const detail = result.findings[0]!.detail;
		expect(detail).not.toContain('BlackVeil-Security-Scanner');
		expect(detail).toContain('all automated crawlers');
	});

	it('says so plainly when a site does name us', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url, 'named');
		};
		const result = await checkSSL('example.com', fetchFn);
		expect(result.findings[0]!.detail).toContain('BlackVeil-Security-Scanner');
	});

	it('records the abstention machine-readably rather than only in prose', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url, 'blanket');
		};
		const result = await checkSSL('crt.sh', fetchFn);
		const meta = result.findings[0]!.metadata ?? {};
		// A consumer must be able to tell "we chose not to look" from "the probe broke"
		// without string-matching the detail copy.
		expect(meta.notAssessedReason).toBe('robots_disallowed');
		expect(meta.robotsScope).toBe('blanket');
		// Pinned explicitly so `inferFindingConfidence`'s prose keyword scan can never
		// reclassify this finding as a side effect of a copy edit.
		expect(meta.confidence).toBe('deterministic');
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
