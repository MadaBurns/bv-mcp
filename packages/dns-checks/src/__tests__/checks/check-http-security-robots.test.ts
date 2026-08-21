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

	it('does not accuse a site of naming us when its robots.txt blocks every crawler', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url, 'blanket');
		};
		const result = await checkHTTPSecurity('crt.sh', fetchFn);
		const detail = result.findings[0]!.detail;
		expect(detail).not.toContain('BlackVeil-Security-Scanner');
		expect(detail).toContain('all automated crawlers');
	});

	it('says so plainly when a site does name us', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url, 'named');
		};
		const result = await checkHTTPSecurity('example.com', fetchFn);
		expect(result.findings[0]!.detail).toContain('BlackVeil-Security-Scanner');
	});

	it('records the abstention machine-readably rather than only in prose', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url, 'blanket');
		};
		const result = await checkHTTPSecurity('crt.sh', fetchFn);
		const meta = result.findings[0]!.metadata ?? {};
		expect(meta.notAssessedReason).toBe('robots_disallowed');
		expect(meta.robotsScope).toBe('blanket');
		expect(meta.confidence).toBe('deterministic');
	});
});
