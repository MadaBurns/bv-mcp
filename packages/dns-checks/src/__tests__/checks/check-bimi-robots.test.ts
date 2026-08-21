// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { checkBIMI } from '../../checks/check-bimi';
import { RobotsDisallowedError } from '../../robots-gate';

const bimiTxt = 'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem';
const dmarcEnforcing = 'v=DMARC1; p=reject';

function queryDNS(fqdn: string, type: string): Promise<string[]> {
	if (fqdn.startsWith('default._bimi.') && type === 'TXT') return Promise.resolve([bimiTxt]);
	if (fqdn.startsWith('_dmarc.') && type === 'TXT') return Promise.resolve([dmarcEnforcing]);
	return Promise.resolve([]);
}

describe('checkBIMI — robots.txt disallow', () => {
	it('reports a neutral info finding instead of a low-severity "fetch failed" penalty', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url);
		};
		const result = await checkBIMI('example.com', queryDNS, { fetchFn });
		const logoFinding = result.findings.find((f) => f.title.includes('robots.txt'));
		expect(logoFinding).toBeDefined();
		expect(logoFinding!.severity).toBe('info');
		expect(result.findings.some((f) => f.title === 'BIMI logo fetch failed')).toBe(false);
	});

	it('does not accuse a site of naming us when its robots.txt blocks every crawler', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url, 'blanket');
		};
		const result = await checkBIMI('example.com', queryDNS, { fetchFn });
		const logoFinding = result.findings.find((f) => f.title.includes('robots.txt'))!;
		expect(logoFinding.detail).not.toContain('BlackVeil-Security-Scanner');
		expect(logoFinding.detail).toContain('all automated crawlers');
	});

	it('says so plainly when a site does name us', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url, 'named');
		};
		const result = await checkBIMI('example.com', queryDNS, { fetchFn });
		const logoFinding = result.findings.find((f) => f.title.includes('robots.txt'))!;
		expect(logoFinding.detail).toContain('BlackVeil-Security-Scanner');
	});

	it('records the abstention machine-readably rather than only in prose', async () => {
		const fetchFn = async (url: string) => {
			throw new RobotsDisallowedError(url, 'blanket');
		};
		const result = await checkBIMI('example.com', queryDNS, { fetchFn });
		const logoFinding = result.findings.find((f) => f.title.includes('robots.txt'))!;
		expect(logoFinding.metadata?.notAssessedReason).toBe('robots_disallowed');
		expect(logoFinding.metadata?.robotsScope).toBe('blanket');
	});
});
