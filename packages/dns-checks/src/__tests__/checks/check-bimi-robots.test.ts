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
});
