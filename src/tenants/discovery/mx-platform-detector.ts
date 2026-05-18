// SPDX-License-Identifier: BUSL-1.1

import { queryDns } from '../../lib/dns-transport';

type DnsQueryFn = (name: string, type: 'MX') => Promise<{ Answer?: Array<{ data?: string }> }>;

export interface MxPlatformCandidate {
	domain: string;
	sharedMxPlatform: string;
	confidence: number;
}

export interface MxPlatformResult {
	seedDomain: string;
	coOwnedDomains: MxPlatformCandidate[];
	queryStatus: 'ok' | 'partial' | 'failed';
}

function platform(records: Array<{ data?: string }>): string | null {
	const joined = records.map((r) => (r.data ?? '').toLowerCase()).join(' ');
	if (/aspmx\.l\.google\.com|googlemail\.com/.test(joined)) return 'google_workspace';
	if (/protection\.outlook\.com/.test(joined)) return 'm365';
	if (/pphosted\.com/.test(joined)) return 'proofpoint';
	if (/mimecast\.com/.test(joined)) return 'mimecast';
	return null;
}

export async function detectSharedMxPlatform(
	seedDomain: string,
	options: { candidateDomains: string[]; dnsQuery?: DnsQueryFn },
): Promise<MxPlatformResult> {
	const dnsQuery = options.dnsQuery ?? ((name, type) => queryDns(name, type) as Promise<{ Answer?: Array<{ data?: string }> }>);
	let seedPlatform: string | null;
	try {
		const seed = await dnsQuery(seedDomain, 'MX');
		seedPlatform = platform(seed.Answer ?? []);
	} catch {
		return { seedDomain, coOwnedDomains: [], queryStatus: 'failed' };
	}
	if (!seedPlatform) return { seedDomain, coOwnedDomains: [], queryStatus: 'ok' };

	const coOwnedDomains: MxPlatformCandidate[] = [];
	let partial = false;
	for (const domain of options.candidateDomains) {
		try {
			const candidate = await dnsQuery(domain, 'MX');
			if (platform(candidate.Answer ?? []) === seedPlatform) {
				coOwnedDomains.push({ domain, sharedMxPlatform: seedPlatform, confidence: 0.55 });
			}
		} catch {
			partial = true;
		}
	}

	return { seedDomain, coOwnedDomains, queryStatus: partial ? 'partial' : 'ok' };
}
