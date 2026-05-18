// SPDX-License-Identifier: BUSL-1.1

import { queryDns } from '../../lib/dns-transport';
import { mapConcurrent } from '../../lib/map-concurrent';
import type { DiscoveryDnsContext } from './dns-context';

type DnsQueryFn = (name: string, type: 'MX') => Promise<{ Answer?: Array<{ data?: string }> }>;

export interface MxPlatformOptions {
	candidateDomains: string[];
	dnsQuery?: DnsQueryFn;
	dnsContext?: DiscoveryDnsContext;
}

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
	options: MxPlatformOptions,
): Promise<MxPlatformResult> {
	const dnsQuery =
		options.dnsContext?.query ??
		options.dnsQuery ??
		((name: string, type: string) => queryDns(name, type as 'MX') as Promise<{ Answer?: Array<{ data?: string }> }>);
	let seedPlatform: string | null;
	try {
		const seed = await dnsQuery(seedDomain, 'MX');
		seedPlatform = platform(seed.Answer ?? []);
	} catch {
		return { seedDomain, coOwnedDomains: [], queryStatus: 'failed' };
	}
	if (!seedPlatform) return { seedDomain, coOwnedDomains: [], queryStatus: 'ok' };

	const probed = await mapConcurrent(options.candidateDomains, 6, async (domain): Promise<{ candidate: MxPlatformCandidate | null; failed: boolean }> => {
		try {
			const candidate = await dnsQuery(domain, 'MX');
			if (platform(candidate.Answer ?? []) === seedPlatform) {
				return { candidate: { domain, sharedMxPlatform: seedPlatform, confidence: 0.55 }, failed: false };
			}
		} catch {
			return { candidate: null, failed: true };
		}
		return { candidate: null, failed: false };
	});

	const coOwnedDomains = probed.flatMap((result) => (result.candidate ? [result.candidate] : []));
	const partial = probed.some((result) => result.failed);

	return { seedDomain, coOwnedDomains, queryStatus: partial ? 'partial' : 'ok' };
}
