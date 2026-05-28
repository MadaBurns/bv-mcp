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
	// Extract each MX exchange host (DoH MX data is "<pref> <host>."), then match
	// on a proper domain suffix rather than a substring of the joined records.
	// Substring/`.test()` on joined data was an unanchored match (CWE-20 /
	// js/regex/missing-regexp-anchor) that could be fooled by a host like
	// `protection.outlook.com.evil.example`; suffix matching is precise.
	const hosts = records.map((r) => {
		const host = (r.data ?? '').trim().toLowerCase().split(/\s+/).pop() ?? '';
		return host.replace(/\.$/, '');
	});
	const matches = (suffix: string) => hosts.some((h) => h === suffix || h.endsWith(`.${suffix}`));
	if (matches('aspmx.l.google.com') || matches('googlemail.com')) return 'google_workspace';
	if (matches('protection.outlook.com')) return 'm365';
	if (matches('pphosted.com')) return 'proofpoint';
	if (matches('mimecast.com')) return 'mimecast';
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
