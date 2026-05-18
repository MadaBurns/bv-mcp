// SPDX-License-Identifier: BUSL-1.1

import { queryDns } from '../../lib/dns-transport';
import { mapConcurrent } from '../../lib/map-concurrent';
import type { DiscoveryDnsContext } from './dns-context';

type DnsQueryFn = (name: string, type: 'TXT') => Promise<{ Answer?: Array<{ data?: string }> }>;

export interface TxtVerificationOptions {
	candidateDomains: string[];
	dnsQuery?: DnsQueryFn;
	dnsContext?: DiscoveryDnsContext;
}

const TOKEN_PREFIXES = [
	'google-site-verification=',
	'MS=',
	'apple-domain-verification=',
	'facebook-domain-verification=',
	'atlassian-domain-verification=',
	'globalsign-domain-verification=',
];

export interface TxtVerificationCandidate {
	domain: string;
	sharedTxtVerifications: string[];
	confidence: number;
}

export interface TxtVerificationResult {
	seedDomain: string;
	coOwnedDomains: TxtVerificationCandidate[];
	queryStatus: 'ok' | 'partial' | 'failed';
}

function cleanTxt(raw: string): string {
	return raw.replace(/^"+|"+$/g, '').trim();
}

function verificationTokens(records: Array<{ data?: string }>): string[] {
	const tokens = new Set<string>();
	for (const record of records) {
		const value = cleanTxt(record.data ?? '');
		if (TOKEN_PREFIXES.some((prefix) => value.startsWith(prefix))) tokens.add(value);
	}
	return Array.from(tokens).sort();
}

export async function detectSharedTxtVerifications(
	seedDomain: string,
	options: TxtVerificationOptions,
): Promise<TxtVerificationResult> {
	const dnsQuery =
		options.dnsContext?.query ??
		options.dnsQuery ??
		((name: string, type: string) => queryDns(name, type as 'TXT') as Promise<{ Answer?: Array<{ data?: string }> }>);
	let seedTokens: string[];
	try {
		const seed = await dnsQuery(seedDomain, 'TXT');
		seedTokens = verificationTokens(seed.Answer ?? []);
	} catch {
		return { seedDomain, coOwnedDomains: [], queryStatus: 'failed' };
	}

	const probed = await mapConcurrent(options.candidateDomains, 6, async (domain): Promise<{ candidate: TxtVerificationCandidate | null; failed: boolean }> => {
		try {
			const candidate = await dnsQuery(domain, 'TXT');
			const candidateTokens = verificationTokens(candidate.Answer ?? []);
			const sharedTxtVerifications = candidateTokens.filter((token) => seedTokens.includes(token));
			if (sharedTxtVerifications.length > 0) {
				return { candidate: { domain, sharedTxtVerifications, confidence: 0.9 }, failed: false };
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
