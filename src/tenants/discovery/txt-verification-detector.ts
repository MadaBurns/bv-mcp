// SPDX-License-Identifier: BUSL-1.1

import { queryDns } from '../../lib/dns-transport';

type DnsQueryFn = (name: string, type: 'TXT') => Promise<{ Answer?: Array<{ data?: string }> }>;

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
	options: { candidateDomains: string[]; dnsQuery?: DnsQueryFn },
): Promise<TxtVerificationResult> {
	const dnsQuery = options.dnsQuery ?? ((name, type) => queryDns(name, type) as Promise<{ Answer?: Array<{ data?: string }> }>);
	let seedTokens: string[];
	try {
		const seed = await dnsQuery(seedDomain, 'TXT');
		seedTokens = verificationTokens(seed.Answer ?? []);
	} catch {
		return { seedDomain, coOwnedDomains: [], queryStatus: 'failed' };
	}

	const coOwnedDomains: TxtVerificationCandidate[] = [];
	let partial = false;
	for (const domain of options.candidateDomains) {
		try {
			const candidate = await dnsQuery(domain, 'TXT');
			const candidateTokens = verificationTokens(candidate.Answer ?? []);
			const sharedTxtVerifications = candidateTokens.filter((token) => seedTokens.includes(token));
			if (sharedTxtVerifications.length > 0) {
				coOwnedDomains.push({ domain, sharedTxtVerifications, confidence: 0.9 });
			}
		} catch {
			partial = true;
		}
	}

	return { seedDomain, coOwnedDomains, queryStatus: partial ? 'partial' : 'ok' };
}
