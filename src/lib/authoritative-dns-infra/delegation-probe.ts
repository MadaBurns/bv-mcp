// SPDX-License-Identifier: BUSL-1.1

/** Ordinary-zone parent/child delegation and glue probe orchestration. */

import { queryDns } from '../dns';
import { RecordType, type RecordTypeName } from '../dns-types';
import { directDnsQuery, type DirectDnsQuery, type DirectDnsResponse } from './dns-tcp';
import type {
	ChildAuthorityObservation,
	DelegationConsistencyEvidence,
	GlueObservation,
	ParentDelegationObservation,
} from './delegation-types';

const MAX_PARENT_NAMESERVERS = 2;
const MAX_CHILD_NAMESERVERS = 4;
const DIRECT_QUERY_TIMEOUT_MS = 1200;

export type RecursiveDnsQuery = (name: string, type: RecordTypeName) => Promise<string[]>;

export interface DelegationProbeDependencies {
	directQuery?: DirectDnsQuery;
	recursiveQuery?: RecursiveDnsQuery;
	now?: () => Date;
}

function normalizeName(name: string): string {
	return name.replace(/\.$/, '').toLowerCase();
}

function uniqueSorted(values: string[]): string[] {
	return [...new Set(values.map(normalizeName).filter(Boolean))].sort();
}

function normalizeAddress(address: string): string {
	const lower = address.toLowerCase();
	if (!lower.includes(':')) return lower;
	const halves = lower.split('::');
	if (halves.length > 2) return lower;
	const left = halves[0] ? halves[0].split(':') : [];
	const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
	const missing = halves.length === 2 ? 8 - left.length - right.length : 0;
	const groups = halves.length === 2 ? [...left, ...Array(Math.max(0, missing)).fill('0'), ...right] : left;
	if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return lower;
	return groups.map((group) => group.padStart(4, '0')).join(':');
}

function parentZoneOf(hostname: string): string {
	const dot = hostname.indexOf('.');
	if (dot <= 0 || dot === hostname.length - 1) throw new Error('A delegated DNS name must contain at least two labels');
	return hostname.slice(dot + 1);
}

function records(response: DirectDnsResponse, type: number, owner?: string): string[] {
	const normalizedOwner = owner ? normalizeName(owner) : undefined;
	return uniqueSorted(
		[...response.answers, ...response.authority]
			.filter((record) => record.type === type && record.data && (!normalizedOwner || record.name === normalizedOwner))
			.map((record) => record.data),
	);
}

function glueRecords(response: DirectDnsResponse, type: number, delegated: Set<string>): Record<string, string[]> {
	const grouped: Record<string, string[]> = {};
	for (const record of response.additional) {
		if (record.type !== type || !record.data || !delegated.has(record.name)) continue;
		(grouped[record.name] ??= []).push(normalizeAddress(record.data));
	}
	for (const name of Object.keys(grouped)) grouped[name] = [...new Set(grouped[name])].sort();
	return grouped;
}

async function defaultRecursiveQuery(name: string, type: RecordTypeName): Promise<string[]> {
	const response = await queryDns(name, type, false, { timeoutMs: DIRECT_QUERY_TIMEOUT_MS, retries: 0 });
	return (response.Answer ?? [])
		.filter((answer) => answer.type === RecordType[type])
		.map((answer) => answer.data.replace(/\.$/, '').toLowerCase());
}

async function observeParent(
	nameserver: string,
	hostname: string,
	query: DirectDnsQuery,
): Promise<ParentDelegationObservation> {
	try {
		const response = await query(nameserver, hostname, RecordType.NS, DIRECT_QUERY_TIMEOUT_MS);
		const delegationNs = records(response, RecordType.NS, hostname);
		const delegated = new Set(delegationNs);
		return {
			nameserver,
			delegationNs,
			glueIpv4: glueRecords(response, RecordType.A, delegated),
			glueIpv6: glueRecords(response, RecordType.AAAA, delegated),
			rcode: response.rcode,
		};
	} catch {
		return { nameserver, error: 'parent_query_failed' };
	}
}

async function observeChild(nameserver: string, hostname: string, query: DirectDnsQuery): Promise<ChildAuthorityObservation> {
	try {
		const response = await query(nameserver, hostname, RecordType.NS, DIRECT_QUERY_TIMEOUT_MS);
		return {
			nameserver,
			aaFlag: response.aa,
			publishedNs: records(response, RecordType.NS, hostname),
			rcode: response.rcode,
		};
	} catch {
		return { nameserver, error: 'child_query_failed' };
	}
}

function aggregateGlue(
	observations: ParentDelegationObservation[],
	field: 'glueIpv4' | 'glueIpv6',
	nameserver: string,
): string[] {
	return [...new Set(observations.flatMap((observation) => observation[field]?.[nameserver] ?? []))].sort();
}

function isInBailiwick(nameserver: string, hostname: string): boolean {
	return nameserver === hostname || nameserver.endsWith(`.${hostname}`);
}

async function observeGlue(
	nameserver: string,
	parentObservations: ParentDelegationObservation[],
	recursiveQuery: RecursiveDnsQuery,
): Promise<GlueObservation> {
	const [ipv4, ipv6] = await Promise.allSettled([
		recursiveQuery(nameserver, 'A'),
		recursiveQuery(nameserver, 'AAAA'),
	]);
	return {
		nameserver,
		parentIpv4: aggregateGlue(parentObservations, 'glueIpv4', nameserver),
		parentIpv6: aggregateGlue(parentObservations, 'glueIpv6', nameserver),
		...(ipv4.status === 'fulfilled' ? { currentIpv4: [...new Set(ipv4.value.map(normalizeAddress))].sort() } : {}),
		...(ipv6.status === 'fulfilled' ? { currentIpv6: [...new Set(ipv6.value.map(normalizeAddress))].sort() } : {}),
	};
}

/**
 * Query the parent directly for its referral, then query each delegated child
 * server directly with RD=0. Every fan-out is hard-capped and every individual
 * failure remains explicit evidence rather than becoming a false finding.
 */
export async function probeDelegationConsistency(
	domain: string,
	dependencies: DelegationProbeDependencies = {},
): Promise<DelegationConsistencyEvidence> {
	const hostname = normalizeName(domain);
	const parentZone = parentZoneOf(hostname);
	const recursiveQuery = dependencies.recursiveQuery ?? defaultRecursiveQuery;
	const directQuery = dependencies.directQuery ?? directDnsQuery;
	const errors: string[] = [];

	let parentNameservers: string[] = [];
	try {
		parentNameservers = uniqueSorted(await recursiveQuery(parentZone, 'NS'));
	} catch {
		errors.push('parent_ns_lookup_failed');
	}

	const parentObservations = await Promise.all(
		parentNameservers
			.slice(0, MAX_PARENT_NAMESERVERS)
			.map((nameserver) => observeParent(nameserver, hostname, directQuery)),
	);
	const parentDelegationNs = uniqueSorted(parentObservations.flatMap((observation) => observation.delegationNs ?? []));
	if (parentNameservers.length === 0) errors.push('parent_nameservers_unavailable');
	if (parentObservations.length > 0 && parentDelegationNs.length === 0) errors.push('parent_delegation_unavailable');

	const childObservations = await Promise.all(
		parentDelegationNs
			.slice(0, MAX_CHILD_NAMESERVERS)
			.map((nameserver) => observeChild(nameserver, hostname, directQuery)),
	);
	const glue = await Promise.all(
		parentDelegationNs
			.filter((nameserver) => isInBailiwick(nameserver, hostname))
			.slice(0, MAX_CHILD_NAMESERVERS)
			.map((nameserver) => observeGlue(nameserver, parentObservations, recursiveQuery)),
	);

	return {
		hostname,
		parentZone,
		checkedAt: (dependencies.now?.() ?? new Date()).toISOString(),
		parentNameservers,
		parentDelegationNs,
		parentObservations,
		childObservations,
		glue,
		...(errors.length > 0 ? { errors } : {}),
	};
}
