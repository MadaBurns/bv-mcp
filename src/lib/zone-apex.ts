// SPDX-License-Identifier: BUSL-1.1

/**
 * Zone-apex resolution for non-apex scan targets.
 *
 * A subdomain such as `mg.ii.inc` owns no NS RRset of its own — it inherits its
 * DNS posture from the zone apex (`ii.inc`). This helper walks the label tree,
 * bounded by the PSL registrable domain, to find the governing zone apex so the
 * NS/CAA/DNSSEC/MTA-STS checks can attribute posture correctly instead of firing
 * a false "missing record" finding. Resolve ONCE per scan and share the result.
 *
 * Runtime: Cloudflare Workers. Uses the worker-side PSL (`tldts`) — the shared
 * `@blackveil/dns-checks` package intentionally has no PSL dependency, so the
 * resolved `ZoneContext` is injected into its checks.
 */

import type { ZoneContext } from '@blackveil/dns-checks';
import { getRegistrableDomain } from './public-suffix';
import { queryDns, RecordType } from './dns';
import type { QueryDnsOptions } from './dns-types';

/** Hard cap on ancestor hops between the label and the registrable apex. */
const MAX_WALK_DEPTH = 8;

/**
 * Total wall-clock budget for the whole walk (own-NS query + up to
 * `MAX_WALK_DEPTH` ancestor hops). `resolveZoneApex` is called outside the
 * per-check timeout envelope in `scan-domain.ts`, so it must self-bound —
 * exceeding this resolves to `unknown` rather than hanging the scan.
 */
const WALK_BUDGET_MS = 4000;

/** Per-query timeout for each NS lookup within the walk, tighter than the
 * default `DNS_TIMEOUT_MS` (~3s + 1 retry) so a single slow/timing-out hop
 * can't eat the whole `WALK_BUDGET_MS` on its own. */
const WALK_QUERY_TIMEOUT_MS = 1500;

/** Shared `unknown`-classification result, used whenever the walk can't be
 * completed (resolver error or budget exhaustion). */
function unknownResult(label: string, floor: string): ZoneContext {
	return {
		scannedLabel: label,
		registrableDomain: floor,
		isApex: false,
		zoneApex: floor,
		apexNsRecords: [],
		delegationStatus: 'unknown',
	};
}

function normalizeNs(records: string[]): string[] {
	return records.map((r) => r.replace(/\.$/, '').toLowerCase());
}

/** Enumerate label → registrable-floor ancestors (inclusive of both ends). */
function ancestorsToFloor(label: string, floor: string): string[] {
	const chain: string[] = [];
	let current = label;
	for (let i = 0; i <= MAX_WALK_DEPTH; i += 1) {
		chain.push(current);
		if (current === floor) break;
		const dot = current.indexOf('.');
		if (dot === -1) break;
		current = current.slice(dot + 1);
	}
	return chain;
}

/**
 * Query NS records at a name. Returns `{ records }` on a clean NOERROR answer
 * (possibly empty), or `{ error: true }` on a resolver failure/timeout so the
 * caller can distinguish "no NS here" from "could not tell".
 */
async function queryNsRecords(name: string, dnsOptions?: QueryDnsOptions): Promise<{ records: string[]; error: boolean }> {
	try {
		const resp = await queryDns(name, 'NS', false, { ...dnsOptions, timeoutMs: WALK_QUERY_TIMEOUT_MS });
		const records = normalizeNs((resp.Answer ?? []).filter((a) => a.type === RecordType.NS).map((a) => a.data));
		return { records, error: false };
	} catch {
		return { records: [], error: true };
	}
}

/**
 * Resolve the governing zone apex for `domain`.
 *
 * - `apex`: the label is its own zone apex (equals the registrable domain, or
 *   owns an NS RRset). Existing check behavior applies unchanged.
 * - `inherited`: not delegated; an ancestor (<= registrable floor) owns NS.
 * - `undelegated_broken`: no NS anywhere up to the registrable apex.
 * - `unknown`: a resolver error made the classification indeterminate.
 */
export async function resolveZoneApex(domain: string, dnsOptions?: QueryDnsOptions): Promise<ZoneContext> {
	const label = domain.replace(/\.$/, '').toLowerCase();
	const floor = getRegistrableDomain(label);

	// PSL could not parse, or the label already IS the registrable apex → apex.
	// Pure, query-free short-circuit — must stay instant, so it's NOT part of the race.
	if (!floor || label === floor) {
		return {
			scannedLabel: label,
			registrableDomain: floor ?? label,
			isApex: true,
			zoneApex: label,
			apexNsRecords: [],
			delegationStatus: 'apex',
		};
	}

	const walk = async (): Promise<ZoneContext> => {
		// The label sits below the registrable floor. Does it own its own NS RRset?
		const own = await queryNsRecords(label, dnsOptions);
		if (own.error) {
			return unknownResult(label, floor);
		}
		if (own.records.length > 0) {
			// Delegated subdomain — its own zone apex. Evaluate on its own NS set.
			return {
				scannedLabel: label,
				registrableDomain: floor,
				isApex: true,
				zoneApex: label,
				apexNsRecords: own.records,
				delegationStatus: 'apex',
			};
		}

		// Not delegated — walk ancestors (excluding the label itself) up to the floor.
		const ancestors = ancestorsToFloor(label, floor).slice(1);
		for (const ancestor of ancestors) {
			const anc = await queryNsRecords(ancestor, dnsOptions);
			if (anc.error) {
				return unknownResult(label, floor);
			}
			if (anc.records.length > 0) {
				return {
					scannedLabel: label,
					registrableDomain: floor,
					isApex: false,
					zoneApex: ancestor,
					apexNsRecords: anc.records,
					delegationStatus: 'inherited',
				};
			}
		}

		// No NS anywhere up to the registrable apex — a genuine failure at the apex.
		return {
			scannedLabel: label,
			registrableDomain: floor,
			isApex: false,
			zoneApex: floor,
			apexNsRecords: [],
			delegationStatus: 'undelegated_broken',
		};
	};

	// Total-time bound: the walk can issue up to MAX_WALK_DEPTH + 1 sequential
	// NS lookups. Never let a pathological deep/timing-out target hang the
	// caller — resolve (never reject) to `unknown` past the budget.
	return Promise.race([
		walk(),
		new Promise<ZoneContext>((resolve) => {
			setTimeout(() => resolve(unknownResult(label, floor)), WALK_BUDGET_MS);
		}),
	]);
}
