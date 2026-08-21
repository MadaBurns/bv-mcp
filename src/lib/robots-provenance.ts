// SPDX-License-Identifier: BUSL-1.1

/**
 * Per-check robots.txt provenance collector (issue #745).
 *
 * `withRobotsGate` is fail-open on any unusable robots.txt — a defensible
 * policy, and one this module does NOT change. What it changes is that the
 * decision is now recorded: a scan whose `ssl`/`http_security` categories were
 * scored because the target's robots.txt happened to 502 inside a 3s window is
 * no longer indistinguishable from one that read a real "you may crawl this"
 * policy. The two produce different `metadata.robotsResolution` stamps.
 *
 * Score-neutral by construction: this module emits no `Finding`, touches no
 * severity, and writes only to `CheckResult.metadata`, which nothing in the
 * scoring path reads.
 */

import type { CheckResult, RobotsResolution, RobotsResolutionRecord } from '@blackveil/dns-checks';

/**
 * The stamp written to `CheckResult.metadata.robotsResolution`.
 *
 * Deliberately one summary object rather than the raw per-request log: a check
 * issues several gated requests (HTTPS, the plain-HTTP redirect probe, redirect
 * hops), and for reproducibility what matters is the policy decision that
 * governed the domain under test, not each hop.
 */
export interface RobotsResolutionStamp {
	/** Hostname whose robots.txt governed the decision. */
	host: string;
	/** Which branch of the gate fired. */
	resolution: RobotsResolution;
	/**
	 * True when the policy could not be read and the check probed anyway. A
	 * consumer comparing two scans of one domain should treat a difference here
	 * as "these results are not comparable", not as a posture change.
	 */
	failOpen: boolean;
	/** HTTP status of the robots.txt fetch, when one was received. */
	status?: number;
	/** Which robots.txt group applied to us, when a policy was read. */
	scope?: RobotsResolutionRecord['scope'];
	/** `error.name` of the failed robots.txt fetch, on the fail-open branches. */
	errorName?: string;
	/** Hostnames beyond `host` that were also gated (redirect targets), if any. */
	otherHosts?: string[];
}

/** A collector handed to `withRobotsGate` for one check invocation. */
export interface RobotsProvenance {
	/** Pass as `onRobotsResolution`. */
	onResolution: (record: RobotsResolutionRecord) => void;
	/** Non-mutating: returns the summary, or `undefined` when no request was gated. */
	summarize: () => RobotsResolutionStamp | undefined;
	/**
	 * Return `result` with `metadata.robotsResolution` attached. Returns the same
	 * object reference untouched when nothing was gated (an abstention that never
	 * issued a request, a check that only read DNS), so opting in costs nothing.
	 */
	stamp: <T extends CheckResult>(result: T) => T;
}

/**
 * Create a provenance collector for one check invocation on `domain`.
 *
 * `domain` selects which record becomes the summary: the first record for the
 * domain under test wins over a redirect target's host, because that is the
 * policy the caller reasoned about. Absent any record for `domain` (e.g. the
 * only gated request was to `mta-sts.<domain>`), the first record wins.
 */
export function createRobotsProvenance(domain: string): RobotsProvenance {
	const records: RobotsResolutionRecord[] = [];
	const seenHosts = new Set<string>();
	const target = domain.toLowerCase();

	const onResolution = (record: RobotsResolutionRecord): void => {
		// One record per host: a host's decision is memoized by the gate, so later
		// records for it are replays of the same fact.
		if (seenHosts.has(record.host)) return;
		seenHosts.add(record.host);
		records.push(record);
	};

	const summarize = (): RobotsResolutionStamp | undefined => {
		if (records.length === 0) return undefined;
		const primary = records.find((r) => r.host.toLowerCase() === target) ?? records[0]!;
		const others = records.filter((r) => r !== primary).map((r) => r.host);
		return {
			host: primary.host,
			resolution: primary.resolution,
			failOpen: primary.failOpen,
			...(primary.status !== undefined ? { status: primary.status } : {}),
			...(primary.scope ? { scope: primary.scope } : {}),
			...(primary.errorName ? { errorName: primary.errorName } : {}),
			...(others.length > 0 ? { otherHosts: others } : {}),
		};
	};

	const stamp = <T extends CheckResult>(result: T): T => {
		const summary = summarize();
		if (!summary) return result;
		return { ...result, metadata: { ...(result.metadata ?? {}), robotsResolution: summary } };
	};

	return { onResolution, summarize, stamp };
}
