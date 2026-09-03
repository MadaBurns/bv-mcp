// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #889 — the scanner's OWN I/O failure inside `checkMTASTS` must abstain, never score.
 *
 * Three catch paths used to convert a thrown fetch / resolver call into a SCORED finding
 * with no `checkStatus`: the policy fetch (`medium` → category 85), the `_smtp._tls`
 * lookup (`low` → 95, recorded as `tlsRptChecked = true` as if measured) and the
 * `_mta-sts` lookup (`low`). None of those is an observation about the domain, and bv-web
 * consumes this package export directly — so the grade published on a named third party
 * went DOWN from zero evidence.
 *
 * The rule (CLAUDE.md "DNS-failure resilience", bv-mcp-scoring): `missingControl` =
 * "we MEASURED and the control is absent"; a probe that never reached the origin is
 * `checkStatus: 'error' | 'timeout'` + `score: 0` + `partial: true` + an `info`
 * not-assessed finding, so scoring EXCLUDES the category and the transient-zero retry
 * can fire. The `CheckStatus` union is NOT widened (#743) — the reason travels in
 * finding metadata (`notAssessedReason`, `robotsAbstentionMetadata`).
 *
 * A DEFINITE negative answer is still evidence and keeps its scored finding: a non-ok
 * HTTP response on the policy URL, and an empty (NXDOMAIN/NODATA) TXT answer.
 */

import { describe, it, expect } from 'vitest';
import { checkMTASTS } from '../../checks/check-mta-sts';
import { RobotsDisallowedError } from '../../robots-gate';
import type { DNSQueryFunction, FetchFunction, Finding } from '../../types';

const STS_RECORD = 'v=STSv1; id=20240101';
const TLSRPT_RECORD = 'v=TLSRPTv1; rua=mailto:tlsrpt@example.com';
const HEALTHY_POLICY = 'version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800';
const POLICY_URL = 'https://mta-sts.example.com/.well-known/mta-sts.txt';

/** Resolver: `_mta-sts` published, TLS-RPT published, MX present; anything else empty. */
function healthyDNS(overrides: Partial<Record<string, string[] | Error>> = {}): DNSQueryFunction {
	const table: Record<string, string[] | Error> = {
		'_mta-sts.example.com': [STS_RECORD],
		'_smtp._tls.example.com': [TLSRPT_RECORD],
		'example.com': ['10 mail.example.com.'],
		...overrides,
	};
	return async (name: string) => {
		const entry = table[name];
		if (entry instanceof Error) throw entry;
		return entry ?? [];
	};
}

const okPolicy: FetchFunction = async () => new Response(HEALTHY_POLICY, { status: 200 });

function throwing(err: Error): FetchFunction {
	return async () => {
		throw err;
	};
}

function named(name: string, message = name): Error {
	const err = new Error(message);
	err.name = name;
	return err;
}

/** True when a finding would actually move the score (medium and above). */
function hasScoredDeficiency(findings: Finding[]): boolean {
	return findings.some((f) => f.severity === 'medium' || f.severity === 'high' || f.severity === 'critical');
}

function notAssessed(findings: Finding[]): Finding | undefined {
	return findings.find((f) => f.metadata?.inconclusive === true);
}

describe('checkMTASTS — scanner-side failure abstains instead of scoring the domain (#889)', () => {
	it('control: a served policy is measured and scored normally (no checkStatus, no partial)', async () => {
		const r = await checkMTASTS('example.com', healthyDNS(), { fetchFn: okPolicy });
		expect(r.checkStatus).toBeUndefined();
		expect(r.partial).toBeUndefined();
		expect(r.score).toBe(100);
		expect(r.controlPresent).toBe(true);
		expect(r.recordPresent).toBe(true);
	});

	it('policy fetch throws a generic transport error (the issue repro) → checkStatus error, score 0, partial, info only', async () => {
		const r = await checkMTASTS('example.com', healthyDNS(), { fetchFn: throwing(new Error('ECONNRESET')) });

		// The issue's observed shape: score 85, checkStatus undefined, a medium "fetch failed".
		expect(r.checkStatus).toBe('error');
		expect(r.score).toBe(0);
		expect(r.passed).toBe(false);
		expect(r.partial).toBe(true);
		expect(hasScoredDeficiency(r.findings)).toBe(false);
		expect(r.findings.some((f) => f.title === 'MTA-STS policy fetch failed')).toBe(false);

		const f = notAssessed(r.findings);
		expect(f, 'an info not-assessed finding must document the abstention').toBeDefined();
		expect(f!.severity).toBe('info');
		expect(f!.metadata?.notAssessedReason).toBe('policy_fetch_failed');
		expect(f!.metadata?.errorKind).toBe('transport_error');
		// Never both: an unmeasured probe must not also claim the control is absent (#638).
		expect(f!.metadata?.missingControl).toBeUndefined();
		expect(f!.detail).toContain(POLICY_URL);
	});

	it("policy fetch throws AbortError (the package's own AbortSignal.timeout) → checkStatus timeout", async () => {
		const r = await checkMTASTS('example.com', healthyDNS(), { fetchFn: throwing(named('AbortError', 'The operation was aborted')) });
		expect(r.checkStatus).toBe('timeout');
		expect(r.score).toBe(0);
		expect(r.partial).toBe(true);
		expect(hasScoredDeficiency(r.findings)).toBe(false);
		expect(notAssessed(r.findings)?.metadata?.errorKind).toBe('timeout');
	});

	it('policy fetch throws TimeoutError (DOMException name in workerd) → checkStatus timeout', async () => {
		const r = await checkMTASTS('example.com', healthyDNS(), { fetchFn: throwing(named('TimeoutError', 'The operation timed out')) });
		expect(r.checkStatus).toBe('timeout');
		expect(notAssessed(r.findings)?.metadata?.notAssessedReason).toBe('policy_fetch_failed');
	});

	it('the observed _mta-sts record is still credited on the policy-fetch abstention (true, never false)', async () => {
		const r = await checkMTASTS('example.com', healthyDNS(), { fetchFn: throwing(new Error('ECONNRESET')) });
		// The TXT record WAS observed; only the policy file was not fetched. `false` here
		// would assert an absence nobody measured; `undefined` would discard a measurement.
		expect(r.controlPresent).toBe(true);
		expect(r.recordPresent).toBe(true);
	});

	it('RobotsDisallowedError → labelled robots abstention (checkStatus error) using the shared vocabulary', async () => {
		const r = await checkMTASTS('example.com', healthyDNS(), { fetchFn: throwing(new RobotsDisallowedError(POLICY_URL, 'blanket')) });
		expect(r.checkStatus).toBe('error');
		expect(r.score).toBe(0);
		expect(r.partial).toBe(true);
		expect(hasScoredDeficiency(r.findings)).toBe(false);

		const f = notAssessed(r.findings);
		expect(f).toBeDefined();
		expect(f!.severity).toBe('info');
		// Same machine-readable abstention as ssl / http_security / bimi (#743).
		expect(f!.metadata?.notAssessedReason).toBe('robots_disallowed');
		expect(f!.metadata?.robotsScope).toBe('blanket');
		expect(f!.metadata?.confidence).toBe('deterministic');
		expect(f!.detail).toContain('robots.txt');
		// A blanket block must not be reported as the site naming this scanner.
		expect(f!.detail).not.toContain('BlackVeil-Security-Scanner');
	});

	it('RobotsDisallowedError with scope named says so plainly', async () => {
		const r = await checkMTASTS('example.com', healthyDNS(), { fetchFn: throwing(new RobotsDisallowedError(POLICY_URL, 'named')) });
		const f = notAssessed(r.findings)!;
		expect(f.metadata?.robotsScope).toBe('named');
		expect(f.detail).toContain('BlackVeil-Security-Scanner');
	});

	it('_smtp._tls lookup rejects → not assessed, NOT recorded as a measured TLS-RPT absence', async () => {
		const r = await checkMTASTS('example.com', healthyDNS({ '_smtp._tls.example.com': new Error('SERVFAIL') }), { fetchFn: okPolicy });

		expect(r.checkStatus).toBe('error');
		expect(r.score).toBe(0);
		expect(r.partial).toBe(true);
		expect(hasScoredDeficiency(r.findings)).toBe(false);
		// The old `low` "TLS-RPT DNS query failed" (→ 95) is gone…
		expect(r.findings.some((f) => f.title === 'TLS-RPT DNS query failed')).toBe(false);
		// …and so is any claim that TLS-RPT was looked for and found missing.
		expect(r.findings.some((f) => /TLS-RPT record missing/i.test(f.title))).toBe(false);
		expect(r.findings.some((f) => f.title === 'No MTA-STS or TLS-RPT records found')).toBe(false);

		const f = notAssessed(r.findings);
		expect(f?.severity).toBe('info');
		expect(f?.metadata?.notAssessedReason).toBe('dns_query_failed');
		expect(f?.metadata?.errorKind).toBe('dns_error');
	});

	it('_smtp._tls lookup rejects with a timeout-class error → checkStatus timeout', async () => {
		const r = await checkMTASTS('example.com', healthyDNS({ '_smtp._tls.example.com': named('TimeoutError') }), { fetchFn: okPolicy });
		expect(r.checkStatus).toBe('timeout');
	});

	it('_mta-sts lookup rejects → not assessed; recordPresent / controlPresent are undefined (unknown), never false', async () => {
		const r = await checkMTASTS('example.com', healthyDNS({ '_mta-sts.example.com': new Error('DNS timeout') }), { fetchFn: okPolicy });

		expect(r.checkStatus).toBe('error');
		expect(r.score).toBe(0);
		expect(r.passed).toBe(false);
		expect(r.partial).toBe(true);
		expect(hasScoredDeficiency(r.findings)).toBe(false);
		expect(r.findings.some((f) => f.title === 'MTA-STS DNS query failed')).toBe(false);
		expect(r.controlPresent).toBeUndefined();
		expect(r.recordPresent).toBeUndefined();

		const f = notAssessed(r.findings);
		expect(f?.severity).toBe('info');
		expect(f?.metadata?.notAssessedReason).toBe('dns_query_failed');
	});

	it('a not-assessed result never carries a low/medium/high finding derived from the failure itself', async () => {
		// Every abstention path: no finding whose title reads as a failure verdict on the domain.
		const cases: Array<Promise<Awaited<ReturnType<typeof checkMTASTS>>>> = [
			checkMTASTS('example.com', healthyDNS(), { fetchFn: throwing(new Error('boom')) }),
			checkMTASTS('example.com', healthyDNS({ '_smtp._tls.example.com': new Error('boom') }), { fetchFn: okPolicy }),
			checkMTASTS('example.com', healthyDNS({ '_mta-sts.example.com': new Error('boom') }), { fetchFn: okPolicy }),
		];
		for (const r of await Promise.all(cases)) {
			expect(r.findings.filter((f) => /query failed|fetch failed/i.test(f.title))).toHaveLength(0);
		}
	});
});

describe('checkMTASTS — a DEFINITE negative answer is still evidence (#889 boundary)', () => {
	it('HTTP 404 on the policy URL keeps the scored high "policy file not accessible" finding', async () => {
		const fetchFn: FetchFunction = async () => new Response('Not Found', { status: 404 });
		const r = await checkMTASTS('example.com', healthyDNS(), { fetchFn });
		expect(r.checkStatus).toBeUndefined();
		expect(r.partial).toBeUndefined();
		expect(r.findings.some((f) => f.title === 'MTA-STS policy file not accessible' && f.severity === 'high')).toBe(true);
		expect(notAssessed(r.findings)).toBeUndefined();
	});

	it('HTTP 5xx on the policy URL is likewise a measured negative', async () => {
		const fetchFn: FetchFunction = async () => new Response('', { status: 503 });
		const r = await checkMTASTS('example.com', healthyDNS(), { fetchFn });
		expect(r.checkStatus).toBeUndefined();
		expect(r.findings.some((f) => f.title === 'MTA-STS policy file not accessible')).toBe(true);
	});

	it('an EMPTY _smtp._tls answer (NXDOMAIN/NODATA) still yields the graded record-missing finding', async () => {
		const r = await checkMTASTS('example.com', healthyDNS({ '_smtp._tls.example.com': [] }), { fetchFn: okPolicy });
		expect(r.checkStatus).toBeUndefined();
		expect(r.partial).toBeUndefined();
		expect(r.findings.some((f) => /TLS-RPT record missing/i.test(f.title) && f.severity === 'low')).toBe(true);
		expect(r.score).toBe(95);
	});

	it('an EMPTY _mta-sts answer with MX still yields the graded absence finding (85, not zeroed, not excluded)', async () => {
		const r = await checkMTASTS('example.com', healthyDNS({ '_mta-sts.example.com': [], '_smtp._tls.example.com': [] }), {
			fetchFn: okPolicy,
		});
		expect(r.checkStatus).toBeUndefined();
		expect(r.findings.some((f) => f.title === 'No MTA-STS or TLS-RPT records found' && f.severity === 'medium')).toBe(true);
		expect(r.score).toBe(85);
		expect(r.recordPresent).toBe(false);
	});

	it('the MX-coverage sub-check keeps its silent abstention when only the MX lookup fails', async () => {
		const r = await checkMTASTS('example.com', healthyDNS({ 'example.com': new Error('SERVFAIL') }), { fetchFn: okPolicy });
		// The policy was served and parsed; a failed MX cross-check neither scores nor excludes.
		expect(r.checkStatus).toBeUndefined();
		expect(r.score).toBe(100);
		expect(r.findings.some((f) => /not covered|uncovered/i.test(f.title))).toBe(false);
	});
});

describe('checkMTASTS — a TLS-RPT sub-probe failure must not blank a DEFINITE MTA-STS measurement (#889 review)', () => {
	const policy404: FetchFunction = async () => new Response('Not Found', { status: 404 });

	it('404 policy + _smtp._tls throws → category MEASURED, the high is retained and scores, TLS-RPT rides along as an unscored info', async () => {
		const r = await checkMTASTS('example.com', healthyDNS({ '_smtp._tls.example.com': new Error('SERVFAIL') }), { fetchFn: policy404 });

		expect(r.checkStatus).toBeUndefined();
		expect(r.partial).toBeUndefined();
		expect(r.findings.some((f) => f.title === 'MTA-STS policy file not accessible' && f.severity === 'high')).toBe(true);
		// The high (−25) scores; the TLS-RPT abstention costs nothing (was −5 pre-PR, would have
		// been a whole-category blank after the first cut of this PR).
		expect(r.score).toBe(75);
		expect(r.passed).toBe(true);

		const tls = r.findings.find((f) => f.metadata?.notAssessedReason === 'dns_query_failed');
		expect(tls?.severity).toBe('info');
		expect(tls?.metadata?.inconclusive).toBe(true);
		// Never recorded as a measured absence.
		expect(r.findings.some((f) => f.title === 'TLS-RPT record missing')).toBe(false);
		expect(r.controlPresent).toBe(true);
		expect(r.recordPresent).toBe(true);
	});

	it('missing _mta-sts record (definite absence) + _smtp._tls throws → measured, graded absence retained', async () => {
		const r = await checkMTASTS(
			'example.com',
			healthyDNS({ '_mta-sts.example.com': [], '_smtp._tls.example.com': new Error('SERVFAIL') }),
			{
				fetchFn: okPolicy,
			},
		);
		expect(r.checkStatus).toBeUndefined();
		expect(r.findings.some((f) => f.title === 'No MTA-STS record found' && f.severity === 'medium')).toBe(true);
		expect(r.score).toBe(85);
		expect(r.recordPresent).toBe(false);
		// The both-missing summary needs a MEASURED TLS-RPT absence; a failed lookup is not one.
		expect(r.findings.some((f) => f.title === 'No MTA-STS or TLS-RPT records found')).toBe(false);
	});

	it('record present + policy fetch throws + TLS-RPT ok → whole-check abstention (unchanged)', async () => {
		const r = await checkMTASTS('example.com', healthyDNS(), { fetchFn: throwing(new Error('ECONNRESET')) });
		expect(r.checkStatus).toBe('error');
		expect(r.score).toBe(0);
		expect(r.partial).toBe(true);
	});

	it('record present + healthy policy (no graded finding) + _smtp._tls throws → whole-check abstention (nothing definite to keep)', async () => {
		const r = await checkMTASTS('example.com', healthyDNS({ '_smtp._tls.example.com': new Error('SERVFAIL') }), { fetchFn: okPolicy });
		expect(r.checkStatus).toBe('error');
		expect(r.score).toBe(0);
		expect(r.findings.some((f) => f.title === 'MTA-STS properly configured')).toBe(false);
	});

	it('both the policy fetch and _smtp._tls throw → abstention carrying both reasons', async () => {
		const r = await checkMTASTS('example.com', healthyDNS({ '_smtp._tls.example.com': named('TimeoutError') }), {
			fetchFn: throwing(new Error('ECONNRESET')),
		});
		expect(r.checkStatus).toBe('error');
		expect(r.score).toBe(0);
		expect(r.partial).toBe(true);
		const reasons = r.findings.filter((f) => f.metadata?.inconclusive === true).map((f) => f.metadata?.notAssessedReason);
		expect(reasons).toEqual(expect.arrayContaining(['policy_fetch_failed', 'dns_query_failed']));
		expect(hasScoredDeficiency(r.findings)).toBe(false);
	});
});
