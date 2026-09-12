// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the sidecar deploy-drift decision core (#945).
 *
 * Imports ONLY `scripts/sidecar-deploy-drift.ts`, which is pure by design. The
 * CLI that shells out to wrangler and git lives in
 * `scripts/ci/sidecar-deploy-drift-check.ts` and is deliberately NOT imported
 * here: this spec runs in the default Workers pool, where `node:child_process`
 * is not real and importing it is a hard SIGSEGV rather than a catchable
 * failure. Its argv contract is asserted from the Node pool instead, in
 * `test/audits/sidecar-deploy-drift-check.node.test.ts`.
 *
 * The gate is fail-CLOSED, so the cases that matter most are the ones that must
 * NOT return ok. A false pass here reproduces exactly the state #945 found:
 * bv-whois serving code 4 commits and 3 months out of date behind a wall of
 * green deploy signals.
 */

import { describe, expect, it } from 'vitest';
import {
	assessSidecarDrift,
	parseNewestDeployment,
	selectCommitsAfter,
	SIDECAR_OVERRIDE_ENV,
	SIDECAR_TARGETS,
	type SidecarProbe,
	type SidecarTarget,
} from '../scripts/sidecar-deploy-drift';

const WHOIS: SidecarTarget = SIDECAR_TARGETS[0]!;

const CLEAN: SidecarProbe = {
	target: WHOIS,
	deployedAtMs: Date.parse('2026-09-01T00:00:00Z'),
	driftCommits: [],
	unverifiedReason: null,
};

/** The literal banner wrangler prints on STDOUT alongside a non-zero exit and a bad token. */
const AUTH_BANNER =
	'\n📎 It looks like you are authenticating Wrangler via a custom API token set in an environment variable.\nPlease ensure it has the correct permissions for this operation.\n';

describe('parseNewestDeployment', () => {
	it('takes the NEWEST deployment — the LAST element, not [0]', () => {
		// ⚠️ The real `wrangler deployments list --json` array is ASCENDING by
		// created_on. Reading [0] takes the OLDEST and reports drift forever. This
		// fixture is the real measured bv-whois listing (10 rows, 2026-05-14 →
		// 2026-05-20), trimmed to its endpoints.
		const stdout = JSON.stringify([
			{ id: 'oldest', created_on: '2026-05-14T12:34:32.060018Z' },
			{ id: 'middle', created_on: '2026-05-20T20:13:02.697444Z' },
			{ id: 'newest', created_on: '2026-05-20T22:01:09.022895Z' },
		]);
		expect(parseNewestDeployment(stdout)).toBe(Date.parse('2026-05-20T22:01:09.022895Z'));
	});

	it('takes the max even if the array arrives out of order', () => {
		const stdout = JSON.stringify([{ created_on: '2026-05-20T22:01:09.022895Z' }, { created_on: '2026-05-14T12:34:32.060018Z' }]);
		expect(parseNewestDeployment(stdout)).toBe(Date.parse('2026-05-20T22:01:09.022895Z'));
	});

	it('THROWS on every non-answer rather than returning a plausible number', () => {
		// Each of these is a way the probe can fail while still producing output.
		// A throw becomes `unverified` → BLOCK; a return value would become a
		// timestamp nobody measured.
		for (const stdout of ['', '   ', AUTH_BANNER, 'null', '{}', '"[]"', '[{}]', '[{"created_on":null}]']) {
			expect(() => parseNewestDeployment(stdout), `must reject ${JSON.stringify(stdout.slice(0, 40))}`).toThrow();
		}
	});

	it('THROWS on an empty deployment list — [] is NEVER "no drift"', () => {
		// A Worker that has never been deployed is maximally drifted, and a wrong
		// or renamed config produces the same empty array. Reading it as fresh is
		// the fail-open shape this whole gate exists to remove.
		expect(() => parseNewestDeployment('[]')).toThrow(/EMPTY deployment list/);
	});

	it('THROWS on an unparseable created_on', () => {
		expect(() => parseNewestDeployment(JSON.stringify([{ created_on: 'not-a-date' }]))).toThrow(/created_on/);
	});

	it('names the offending output so the operator can tell auth failure from drift', () => {
		expect(() => parseNewestDeployment(AUTH_BANNER)).toThrow(/did not return JSON/);
	});
});

describe('selectCommitsAfter', () => {
	const T = Date.parse('2026-05-20T22:01:09.022895Z');
	const row = (iso: string, subject = 'x') => `abc1234deadbeef\t${iso}\t${subject}`;

	it('keeps only commits STRICTLY newer than the deployment', () => {
		const rows = [row('2026-09-09T13:06:46+12:00', 'newer'), row('2026-01-01T00:00:00Z', 'older')];
		expect(selectCommitsAfter(rows, T)).toEqual([rows[0]]);
	});

	it('a commit timestamped exactly AT the deployment is not drift', () => {
		// That is the commit that was deployed, not one that came after it.
		expect(selectCommitsAfter([row('2026-05-20T22:01:09.022895Z')], T)).toEqual([]);
	});

	it('reads empty and blank input as nothing missing, not as one blank commit', () => {
		for (const rows of [[], [''], ['', '  ', '\n']]) {
			expect(selectCommitsAfter(rows, T)).toEqual([]);
		}
	});

	it('THROWS on a row whose committer date will not parse', () => {
		// Silently dropping it would UNDER-report drift, the one direction this
		// gate must never fail in.
		expect(() => selectCommitsAfter(['abc1234\tnot-a-date\tsubject'], T)).toThrow(/committer date/);
		expect(() => selectCommitsAfter(['no-tabs-at-all'], T)).toThrow(/committer date/);
	});
});

describe('assessSidecarDrift', () => {
	it('passes only when every sidecar verified clean', () => {
		const v = assessSidecarDrift([CLEAN, { ...CLEAN, target: SIDECAR_TARGETS[1]! }], false);
		expect(v.ok).toBe(true);
		expect(v.code).toBe('fresh');
	});

	it('BLOCKS when a sidecar has newer source commits', () => {
		const v = assessSidecarDrift([{ ...CLEAN, driftCommits: ['abc1234\t2026-09-09T00:00:00Z\tfix: something'] }], false);
		expect(v.ok).toBe(false);
		expect(v.code).toBe('drifted');
	});

	it('BLOCKS when a probe could not be verified', () => {
		const v = assessSidecarDrift([{ ...CLEAN, deployedAtMs: null, unverifiedReason: 'bad token' }], false);
		expect(v.ok).toBe(false);
		expect(v.code).toBe('unverified');
	});

	it('BLOCKS an unverified probe even when no drift is known — absence of evidence is not evidence', () => {
		const v = assessSidecarDrift([CLEAN, { ...CLEAN, deployedAtMs: null, unverifiedReason: 'offline' }], false);
		expect(v.ok).toBe(false);
		expect(v.code).not.toBe('fresh');
	});

	it('BLOCKS on an empty probe set — a gate that measured nothing is broken, not clean', () => {
		const v = assessSidecarDrift([], false);
		expect(v.ok).toBe(false);
		expect(v.code).toBe('unverified');
	});

	it('every blocking message names the sidecar, its commits, the fix command and the override', () => {
		const drift = ['1111111aaaa\t2026-09-09T13:06:46+12:00\tfix(rdap): surface WHOIS dates (#526)'];
		for (const probe of [
			{ ...CLEAN, driftCommits: drift },
			{ ...CLEAN, driftCommits: drift, unverifiedReason: 'wrangler exited 1: bad token' },
		]) {
			const v = assessSidecarDrift([probe], false);
			expect(v.ok).toBe(false);
			expect(v.message).toContain(WHOIS.worker);
			expect(v.message).toContain(WHOIS.configPath);
			expect(v.message).toContain(WHOIS.deployCommand);
			expect(v.message).toContain('#526');
			expect(v.message).toContain(SIDECAR_OVERRIDE_ENV);
			expect(v.message.length).toBeGreaterThan(80);
		}
	});

	it('the override releases drifted sidecars but PRINTS what it is bypassing', () => {
		const v = assessSidecarDrift([{ ...CLEAN, driftCommits: ['abc1234\t2026-09-09T00:00:00Z\tfix: something'] }], true);
		expect(v.ok).toBe(true);
		expect(v.code).toBe('override');
		expect(v.message).toContain(SIDECAR_OVERRIDE_ENV);
		expect(v.message).toContain(WHOIS.worker);
		expect(v.message).toContain('fix: something');
		expect(v.message).toContain(WHOIS.deployCommand);
	});

	it('the override also releases an unverifiable probe (offline deploys)', () => {
		const v = assessSidecarDrift([{ ...CLEAN, deployedAtMs: null, unverifiedReason: 'offline' }], true);
		expect(v.ok).toBe(true);
		expect(v.code).toBe('override');
		expect(v.message).toContain('offline');
	});

	it('uses an override variable DISTINCT from the git-freshness one', () => {
		// A deliberate rollback (BV_ALLOW_STALE_DEPLOY) must not silently also wave
		// through months of undeployed sidecar code.
		expect(SIDECAR_OVERRIDE_ENV).toBe('BV_ALLOW_STALE_SIDECARS');
		expect(SIDECAR_OVERRIDE_ENV).not.toBe('BV_ALLOW_STALE_DEPLOY');
		const v = assessSidecarDrift([{ ...CLEAN, driftCommits: ['abc1234\t2026-09-09T00:00:00Z\tx'] }], false);
		expect(v.message).not.toContain('BV_ALLOW_STALE_DEPLOY');
	});

	it('ONLY a fully-verified-clean set or an explicit override may pass', () => {
		// Exhaustive over the input space, mirroring the deploy-freshness sweep.
		// Pins the fail-closed property against future edits.
		for (const driftCommits of [[], ['abc1234\t2026-09-09T00:00:00Z\tx']]) {
			for (const unverifiedReason of [null, 'probe failed']) {
				for (const allowStale of [false, true]) {
					const probe: SidecarProbe = {
						target: WHOIS,
						deployedAtMs: unverifiedReason ? null : Date.parse('2026-09-01T00:00:00Z'),
						driftCommits,
						unverifiedReason,
					};
					const v = assessSidecarDrift([probe], allowStale);
					if (v.ok) {
						expect(allowStale || (driftCommits.length === 0 && unverifiedReason === null)).toBe(true);
						expect(['fresh', 'override']).toContain(v.code);
					}
				}
			}
		}
	});
});

describe('#945 regression fixture — the real measured drift', () => {
	// Built from the numbers measured on 2026-09-09, before this gate existed.
	const DEPLOYED = '2026-05-20T22:01:09.022895Z';
	const WHOIS_COMMITS = [
		'19e41c8370d608efba4f13aac5bd3a971181694d\t2026-09-09T13:06:46+12:00\tfix(rdap): classify registry-omitted registrar as redacted (#935)',
		'a78820ab8a2b0330e74c2d1609d2b2aed49e6ee5\t2026-08-27T17:25:10+12:00\tfix(security): harden MCP trust boundaries end to end (#803)',
		'9c170b0d1d6402054cd4f98bcaf9ae91742dcb8f\t2026-07-20T15:17:39+12:00\tfix(rdap): surface WHOIS-sourced dates + registrant privacy (#526)',
		'52ab60dafdbbbba7339bf2d216d3cad9aef49b93\t2026-05-21T11:36:21+12:00\tfeat(brand-discovery): sidecar schema v4',
		// Deployed on 2026-05-20, BEFORE the live deployment — must not count.
		'ba97c0934c17e8f5dec0eb4fdc4234c199a421a2\t2026-05-20T09:24:42+12:00\tfeat(brand-audit): data-depth pipeline (#143)',
	];

	it('reproduces the exact 4-commit bv-whois drift and blocks on it', () => {
		const deployedAtMs = parseNewestDeployment(JSON.stringify([{ created_on: DEPLOYED }]));
		const driftCommits = selectCommitsAfter(WHOIS_COMMITS, deployedAtMs);
		expect(driftCommits).toHaveLength(4);

		const v = assessSidecarDrift([{ target: WHOIS, deployedAtMs, driftCommits, unverifiedReason: null }], false);
		expect(v.ok).toBe(false);
		expect(v.code).toBe('drifted');
		// #526 is the commit that added the WHOIS dates the RDAP fallback asks the
		// shim for — the concrete capability that was missing from production.
		expect(v.message).toContain('#526');
		expect(v.message).toContain('npm run deploy:whois');
		expect(v.message).not.toContain('#143');
	});
});

describe('SIDECAR_TARGETS shape', () => {
	it('covers both known sidecars with a deploy command each', () => {
		expect(SIDECAR_TARGETS.map((t) => t.worker).sort()).toEqual(['bv-infra-probe', 'bv-whois']);
		for (const target of SIDECAR_TARGETS) {
			expect(target.configPath).toMatch(/wrangler[\w.-]*\.jsonc$/);
			expect(target.watchPaths.length).toBeGreaterThan(0);
			expect(target.deployCommand).toMatch(/^npm run deploy:/);
		}
	});

	it('never names the main Worker — deploy:prod already ships that one', () => {
		expect(SIDECAR_TARGETS.map((t) => t.worker)).not.toContain('bv-dns-security-mcp');
	});
});
