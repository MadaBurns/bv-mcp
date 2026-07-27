// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the deploy-freshness decision core.
 *
 * Imports ONLY `scripts/deploy-freshness.ts`, which is pure by design. The CLI
 * that performs git I/O lives in `scripts/ci/deploy-freshness-check.ts` and is
 * deliberately NOT imported here: this spec runs in the default Workers pool,
 * where `node:child_process` is not real and importing it is a hard SIGSEGV
 * rather than a catchable failure (see the exclude block in vitest.config.mts).
 *
 * The gate is fail-CLOSED, so the cases that matter most are the ones that must
 * NOT return ok — a false pass here reproduces the 2026-07-27 incident where a
 * green deploy shipped code three merges out of date.
 */

import { describe, expect, it } from 'vitest';
import { assessDeployFreshness, parseMissingCommits } from '../scripts/deploy-freshness';

const FRESH = { missingCommits: [], upstreamUnverified: false, allowStale: false };

describe('assessDeployFreshness', () => {
	it('passes when HEAD contains every upstream commit', () => {
		const v = assessDeployFreshness(FRESH);
		expect(v.ok).toBe(true);
		expect(v.code).toBe('fresh');
	});

	it('BLOCKS when commits are missing from HEAD', () => {
		const v = assessDeployFreshness({
			...FRESH,
			missingCommits: ['d966bee6 fix(discover_subdomains): replace the overclaim'],
		});
		expect(v.ok).toBe(false);
		expect(v.code).toBe('stale');
	});

	it('names every missing commit so the operator can see what would be reverted', () => {
		const commits = ['d966bee6 third', '56d86eb3 second', '4eea74fc first'];
		const v = assessDeployFreshness({ ...FRESH, missingCommits: commits });
		for (const c of commits) expect(v.message).toContain(c);
		expect(v.message).toContain('3 commit(s) behind');
	});

	it('BLOCKS when the upstream ref could not be refreshed', () => {
		// The real incident had a STALE local origin/main. Treating an
		// unverifiable upstream as fresh would let exactly that through.
		const v = assessDeployFreshness({ ...FRESH, upstreamUnverified: true });
		expect(v.ok).toBe(false);
		expect(v.code).toBe('unverified');
	});

	it('BLOCKS on an unverifiable upstream even when no commits are known to be missing', () => {
		// An empty missingCommits list is meaningless if the comparison itself
		// could not be trusted — it must not be read as evidence of freshness.
		const v = assessDeployFreshness({ missingCommits: [], upstreamUnverified: true, allowStale: false });
		expect(v.ok).toBe(false);
		expect(v.code).not.toBe('fresh');
	});

	it('the override releases a stale tree', () => {
		const v = assessDeployFreshness({ ...FRESH, missingCommits: ['abc1234 x'], allowStale: true });
		expect(v.ok).toBe(true);
		expect(v.code).toBe('override');
	});

	it('the override also releases an unverifiable upstream (offline deploys)', () => {
		const v = assessDeployFreshness({ ...FRESH, upstreamUnverified: true, allowStale: true });
		expect(v.ok).toBe(true);
		expect(v.code).toBe('override');
	});

	it('the override announces itself rather than passing silently', () => {
		const v = assessDeployFreshness({ ...FRESH, missingCommits: ['abc1234 x'], allowStale: true });
		expect(v.message).toContain('BV_ALLOW_STALE_DEPLOY');
		expect(v.message).toContain('1 commit(s) missing');
	});

	it('every blocking verdict tells the operator how to fix it', () => {
		for (const input of [
			{ ...FRESH, missingCommits: ['abc1234 x'] },
			{ ...FRESH, upstreamUnverified: true },
		]) {
			const v = assessDeployFreshness(input);
			expect(v.ok).toBe(false);
			expect(v.message).toContain('BV_ALLOW_STALE_DEPLOY');
			expect(v.message.length).toBeGreaterThan(80);
		}
	});

	it('ONLY a proven-fresh tree or an explicit override may pass', () => {
		// Exhaustive over the input space: any ok verdict must be one of the two
		// sanctioned codes. Pins the fail-closed property against future edits.
		for (const missingCommits of [[], ['abc1234 x']]) {
			for (const upstreamUnverified of [false, true]) {
				for (const allowStale of [false, true]) {
					const v = assessDeployFreshness({ missingCommits, upstreamUnverified, allowStale });
					if (v.ok) {
						expect(allowStale || (missingCommits.length === 0 && !upstreamUnverified)).toBe(true);
						expect(['fresh', 'override']).toContain(v.code);
					}
				}
			}
		}
	});
});

describe('parseMissingCommits', () => {
	it('reads an empty log as nothing missing, not as one blank commit', () => {
		// The critical case: misreading '' as a single entry would block every
		// deploy from a perfectly fresh checkout.
		for (const empty of ['', '\n', '  \n  \n']) {
			expect(parseMissingCommits(empty)).toEqual([]);
			expect(assessDeployFreshness({ ...FRESH, missingCommits: parseMissingCommits(empty) }).ok).toBe(true);
		}
	});

	it('parses real git --oneline output, preserving order and subject text', () => {
		const stdout = 'd966bee6 fix(discover_subdomains): replace the overclaim\n56d86eb3 ci(hygiene): reject ANY tracked symlink\n';
		expect(parseMissingCommits(stdout)).toEqual([
			'd966bee6 fix(discover_subdomains): replace the overclaim',
			'56d86eb3 ci(hygiene): reject ANY tracked symlink',
		]);
	});
});
