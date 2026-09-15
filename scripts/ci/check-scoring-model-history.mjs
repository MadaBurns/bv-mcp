// SPDX-License-Identifier: BUSL-1.1

/**
 * Guards `src/lib/scoring-version.ts`'s version-history comment against the
 * #984 defect class: two PRs, each authored against a base that predated the
 * other's merge, independently claim the SAME next `SCORING_MODEL_VERSION`
 * number for DIFFERENT scoring content (#956/#958/#959 vs #971, which
 * happened to land first as commit 6e36ce59f). A conflict in this file at
 * merge time is not itself a safety net — a careless resolution (or a
 * cherry-pick that drops one side's history line while keeping its code) can
 * leave a version number silently reused, and `packages/dns-checks/package.json`
 * / `PARITY_CORPUS_VERSION` auto-merge clean whenever both branches
 * independently picked the same version string, so nothing downstream flags it.
 *
 * What this catches: a version number that reappears in the history log AFTER
 * a strictly newer version has already been logged (going backward, or
 * resurrecting a superseded number) — the shape a rebase drift or a careless
 * merge resolution produces. It also requires the exported
 * `SCORING_MODEL_VERSION` constant to equal the newest (last) logged entry, so
 * the two cannot silently diverge.
 *
 * What this does NOT catch: two entries for the SAME version placed
 * ADJACENTLY (no other version between them) are accepted as one shipped
 * batch — the existing 1.8.0 block (three PRs shipped without an intervening
 * bump: #637, #642, #643) is exactly this shape and predates this guard. A
 * merge that lands two DIFFERENT scoring changes under one brand-new version
 * number, with their history bullets placed next to each other, is therefore
 * invisible to this check — only the ORDERING invariant (a version, once
 * superseded, can never come back) is enforced, not content-uniqueness within
 * one version block. It also only reads the hand-maintained comment, so a
 * change that skips writing a history bullet at all is not detected here (the
 * PR-level `scripts/ci/check-scoring-version.mjs` gate covers that surface).
 */

const BULLET_RE = /^\s*\*\s-\s(\d+\.\d+\.\d+)\s—/gm;

/** Parse the `- X.Y.Z —` history bullet versions out of the block comment source, in document order. */
export function parseVersionHistory(source) {
	return [...source.matchAll(BULLET_RE)].map((m) => m[1]);
}

function compareSemver(a, b) {
	const pa = a.split('.').map(Number);
	const pb = b.split('.').map(Number);
	for (let i = 0; i < 3; i += 1) {
		if (pa[i] !== pb[i]) return pa[i] - pb[i];
	}
	return 0;
}

function dedupeConsecutive(versions) {
	const out = [];
	for (const version of versions) {
		if (out.length === 0 || out[out.length - 1] !== version) out.push(version);
	}
	return out;
}

/**
 * Evaluate a parsed version list (document order) against the two invariants:
 * 1. Collapsing adjacent repeats into one "block" (a batch shipped at one
 *    version), the block sequence must be strictly increasing — a version can
 *    never reappear, or go backward, once the log has moved past it.
 * 2. The current exported `SCORING_MODEL_VERSION` equals the last (newest)
 *    logged entry.
 */
export function evaluateScoringVersionHistory(versions, currentVersion) {
	const errors = [];
	if (versions.length === 0) {
		return { ok: false, errors: ['No `- X.Y.Z —` history entries found — parser or file drifted.'] };
	}

	const blocks = dedupeConsecutive(versions);
	for (let i = 1; i < blocks.length; i += 1) {
		if (compareSemver(blocks[i], blocks[i - 1]) <= 0) {
			errors.push(
				`History entry '${blocks[i]}' is not newer than the preceding block '${blocks[i - 1]}'. ` +
					'A version may repeat only the entry immediately before it (one shipped batch) — ' +
					'it can never reappear, or go backward, once the log has moved past it.',
			);
		}
	}

	const newest = versions[versions.length - 1];
	if (newest !== currentVersion) {
		errors.push(`SCORING_MODEL_VERSION is '${currentVersion}' but the newest history entry is '${newest}'.`);
	}

	return { ok: errors.length === 0, errors };
}
