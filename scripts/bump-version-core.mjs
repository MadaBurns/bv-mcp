// SPDX-License-Identifier: BUSL-1.1

/**
 * Version-bump decision core (release automation).
 *
 * PURE string transforms only — no `node:*` imports, not even a lazy one. This
 * mirrors the pure/CLI split in `scripts/release-integrity.ts`: the transforms
 * live here so `test/bump-version.spec.ts` can import them directly in the
 * default Workers pool, where `node:*` built-ins are not real and importing one
 * is a hard SIGSEGV rather than a catchable failure. All file I/O (reading
 * server.json/CHANGELOG.md, writing them back, `git add`) lives in the sibling
 * CLI, `scripts/bump-version.mjs`, which nothing under `test/` imports.
 */

/** Matches server.json's single tab-indented top-level `"version"` line. server.json is tab-indented — verified with `od -c server.json`. */
const SERVER_JSON_VERSION_LINE_RE = /^(\t"version": ")([^"]*)(",)$/gm;

/**
 * Rewrite server.json's top-level `"version"` field with a plain string
 * substitution — never `JSON.parse`/`JSON.stringify`. A `JSON.stringify(obj,
 * null, '\t')` re-serialization broke the release gate for 3.40.0–3.42.0 by
 * silently reformatting the rest of the file (key order, trailing content);
 * a regex substitution touches only the one line it matches.
 *
 * Throws if the version line is absent or appears more than once — either
 * shape means this function can no longer be sure it edited the right (and
 * only the right) line.
 */
export function updateServerJsonVersion(content, newVersion) {
	const matches = content.match(SERVER_JSON_VERSION_LINE_RE);
	const count = matches ? matches.length : 0;
	if (count !== 1) {
		throw new Error(
			`server.json: expected exactly one top-level "version" line matching ${SERVER_JSON_VERSION_LINE_RE}, found ${count}`,
		);
	}
	return content.replace(SERVER_JSON_VERSION_LINE_RE, (_full, prefix, _old, suffix) => `${prefix}${newVersion}${suffix}`);
}

/** Escape a string for safe interpolation into a `RegExp` source. */
function escapeRegExp(s) {
	return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Format a `Date` as `YYYY-MM-DD` in UTC, so the result does not depend on the caller's local timezone. */
function formatDate(date) {
	const y = date.getUTCFullYear();
	const m = String(date.getUTCMonth() + 1).padStart(2, '0');
	const d = String(date.getUTCDate()).padStart(2, '0');
	return `${y}-${m}-${d}`;
}

/**
 * Insert a `## [X.Y.Z] - YYYY-MM-DD` CHANGELOG heading + stub line.
 *
 * Idempotent: if a `## [X.Y.Z]` heading for this exact version already
 * exists anywhere in the file, returns the content UNCHANGED with
 * `inserted: false` — the common case is that a developer already wrote the
 * real release notes under that heading by hand, and this function must
 * never clobber or duplicate that.
 *
 * Otherwise inserts the new heading + a stub line directly above the FIRST
 * existing `^## [` heading in the file (whatever it is — `## [Unreleased]`
 * or a prior version), leaving everything else byte-identical, and returns
 * `inserted: true` so the caller can warn that the stub needs real notes.
 */
export function insertChangelogEntry(content, version, now) {
	const versionHeadingRe = new RegExp(`^## \\[${escapeRegExp(version)}\\]`, 'm');
	if (versionHeadingRe.test(content)) {
		return { content, inserted: false };
	}

	const firstHeadingRe = /^## \[.*\]/m;
	const match = firstHeadingRe.exec(content);
	if (!match) {
		throw new Error('CHANGELOG.md: no existing "## [...]" heading found to insert above');
	}

	const date = formatDate(now);
	const entry = `## [${version}] - ${date}\n\n- TODO: fill in release notes.\n\n`;
	const insertAt = match.index;
	const newContent = content.slice(0, insertAt) + entry + content.slice(insertAt);
	return { content: newContent, inserted: true };
}
