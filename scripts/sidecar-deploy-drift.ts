// SPDX-License-Identifier: BUSL-1.1

/**
 * Sidecar deploy-drift decision core (#945).
 *
 * `npm run deploy:prod` deploys exactly ONE Worker: the MCP Worker, from
 * `wrangler.production.jsonc`. The repo also ships two sidecar Workers that are
 * deployed from their own configs by their own commands — and until #945 no
 * root script, workflow, checklist or CI job invoked either of them. The result
 * is the classic silent-drift shape: every deploy signal is green while a
 * sidecar keeps serving months-old code.
 *
 * Measured on 2026-09-09, before this gate existed:
 *
 *   bv-whois        last deployed 2026-05-20T22:01:09Z — 4 newer commits under
 *                   `packages/bv-whois/src`, the oldest being 9c170b0d (#526),
 *                   which added the WHOIS-sourced dates the shim is supposed to
 *                   return. The RDAP fallback path had been calling a shim that
 *                   could not answer the question for ~3 months.
 *   bv-infra-probe  last deployed 2026-05-20T21:27:44Z, likewise stale.
 *
 * The operator decision was a FAIL-CLOSED BLOCKING gate, not a warning: a
 * warning printed mid-`&&`-chain is exactly what the existing green-but-stale
 * signals already looked like.
 *
 * This module is deliberately PURE — no `node:*` imports, not even a lazy one.
 * The verdict logic is unit-tested from `test/sidecar-deploy-drift.spec.ts`,
 * which runs in the default Workers pool where `node:child_process` is not real
 * and importing it is a hard SIGSEGV rather than a catchable error. All process
 * and git I/O lives in the sibling CLI, `scripts/ci/sidecar-deploy-drift-check.ts`.
 * Same split, same reason, as `scripts/deploy-freshness.ts`.
 */

/** A Worker in this repo that `deploy:prod` does NOT deploy. */
export interface SidecarTarget {
	/** Wrangler `name` of the deployed Worker. Must match the config's `name`. */
	worker: string;
	/** Repo-relative Wrangler config, passed to `wrangler deployments list --config`. */
	configPath: string;
	/**
	 * Repo-relative paths whose commits constitute this Worker's source. A commit
	 * touching any of them that is newer than the live deployment is drift.
	 */
	watchPaths: string[];
	/** The command that resolves the drift. Printed verbatim in the block message. */
	deployCommand: string;
}

/**
 * Every Worker in this repo other than the main MCP Worker.
 *
 * Kept as data, not prose, so `test/audits/sidecar-deploy-drift-check.node.test.ts`
 * can prove on disk that (a) each config exists, (b) its `name` matches `worker`,
 * and (c) no tracked `wrangler*.jsonc` naming a non-main Worker is missing from
 * this list — a THIRD sidecar added later cannot be silently omitted.
 */
export const SIDECAR_TARGETS: readonly SidecarTarget[] = [
	{
		worker: 'bv-whois',
		configPath: 'packages/bv-whois/wrangler.jsonc',
		watchPaths: ['packages/bv-whois/src'],
		deployCommand: 'npm run deploy:whois',
	},
	{
		worker: 'bv-infra-probe',
		configPath: 'wrangler.infra-probe.jsonc',
		// The entrypoint plus the module tree it bundles. `authoritative-dns-infra`
		// is shared with the main Worker, which is precisely why it belongs here:
		// a change there ships to the MCP Worker on the next `deploy:prod` and to
		// the probe never, which is the drift this gate exists to catch.
		watchPaths: ['src/workers/infra-probe.ts', 'src/lib/authoritative-dns-infra'],
		deployCommand: 'npm run deploy:infra-probe',
	},
];

/** The Wrangler `name` of the Worker `deploy:prod` DOES deploy — excluded from the sidecar set. */
export const MAIN_WORKER_NAME = 'bv-dns-security-mcp';

/** One sidecar's measured state. Built by the CLI, consumed by `assessSidecarDrift`. */
export interface SidecarProbe {
	target: SidecarTarget;
	/** Epoch ms of the newest live deployment, or null when it could not be read. */
	deployedAtMs: number | null;
	/** `sha\tcommitterDateISO\tsubject` rows newer than the deployment. */
	driftCommits: string[];
	/** Non-null means the probe did not produce a trustworthy answer — BLOCK. */
	unverifiedReason: string | null;
}

export type SidecarDriftCode = 'fresh' | 'drifted' | 'unverified' | 'override';

export interface SidecarDriftVerdict {
	/** False means: do not deploy. The CLI exits non-zero. */
	ok: boolean;
	code: SidecarDriftCode;
	message: string;
}

/**
 * Deliberately DISTINCT from `BV_ALLOW_STALE_DEPLOY`.
 *
 * Bypassing the git-freshness gate to perform an intentional rollback is a
 * completely different decision from accepting a stale sidecar. One variable
 * covering both would mean every deliberate rollback silently also waved
 * through however many months of undeployed sidecar code.
 */
export const SIDECAR_OVERRIDE_ENV = 'BV_ALLOW_STALE_SIDECARS';

/**
 * Read the newest deployment timestamp out of `wrangler deployments list --json`.
 *
 * ⚠️ The array is ASCENDING by `created_on` — the newest deployment is the LAST
 * element. A `[0]` read takes the OLDEST (for bv-whois, 2026-05-14, seven
 * deployments before the live one) and would report drift forever. This takes
 * the max rather than trusting the ordering at all.
 *
 * EVERY rejection throws, and the caller maps a throw to `unverified` → BLOCK.
 * That matters because the failure modes here do not look like failures:
 *
 * - With a bad/expired API token, wrangler exits 1 but still prints ~199 bytes
 *   of non-JSON banner text ("📎 It looks like you are authenticating Wrangler
 *   via a custom API token…") on STDOUT. Parsing stdout without a status check
 *   plus this parse guard turns an auth failure into a crash or, worse, a pass.
 * - An EMPTY array is NOT "no drift". A Worker that has never been deployed is
 *   maximally drifted, and an empty list is also what a wrong/renamed config
 *   would produce. It blocks.
 */
export function parseNewestDeployment(stdout: string): number {
	let parsed: unknown;
	try {
		parsed = JSON.parse(stdout);
	} catch {
		const preview = stdout.trim().slice(0, 120);
		throw new Error(
			`\`wrangler deployments list --json\` did not return JSON (likely an auth banner or an error): ${preview || '<empty output>'}`,
		);
	}
	if (!Array.isArray(parsed)) {
		throw new Error(`\`wrangler deployments list --json\` returned ${typeof parsed}, expected an array of deployments`);
	}
	if (parsed.length === 0) {
		throw new Error(
			'`wrangler deployments list --json` returned an EMPTY deployment list — this is NOT evidence of freshness (a never-deployed or misnamed Worker looks identical)',
		);
	}
	let newestMs = Number.NEGATIVE_INFINITY;
	for (const row of parsed) {
		const createdOn = (row as { created_on?: unknown } | null)?.created_on;
		const ms = typeof createdOn === 'string' ? Date.parse(createdOn) : Number.NaN;
		if (Number.isNaN(ms)) {
			throw new Error(`deployment record has a missing or unparseable created_on: ${JSON.stringify(createdOn ?? null)}`);
		}
		if (ms > newestMs) newestMs = ms;
	}
	return newestMs;
}

/**
 * Keep the `git log --format=%H%x09%cI%x09%s` rows committed STRICTLY after the
 * deployment. A commit whose timestamp equals the deployment's is not drift —
 * it is the commit that was deployed.
 *
 * Blank rows are dropped (an empty log is "no drift", not one blank commit); a
 * non-blank row whose date will not parse THROWS, because silently dropping it
 * would under-report drift, which is the direction this gate must never fail in.
 */
export function selectCommitsAfter(rows: string[], deployedAtMs: number): string[] {
	const kept: string[] = [];
	for (const row of rows) {
		const line = row.trim();
		if (line === '') continue;
		const parts = line.split('\t');
		const ms = parts.length >= 2 ? Date.parse(parts[1] ?? '') : Number.NaN;
		if (Number.isNaN(ms)) {
			throw new Error(`git log row has a missing or unparseable committer date: ${JSON.stringify(line.slice(0, 120))}`);
		}
		if (ms > deployedAtMs) kept.push(line);
	}
	return kept;
}

function formatCommit(row: string): string {
	const [sha = '', date = '', ...subject] = row.split('\t');
	return `    ${sha.slice(0, 8)}  ${date}  ${subject.join('\t')}`;
}

function describeProbe(probe: SidecarProbe): string[] {
	const lines = [`  ${probe.target.worker} (${probe.target.configPath})`];
	if (probe.unverifiedReason) lines.push(`    ! could not verify: ${probe.unverifiedReason}`);
	if (probe.deployedAtMs !== null) lines.push(`    live deployment: ${new Date(probe.deployedAtMs).toISOString()}`);
	if (probe.driftCommits.length > 0) {
		lines.push(`    ${probe.driftCommits.length} newer commit(s) under ${probe.target.watchPaths.join(', ')}:`);
		for (const row of probe.driftCommits) lines.push(formatCommit(row));
	}
	lines.push(`    fix: ${probe.target.deployCommand}`);
	return lines;
}

/**
 * Decide whether the sidecar Workers are current enough to let a deploy proceed.
 *
 * Fail-CLOSED by construction: the only paths that return `ok: true` are a set
 * of probes that ALL verified clean, and an explicit operator override. Anything
 * unproven blocks — an `unverified` result is not evidence that the sidecars are
 * current, it is the absence of evidence either way.
 */
export function assessSidecarDrift(probes: SidecarProbe[], allowStale: boolean): SidecarDriftVerdict {
	const unverified = probes.filter((p) => p.unverifiedReason !== null);
	const drifted = probes.filter((p) => p.unverifiedReason === null && p.driftCommits.length > 0);

	// Checked FIRST, matching `deploy-freshness.ts`, so the escape hatch also
	// covers an unverifiable probe — an operator deploying offline must not be
	// stranded by a gate that cannot reach the Cloudflare API.
	if (allowStale) {
		const detail =
			unverified.length > 0 || drifted.length > 0
				? [...unverified, ...drifted].flatMap(describeProbe)
				: ['  all sidecars verified current'];
		return {
			ok: true,
			code: 'override',
			message: [
				`${SIDECAR_OVERRIDE_ENV}=1 — sidecar deploy-drift gate bypassed. Bypassing:`,
				...detail,
				'',
				'The sidecar Workers above are NOT being deployed by this run.',
			].join('\n'),
		};
	}

	if (probes.length === 0) {
		return {
			ok: false,
			code: 'unverified',
			message: [
				'DEPLOY BLOCKED — the sidecar deploy-drift gate probed nothing.',
				'',
				'An empty probe set is a broken gate, not a clean result.',
				'',
				`Deliberate bypass: ${SIDECAR_OVERRIDE_ENV}=1 npm run deploy:prod`,
			].join('\n'),
		};
	}

	if (unverified.length > 0) {
		return {
			ok: false,
			code: 'unverified',
			message: [
				`DEPLOY BLOCKED — could not verify ${unverified.length} sidecar Worker(s) against their live deployments.`,
				'',
				'This gate does not guess. `wrangler deployments list` failing (bad or',
				'expired token, offline, wrangler missing) prints an auth banner on STDOUT',
				'that is not JSON — reading it as "no drift" is exactly the false-clean',
				'signal this gate exists to remove.',
				'',
				...unverified.flatMap(describeProbe),
				...(drifted.length > 0 ? ['', 'Also drifted:', ...drifted.flatMap(describeProbe)] : []),
				'',
				'Fix: restore Cloudflare auth / network access and re-run. An unverified',
				'result is NOT proof the sidecars are current.',
				`Deliberate bypass: ${SIDECAR_OVERRIDE_ENV}=1 npm run deploy:prod`,
			].join('\n'),
		};
	}

	if (drifted.length > 0) {
		const total = drifted.reduce((n, p) => n + p.driftCommits.length, 0);
		return {
			ok: false,
			code: 'drifted',
			message: [
				`DEPLOY BLOCKED — ${drifted.length} sidecar Worker(s) are behind their source by ${total} commit(s).`,
				'',
				'`deploy:prod` deploys the MCP Worker ONLY. The Workers below have their',
				'own configs and their own deploy commands; nothing else invokes them, so',
				'their drift is invisible in an otherwise-green deploy (#945: bv-whois ran',
				'4 source commits stale for 3 months, including the commit that added the',
				'WHOIS dates the RDAP fallback asks it for).',
				'',
				...drifted.flatMap(describeProbe),
				'',
				'Fix: run the command(s) above, then re-run the deploy.',
				`Deliberate bypass: ${SIDECAR_OVERRIDE_ENV}=1 npm run deploy:prod`,
			].join('\n'),
		};
	}

	return {
		ok: true,
		code: 'fresh',
		message: `Sidecar deploy-drift OK — ${probes.map((p) => p.target.worker).join(', ')} are at or ahead of their newest source commit.`,
	};
}
