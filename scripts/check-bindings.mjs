#!/usr/bin/env node
// Runs `wrangler types` (optionally against a named config) and then
// `tsc --noEmit`, WITHOUT echoing the generated Env interface to the
// terminal — that interface embeds literal `vars` values verbatim
// (#1073: this leaked plaintext config values to CI/console logs).
//
// `wrangler types` itself has no quiet/summary flag (checked: `npx wrangler
// types --help`, wrangler 4.131.1), so its stdout is captured instead of
// inheriting the terminal, and only a name/count summary is printed. stderr
// is passed through untouched so real failures (bad config, parse errors)
// still surface with a readable message and a non-zero exit. The generated
// worker-configuration.d.ts is still written to disk as usual (gitignored,
// pre-commit-blocked) for tsc and editors to consume.
import { readFileSync, realpathSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const extraArgs = process.argv.slice(2);

const SCANNER_QUEUE_NAME = 'bv-scanner-queue';

/**
 * Pure check: does the `bv-scanner-queue` consumer in the given (already
 * parsed) wrangler config declare a `dead_letter_queue`? Advisory only — a
 * missing DLQ never fails this gate, since the operator must create the
 * queue first (`npx wrangler queues create bv-scanner-dlq`, see
 * docs/tenant-ops-runbook.md's "Dead-Letter Queue Setup" subsection) before
 * the field means anything. SQ-169 measured 260/500 tenant-cycle messages
 * dropped silently past `max_retries` with no DLQ to catch them.
 *
 * No I/O — takes the parsed config object, so it is unit-testable directly.
 *
 * @param {{ queues?: { consumers?: Array<Record<string, unknown>> } } | null | undefined} config
 * @returns {{ ok: boolean, message: string | null }}
 */
export function assessScannerQueueDlq(config) {
	const consumers = config && config.queues && Array.isArray(config.queues.consumers) ? config.queues.consumers : [];
	const scannerConsumer = consumers.find((consumer) => consumer && consumer.queue === SCANNER_QUEUE_NAME);
	if (!scannerConsumer || scannerConsumer.dead_letter_queue) {
		return { ok: true, message: null };
	}
	return {
		ok: false,
		message:
			`WARNING: the ${SCANNER_QUEUE_NAME} consumer has no dead_letter_queue. A message that exhausts ` +
			'max_retries is dropped with no durable marker (SQ-169 — 260/500 messages lost this way on the ' +
			"09-13 and 09-20 tenant cycles). Create one and wire it in — see docs/tenant-ops-runbook.md's " +
			'"Dead-Letter Queue Setup" subsection.',
	};
}

/**
 * Extracts the `--config <path>` value passed through this script's own argv
 * (mirrors what gets forwarded to `wrangler types` below). Absent when the
 * default `wrangler.jsonc` is in play, which never carries queues — so the
 * DLQ check has nothing to look at and is skipped silently.
 *
 * @param {string[]} args
 * @returns {string | null}
 */
export function extractConfigPath(args) {
	const idx = args.indexOf('--config');
	return idx !== -1 && args[idx + 1] ? args[idx + 1] : null;
}

/**
 * Reads and parses `configPath` best-effort and warns (never fails) if the
 * scanner-queue consumer has no DLQ. Swallows a missing/unparseable file —
 * this check runs after `wrangler types` already validated the config, so a
 * read failure here just means "nothing to check," not a new failure mode.
 *
 * @param {string | null} configPath
 * @param {(path: string, encoding: string) => string} readFileFn
 */
export function warnIfScannerQueueMissingDlq(configPath, readFileFn = readFileSync) {
	if (!configPath) return;
	let config;
	try {
		config = JSON.parse(readFileFn(configPath, 'utf8'));
	} catch {
		return;
	}
	const verdict = assessScannerQueueDlq(config);
	if (!verdict.ok) {
		console.warn(verdict.message);
	}
}

function run(command, args, { captureStdout = false } = {}) {
	return new Promise((resolve, reject) => {
		const child = spawn(command, args, {
			stdio: [
				'inherit',
				captureStdout ? 'pipe' : 'inherit',
				'inherit', // never swallow stderr: real errors must stay visible
			],
		});
		let stdout = '';
		if (captureStdout) {
			child.stdout.on('data', (chunk) => {
				stdout += chunk.toString();
			});
		}
		child.on('error', reject);
		child.on('close', (code) => resolve({ code, stdout }));
	});
}

// Summarise the generated Env interface by name/kind only — never by value.
function summarize(dtsSource) {
	const match = dtsSource.match(/interface __BaseEnv_Env \{([\s\S]*?)\n\}/);
	const body = match ? match[1] : '';
	let vars = 0;
	let bindings = 0;
	for (const line of body.split('\n')) {
		const trimmed = line.trim();
		if (!trimmed || !trimmed.includes(':')) continue;
		if (/:\s*"/.test(trimmed)) {
			vars += 1;
		} else {
			bindings += 1;
		}
	}
	return { vars, bindings };
}

async function main() {
	const typesResult = await run('npx', ['wrangler', 'types', ...extraArgs], {
		captureStdout: true,
	});
	if (typesResult.code !== 0) {
		process.exitCode = typesResult.code ?? 1;
		return;
	}

	let summary;
	try {
		summary = summarize(readFileSync('worker-configuration.d.ts', 'utf8'));
	} catch {
		// Fall back to parsing the captured stdout if the file read fails for
		// any reason — still names/counts only, never values.
		summary = summarize(typesResult.stdout);
	}
	console.log(`bindings check: OK (${summary.vars} vars, ${summary.bindings} bindings)`);

	warnIfScannerQueueMissingDlq(extractConfigPath(extraArgs));

	const tscResult = await run('npx', ['tsc', '--noEmit']);
	process.exitCode = tscResult.code ?? 1;
}

/**
 * True when this file was invoked as the CLI entrypoint, not merely imported
 * (the audit test imports the pure `assessScannerQueueDlq`/`extractConfigPath`
 * helpers above without running `main()`'s real `wrangler types` + `tsc`
 * shell-outs as an import side effect). Same guard as
 * `scripts/ci/sidecar-deploy-drift-check.ts`'s `isInvokedDirectly`.
 */
export function isInvokedDirectly(argv1, moduleUrl, realpath = realpathSync) {
	if (!argv1) return false;
	return realpath(argv1) === fileURLToPath(moduleUrl);
}

if (isInvokedDirectly(process.argv[1], import.meta.url)) {
	main();
}
