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
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';

const extraArgs = process.argv.slice(2);

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

	const tscResult = await run('npx', ['tsc', '--noEmit']);
	process.exitCode = tscResult.code ?? 1;
}

main();
