#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
// $0 guard: fail if any active workflow uses a self-hosted runner or a known
// paid marketplace action. Keeps the public-repo CI/CD pipeline free.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PAID_ACTION_DENYLIST = ['MadaBurns/blackveil-dns-action'];

export function findCostViolations(fileName, content) {
	const violations = [];
	content.split('\n').forEach((line, i) => {
		const stripped = line.replace(/#.*$/, '');
		if (/runs-on:\s*\[?\s*['"]?self-hosted/.test(stripped)) {
			violations.push({ file: fileName, line: i + 1, kind: 'self-hosted-runner', text: line.trim() });
		}
		for (const action of PAID_ACTION_DENYLIST) {
			const esc = action.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
			if (new RegExp(`uses:\\s*${esc}(@|\\s|$)`).test(stripped)) {
				violations.push({ file: fileName, line: i + 1, kind: 'paid-action', text: line.trim() });
			}
		}
	});
	return violations;
}

export function scanWorkflowDir(dir) {
	const out = [];
	for (const f of readdirSync(dir).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'))) {
		out.push(...findCostViolations(f, readFileSync(join(dir, f), 'utf8')));
	}
	return out;
}

function main() {
	const dir = process.argv[2] || '.github/workflows';
	const violations = scanWorkflowDir(dir);
	if (violations.length) {
		for (const v of violations) console.error(`::error file=${dir}/${v.file},line=${v.line}::${v.kind}: ${v.text}`);
		console.error(`\n${violations.length} cost violation(s). Pipeline must stay $0 — see docs/ci-cost-posture.md.`);
		process.exit(1);
	}
	console.log('Cost guard: no self-hosted runners or paid actions. Pipeline is $0.');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
