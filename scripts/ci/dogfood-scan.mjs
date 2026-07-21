#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
// $0 dogfood DNS-security scan: runs bv-mcp's own built stdio CLI against a
// target domain and exits non-zero if the grade is below the minimum.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const DEFAULT_DOMAIN = 'blackveilsecurity.com';
const DEFAULT_MIN_GRADE = 'B';
// Union of both grade scales (9-band canonical + 6-band NIST), best → worst.
export const GRADE_ORDER = ['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'F'];

export function gradeRank(grade) {
	const i = GRADE_ORDER.indexOf(grade);
	return i === -1 ? GRADE_ORDER.length : i;
}

export function meetsMinimum(grade, minGrade) {
	return gradeRank(grade) <= gradeRank(minGrade);
}

export function parseScanResult(stdout) {
	for (const line of stdout.trim().split('\n')) {
		let msg;
		try {
			msg = JSON.parse(line);
		} catch {
			continue;
		}
		if (msg.id !== 2) continue;
		if (msg.error) throw new Error(`scan_domain error: ${msg.error.message}`);
		const sc = msg.result?.structuredContent;
		if (sc) return { score: sc.score, grade: sc.grade, maturityStage: sc.maturityStage };
	}
	throw new Error('No scan_domain result found in CLI output');
}

export function runScan(domain, { cliPath = 'dist/stdio.js', timeoutMs = 90000 } = {}) {
	return new Promise((resolve, reject) => {
		const child = spawn('node', [cliPath], { stdio: ['pipe', 'pipe', 'pipe'] });
		let out = '';
		let err = '';
		const timer = setTimeout(() => {
			child.kill('SIGKILL');
			reject(new Error(`scan timed out after ${timeoutMs}ms`));
		}, timeoutMs);
		child.stdout.on('data', (d) => (out += d));
		child.stderr.on('data', (d) => (err += d));
		child.on('error', reject);
		child.on('close', (code) => {
			clearTimeout(timer);
			if (code !== 0) return reject(new Error(`stdio CLI exited ${code}: ${err}`));
			resolve(out);
		});
		const init = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bv-load-test', version: '1.0.0' } } });
		const call = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'scan_domain', arguments: { domain, format: 'compact' } } });
		child.stdin.write(init + '\n' + call + '\n');
		child.stdin.end();
	});
}

async function main() {
	const domain = process.env.DOGFOOD_DOMAIN || DEFAULT_DOMAIN;
	const minGrade = process.env.DOGFOOD_MIN_GRADE || DEFAULT_MIN_GRADE;
	let result;
	let lastErr;
	for (let attempt = 1; attempt <= 3; attempt++) {
		try {
			result = parseScanResult(await runScan(domain));
			break;
		} catch (e) {
			lastErr = e;
			console.error(`attempt ${attempt} failed: ${e.message}`);
		}
	}
	if (!result) throw lastErr;
	console.log(`Domain: ${domain}`);
	console.log(`Score: ${result.score}`);
	console.log(`Grade: ${result.grade}`);
	console.log(`Maturity: ${result.maturityStage}`);
	if (!meetsMinimum(result.grade, minGrade)) {
		console.error(`::error::Grade ${result.grade} is below minimum ${minGrade}`);
		process.exit(1);
	}
	console.log(`PASS: ${result.grade} meets minimum ${minGrade}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	main().catch((e) => {
		console.error(`::error::${e.message}`);
		process.exit(1);
	});
}
