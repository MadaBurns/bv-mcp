#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const GRADES = ['bad', 'weak', 'review', 'ok'];

function usage(message) {
	if (message) console.error(message);
	console.error('Usage: node scripts/audits/brand-report-quality-audit.mjs [--reports-dir reports] [--fail-on bad,weak,review]');
	process.exit(1);
}

function parseArgs(argv) {
	const out = { reportsDir: 'reports', failOn: new Set(['bad', 'weak', 'review']) };
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];
		if (arg === '--reports-dir') {
			out.reportsDir = argv[++i] ?? '';
		} else if (arg === '--fail-on') {
			out.failOn = new Set(
				(argv[++i] ?? '')
					.split(',')
					.map((value) => value.trim())
					.filter(Boolean),
			);
		} else {
			usage(`Unknown argument: ${arg}`);
		}
	}
	if (!out.reportsDir) usage('--reports-dir must not be empty');
	for (const grade of out.failOn) {
		if (!GRADES.includes(grade)) usage(`Unknown grade in --fail-on: ${grade}`);
	}
	return out;
}

function isObject(value) {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readJson(path) {
	try {
		return { value: JSON.parse(readFileSync(path, 'utf8')), error: null };
	} catch (error) {
		return { value: null, error: error instanceof Error ? error.message : String(error) };
	}
}

function allCandidates(sidecar) {
	const buckets = isObject(sidecar.buckets) ? sidecar.buckets : {};
	return ['consolidated', 'shadowIt', 'indeterminate', 'impersonation'].flatMap((bucket) => {
		const candidates = buckets[bucket];
		if (!Array.isArray(candidates)) return [];
		return candidates.filter(isObject).map((candidate) => ({ ...candidate, bucket }));
	});
}

function isGraphOnly(candidate) {
	const signals = Array.isArray(candidate.signals) ? candidate.signals : [];
	return signals.length === 1 && signals[0] === 'markov_gen';
}

const DETERMINISTIC_GRAPH_SIGNAL_TYPES = new Set([
	'ns',
	'dkim_key_reuse',
	'spf_include',
	'txt_verification',
	'cname_alignment',
	'cert_fingerprint',
	'cert_san',
	'http_redirect',
	'dmarc_rua',
]);

function graphEvidenceClears(candidate) {
	const evidence = candidate.graphEvidence;
	if (!isObject(evidence)) return false;
	const signalTypes = Array.isArray(evidence.signalTypes)
		? evidence.signalTypes.filter((value) => typeof value === 'string')
		: [];
	if (signalTypes.some((type) => DETERMINISTIC_GRAPH_SIGNAL_TYPES.has(type))) return true;
	const numSharedSignals = typeof evidence.numSharedSignals === 'number' ? evidence.numSharedSignals : 0;
	const maxSpecificity = typeof evidence.maxSpecificity === 'number' ? evidence.maxSpecificity : 0;
	return numSharedSignals >= 2 && maxSpecificity >= 0.8;
}

function hasMissingRegistrar(candidate) {
	const source = candidate.registrarSource ?? 'unknown';
	const registrar = candidate.registrar ?? 'Unknown';
	return source === 'unknown' || source === 'lookup_failed' || source === 'redacted' || source === 'notfound' || registrar === 'Unknown';
}

function pickGrade(current, next) {
	if (current === 'bad' || next === 'bad') return 'bad';
	if (current === 'review' || next === 'review') return 'review';
	if (current === 'weak' || next === 'weak') return 'weak';
	return 'ok';
}

function gradeSidecar(sidecar, file, readError) {
	if (readError || !isObject(sidecar)) {
		return {
			domain: file.replace(/-discovery-report\.json$/, ''),
			file,
			grade: 'bad',
			candidateCount: 0,
			notes: [readError ? `invalid JSON: ${readError}` : 'JSON sidecar is not an object'],
			graphOnlyCandidates: [],
			missingRegistrarCandidates: [],
		};
	}

	const candidates = allCandidates(sidecar);
	const notes = [];
	let grade = 'ok';
	if (sidecar.qaSchemaVersion !== 3 || sidecar.discoveryMode !== 'tiered') {
		grade = 'bad';
		notes.push('not tiered v3');
	}
	if (candidates.length === 0) {
		grade = pickGrade(grade, 'weak');
		notes.push('zero surfaced candidates');
	}

	const graphOnly = candidates.filter(isGraphOnly);
	if (graphOnly.length > 0) {
		const badGraphOnly = graphOnly.filter((candidate) => hasMissingRegistrar(candidate) && !graphEvidenceClears(candidate));
		grade = pickGrade(grade, badGraphOnly.length > 0 ? 'bad' : 'review');
		notes.push(`${graphOnly.length} graph-only candidate(s)`);
		if (badGraphOnly.length > 0) notes.push(`${badGraphOnly.length} graph-only candidate(s) missing registrar and deterministic graph provenance`);
	}

	const missingRegistrars = candidates.filter(hasMissingRegistrar);
	if (missingRegistrars.length > 0) notes.push(`${missingRegistrars.length} missing registrar attribution(s)`);

	return {
		domain: typeof sidecar.target === 'string' && sidecar.target.length > 0 ? sidecar.target : file.replace(/-discovery-report\.json$/, ''),
		file,
		grade,
		candidateCount: candidates.length,
		notes,
		graphOnlyCandidates: graphOnly.map((candidate) => candidate.domain).filter((domain) => typeof domain === 'string'),
		missingRegistrarCandidates: missingRegistrars.map((candidate) => candidate.domain).filter((domain) => typeof domain === 'string'),
	};
}

const args = parseArgs(process.argv.slice(2));
if (!existsSync(args.reportsDir)) usage(`Reports directory not found: ${args.reportsDir}`);

const files = readdirSync(args.reportsDir)
	.filter((file) => file.endsWith('-discovery-report.json'))
	.sort();

const results = files.map((file) => {
	const path = join(args.reportsDir, file);
	const { value, error } = readJson(path);
	return gradeSidecar(value, file, error);
});

const summary = results.reduce(
	(acc, result) => {
		acc.total++;
		acc[result.grade]++;
		return acc;
	},
	{ total: 0, bad: 0, weak: 0, review: 0, ok: 0 },
);
const errors = files.length === 0 ? [`no report sidecars found in ${args.reportsDir}`] : [];
const ok = errors.length === 0 && results.every((result) => !args.failOn.has(result.grade));

console.log(JSON.stringify({ ok, summary, errors, results }, null, 2));
if (!ok) process.exit(1);
