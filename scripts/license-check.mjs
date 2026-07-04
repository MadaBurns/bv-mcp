// SPDX-License-Identifier: BUSL-1.1
//
// Dependency-license compliance gate.
//
// Walks the PRODUCTION dependency closure (the `dependencies` — NOT
// devDependencies — of the root package.json and packages/dns-checks/package.json)
// and fails (exit 1) if any shipped package carries a non-allowlisted license.
// The shipped tree is expected to be all-permissive (MIT/Apache-2.0/BSD/ISC/…);
// our own @blackveil/* packages ship BUSL-1.1, which is allowlisted for us.
//
// Zero dependencies, plain Node ESM. Mirrors the style of
// scripts/repo-safety/scan-sensitive-surface.mjs.
//
// Usage:
//   node scripts/license-check.mjs               # checks the current repo
//   node scripts/license-check.mjs --root <dir>  # checks a different package root (fixtures/tests)
//
// Exit codes:
//   0 — every production package resolved to an allowlisted license
//   1 — one or more packages carry a missing/unknown/non-allowlisted license
//   2 — node_modules is absent (nothing installed to check)

import { existsSync, readFileSync } from 'node:fs';
import { realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

// SPDX identifiers we accept for shipped (production) dependencies.
const ALLOWLIST = new Set(
	[
		'MIT',
		'Apache-2.0',
		'BSD-2-Clause',
		'BSD-3-Clause',
		'0BSD',
		'ISC',
		'Zlib',
		'BlueOak-1.0.0',
		'CC0-1.0',
		'CC-BY-4.0',
		'Unlicense',
		'Python-2.0',
		'WTFPL',
		'MIT-0',
		'BUSL-1.1', // our own @blackveil/* packages
	].map((l) => l.toLowerCase()),
);

// --- CLI args ---------------------------------------------------------------

function parseRoot(argv) {
	const idx = argv.indexOf('--root');
	if (idx !== -1 && argv[idx + 1]) {
		return resolve(argv[idx + 1]);
	}
	return process.cwd();
}

const root = parseRoot(process.argv.slice(2));

// --- SPDX expression evaluation --------------------------------------------

/** Split `s` on top-level occurrences of `op` (paren depth 0). */
function splitTopLevel(s, op) {
	const parts = [];
	let depth = 0;
	let current = '';
	let i = 0;
	while (i < s.length) {
		const ch = s[i];
		if (ch === '(') {
			depth++;
			current += ch;
			i++;
			continue;
		}
		if (ch === ')') {
			depth--;
			current += ch;
			i++;
			continue;
		}
		// `op` already carries its surrounding spaces (e.g. ' OR ' / ' AND '),
		// so a top-level match is a real operator boundary.
		if (depth === 0 && s.startsWith(op, i)) {
			parts.push(current);
			current = '';
			i += op.length;
			continue;
		}
		current += ch;
		i++;
	}
	parts.push(current);
	return parts;
}

/** Strip one balanced enclosing pair of parens (repeatedly) plus surrounding whitespace. */
function stripOuterParens(s) {
	let str = s.trim();
	while (str.startsWith('(') && str.endsWith(')')) {
		// Confirm the leading '(' matches the trailing ')'.
		let depth = 0;
		let matches = true;
		for (let i = 0; i < str.length; i++) {
			if (str[i] === '(') depth++;
			else if (str[i] === ')') depth--;
			if (depth === 0 && i < str.length - 1) {
				matches = false;
				break;
			}
		}
		if (!matches) break;
		str = str.slice(1, -1).trim();
	}
	return str;
}

/** Is a single SPDX identifier (no operators) allowlisted? */
function isSingleAllowed(idRaw) {
	let id = stripOuterParens(idRaw).trim();
	// Drop an SPDX "or later" trailing '+', e.g. Apache-2.0+.
	if (id.endsWith('+')) id = id.slice(0, -1);
	if (!id) return false;
	return ALLOWLIST.has(id.toLowerCase());
}

/** Evaluate a full SPDX expression against the allowlist. */
function isExpressionAllowed(exprRaw) {
	const expr = stripOuterParens(exprRaw);
	if (!expr) return false;

	const orParts = splitTopLevel(expr, ' OR ');
	if (orParts.length > 1) {
		return orParts.some((p) => isExpressionAllowed(p));
	}

	const andParts = splitTopLevel(expr, ' AND ');
	if (andParts.length > 1) {
		return andParts.every((p) => isExpressionAllowed(p));
	}

	return isSingleAllowed(expr);
}

// --- package.json license extraction ---------------------------------------

/** Normalize a package.json `license`/`licenses` field to an SPDX string (or null). */
function extractLicense(pkg) {
	if (typeof pkg.license === 'string') return pkg.license;
	// Deprecated object form: { type: 'MIT', url: '...' }.
	if (pkg.license && typeof pkg.license === 'object' && typeof pkg.license.type === 'string') {
		return pkg.license.type;
	}
	// Legacy array form: [{ type: 'MIT' }, { type: 'Apache-2.0' }] → treat as OR.
	if (Array.isArray(pkg.licenses)) {
		const types = pkg.licenses.map((l) => (l && typeof l.type === 'string' ? l.type : null)).filter(Boolean);
		if (types.length > 0) return `(${types.join(' OR ')})`;
	}
	return null;
}

// --- dependency resolution --------------------------------------------------

/**
 * Resolve an installed package by walking node_modules up the directory tree
 * from `fromDir` toward the filesystem root (repo root's node_modules is in
 * that ancestor chain and acts as the hoisted main store).
 * Returns { dir, pkg } or null if not found.
 */
function resolvePackage(name, fromDir) {
	let dir = fromDir;
	for (;;) {
		const candidate = join(dir, 'node_modules', name, 'package.json');
		if (existsSync(candidate)) {
			try {
				const pkg = JSON.parse(readFileSync(candidate, 'utf8'));
				return { dir: dirname(candidate), pkg };
			} catch {
				return null;
			}
		}
		const parent = dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	return null;
}

// --- walk -------------------------------------------------------------------

if (!existsSync(join(root, 'node_modules'))) {
	console.error(`license-check: no node_modules found under ${root} — install dependencies before running the gate.`);
	process.exit(2);
}

/** Read the production `dependencies` map of a package.json at `path`, or {} if absent. */
function readProdDeps(path) {
	if (!existsSync(path)) return {};
	try {
		const pkg = JSON.parse(readFileSync(path, 'utf8'));
		return pkg.dependencies && typeof pkg.dependencies === 'object' ? pkg.dependencies : {};
	} catch {
		return {};
	}
}

// Seed queue from the root package.json and (if present) packages/dns-checks.
const seeds = [
	{ path: join(root, 'package.json'), fromDir: root, label: 'package.json' },
	{ path: join(root, 'packages/dns-checks/package.json'), fromDir: join(root, 'packages/dns-checks'), label: 'packages/dns-checks' },
];

/** @type {Array<{ name: string, fromDir: string, parent: string }>} */
const queue = [];
for (const seed of seeds) {
	const deps = readProdDeps(seed.path);
	for (const name of Object.keys(deps)) {
		queue.push({ name, fromDir: seed.fromDir, parent: seed.label });
	}
}

const visited = new Set();
const violations = [];
const warnings = [];
let checked = 0;

while (queue.length > 0) {
	const { name, fromDir, parent } = queue.shift();
	const resolved = resolvePackage(name, fromDir);

	if (!resolved) {
		// Soft warning: a declared production dep isn't installed. Skip, don't crash.
		warnings.push(`${name} (pulled in by ${parent}) — not found in node_modules, skipped`);
		continue;
	}

	// Dedupe by real path so cycles and hoisted repeats are visited once.
	let key;
	try {
		key = realpathSync(resolved.dir);
	} catch {
		key = resolved.dir;
	}
	if (visited.has(key)) continue;
	visited.add(key);

	const version = typeof resolved.pkg.version === 'string' ? resolved.pkg.version : '0.0.0';
	const license = extractLicense(resolved.pkg);

	checked++;

	if (!license || !isExpressionAllowed(license)) {
		violations.push({
			name,
			version,
			license: license || '(missing)',
			parent,
		});
	}

	// Recurse into this package's own production dependencies.
	const childDeps = resolved.pkg.dependencies && typeof resolved.pkg.dependencies === 'object' ? resolved.pkg.dependencies : {};
	for (const childName of Object.keys(childDeps)) {
		queue.push({ name: childName, fromDir: resolved.dir, parent: `${name}@${version}` });
	}
}

// --- report -----------------------------------------------------------------

if (warnings.length > 0) {
	console.warn('license-check: soft warnings (declared but not installed):');
	for (const w of warnings) {
		console.warn(`  - ${w}`);
	}
}

if (violations.length > 0) {
	console.error('license-check FAILED — non-allowlisted license(s) in the production dependency tree:');
	for (const v of violations) {
		console.error(`  - ${v.name}@${v.version} -> ${v.license}   (pulled in by ${v.parent})`);
	}
	console.error(`\n${violations.length} disallowed license(s) across ${checked} production packages.`);
	console.error('Allowlisted SPDX ids: ' + [...ALLOWLIST].join(', '));
	process.exit(1);
}

console.log(`Checked ${checked} production packages, all licenses allowlisted.`);
process.exit(0);
