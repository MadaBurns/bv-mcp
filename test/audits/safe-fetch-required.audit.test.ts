// SPDX-License-Identifier: BUSL-1.1

/**
 * SSRF backstop (SQ-70): fails when a bare, unwrapped `fetch(...)` call
 * appears in `src/` outside a documented, reviewed exception.
 *
 * bv-mcp fetches hostnames supplied by (or derived from) the domain under
 * scan. Per `bv-mcp-security-surface`: "Attacker-controlled URLs MUST use
 * `safeFetch`" (src/lib/safe-fetch.ts) — BIMI `l=`/`a=`, redirect targets,
 * anything whose host came from a scanned record. SQ-60 audited a handful of
 * call sites and found `safeFetch` correctly used, but found no CI backstop
 * against a future call site skipping it. This test is that backstop.
 *
 * What it flags: a bare identifier call `fetch(...)` — the raw global — plus
 * three evasions of that same raw global closed by SQ-81 (a follow-up from
 * SQ-76's adversarial review of this gate itself, which found no live
 * exploit of them but confirmed the detector missed all three):
 *   - `globalThis['fetch'](...)` / `self['fetch'](...)` / `window['fetch'](...)`
 *     — bracket-string access carries no `fetch(` token for the bare pattern
 *     to find.
 *   - `globalThis.fetch(...)`, `self.fetch(...)`, `window.fetch(...)` — these
 *     look like member calls but are byte-identical in behaviour to the raw
 *     global in the Workers runtime, so the member exemption below must not
 *     cover them even though it covers everything else shaped like `.fetch(`.
 *   - `const f = fetch; f(url)` — aliasing the raw global to a local name
 *     before calling it. See FETCH_ALIAS_ASSIGNMENT_PATTERN below for the
 *     documented bound on how far this one reaches.
 *
 * It does NOT flag:
 *   - `safeFetch(...)` (different identifier — already validated).
 *   - `<obj>.fetch(...)` (a MEMBER call, e.g. `env.BV_RECON.fetch(...)`,
 *     `stub.fetch(...)`, `binding.fetch(...)`) — Cloudflare service-binding
 *     calls resolve to an operator-configured internal route, never an
 *     attacker-supplied host, so they're structurally exempt without needing
 *     an ALLOWLIST entry — the `.` before `fetch(` is the whole test. This
 *     exemption does NOT cover `globalThis`/`self`/`window` (see above).
 *   - anything under `test/` — this audit only walks `src/`, so test mocks
 *     and fixtures (`global.fetch = vi.fn()`, etc.) are out of scope by
 *     construction.
 *   - a `fetch(...)` interface/method signature or the Worker/DO `fetch`
 *     entrypoint handler (`async fetch(request: Request): Promise<Response>
 *     {`) — a declaration, not a call.
 *
 * What's left after those exclusions is a bare call to the global `fetch`,
 * including through the three evasions above.
 * Every existing one has been read and classified into one of two safe
 * shapes, recorded in ALLOWLIST with a one-line reason each:
 *   - fixed/trusted host, scan input travels only in the query string or
 *     path (DoH resolvers, crt.sh, certspotter, IANA, Cloudflare's own API,
 *     bug-bounty platform APIs) — the request never resolves a
 *     scan-controlled hostname.
 *   - "first-party": the host is deterministically derived from the
 *     ALREADY-VALIDATED scanned domain itself (mta-sts.<domain>,
 *     <domain>/.well-known/..., a subdomain the check itself enumerated) —
 *     not from response content or a redirect target. This is the same
 *     dual-fetch pattern SQ-60 found in check-ssl.ts's `firstParty` ternary
 *     and check-http-security.ts's `gatedFetch`/`gatedSafeFetch` pair.
 *
 * A NEW bare fetch call fails the count check below until it's classified
 * the same way and added here — that's the point: a future raw fetch can no
 * longer land silently.
 */

import { describe, it, expect } from 'vitest';

const srcModules = import.meta.glob(['../../src/**/*.ts', '!../../src/**/*.d.ts'], {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const FILES: ReadonlyArray<readonly [string, string]> = Object.entries(srcModules)
	.map(([path, content]) => [path.replace(/^(\.\.\/)+/, ''), content] as const)
	.sort(([a], [b]) => a.localeCompare(b));

interface AllowlistEntry {
	/** Exact number of bare `fetch(` call sites expected in this file. */
	count: number;
	/** Why every one of them is safe without safeFetch. Must say WHY. */
	why: string;
}

/**
 * Explicit, reviewed exceptions. Every file with a bare `fetch(` call must
 * have an entry here, and the count must match exactly (not just "at
 * least") — a file dropping below its count means the ledger is stale and
 * should shrink too, so it can't quietly mask a NEW call site elsewhere in
 * the same file.
 */
const ALLOWLIST: Readonly<Record<string, AllowlistEntry>> = {
	'src/lib/safe-fetch.ts': {
		count: 1,
		why: "The safeFetch wrapper's own implementation: it validates the URL via validateOutboundUrl() first, then must call the underlying global fetch to make the request. This IS the safe path — nothing else may skip it.",
	},
	'src/lib/alerting.ts': {
		count: 1,
		why: 'Fallback branch used only when no BV_WEB service binding is available. webhookUrl is the operator-configured ALERT_WEBHOOK_URL — not domain- or scan-derived.',
	},
	'src/lib/dns-multi-resolver.ts': {
		count: 1,
		why: 'DoH query against a fixed resolver endpoint from the resolver list; the scanned domain travels in the query string, never as the request hostname.',
	},
	'src/lib/dns-transport.ts': {
		count: 2,
		why: 'Shared DoH transport (both the direct and semaphore-queued dispatch paths) querying fixed resolver endpoints; the domain is a query parameter, never the hostname.',
	},
	'src/lib/analytics-engine.ts': {
		count: 1,
		why: "Fixed api.cloudflare.com Analytics Engine SQL endpoint; accountId/token are operator config, not scan input.",
	},
	'src/lib/brand-audit-registrar-enrichment.ts': {
		count: 1,
		why: 'DoH MX lookup against a fixed DOH_ENDPOINT constant; the domain is a query parameter, never the hostname.',
	},
	'src/lib/provider-signature-source.ts': {
		count: 1,
		why: "Fetches the operator-configured provider-signature source URL; the caller verifies the response against an expected SHA-256, so the content is integrity-pinned even though the transport is unwrapped.",
	},
	'src/tenants/discovery/app-links-detector.ts': {
		count: 1,
		why: "First-party: fetches the scanned domain's own /.well-known/apple-app-site-association. The host is deterministically derived from the already-validated input domain, not from response content or a redirect.",
	},
	'src/tenants/discovery/bounty-scope-detector.ts': {
		count: 1,
		why: 'Fixed bug-bounty platform hosts (hackerone.com / bugcrowd.com / api.intigriti.com); the program handle is a path segment, never the hostname.',
	},
	'src/tools/check-dnssec.ts': {
		count: 1,
		why: 'DoH AD-flag confirmation against the fixed Google DoH endpoint (dns.google); the domain is a query parameter.',
	},
	'src/tools/check-http-security.ts': {
		count: 2,
		why: "First-party gatedFetch (unbudgeted + budgeted variants) issues the direct request to the already-validated scanned domain with manual redirect handling. Its sibling gatedSafeFetch (a few lines below each, wrapping safeFetch) is what actually follows redirect targets — those go through safeFetch, not here.",
	},
	'src/tools/check-mta-sts.ts': {
		count: 2,
		why: "First-party: fetches mta-sts.<domain>/.well-known/mta-sts.txt and mta-sts.<domain>/robots.txt (unbudgeted + budgeted variants). The host is deterministically derived from the already-validated scanned domain, matching check-http-security.ts's gatedFetch pattern — not content- or redirect-derived.",
	},
	'src/tools/check-nsec-walkability.ts': {
		count: 1,
		why: 'DoH probe against the fixed CLOUDFLARE_DOH_ENDPOINT constant; the probe name travels in the query string, never as the hostname.',
	},
	'src/tools/check-rdap-lookup.ts': {
		count: 1,
		why: 'Fetches the fixed IANA_BOOTSTRAP_URL constant; not domain-derived.',
	},
	'src/tools/check-ssl.ts': {
		count: 1,
		why: "SQ-60-reviewed firstParty ternary: `firstParty ? fetch(input, init) : safeFetch(input, init)`. Only the already-validated first-party host skips safeFetch; every other target on the same line routes through it.",
	},
	'src/tools/check-subdomain-takeover.ts': {
		count: 1,
		why: "First-party: fingerprint-probes a subdomain the check itself enumerated under the already-validated scanned domain, not an externally supplied redirect target.",
	},
	'src/tools/discover-subdomains.ts': {
		count: 2,
		why: 'crt.sh and api.certspotter.com certificate-transparency queries against fixed hosts; the scanned domain travels in the query string, never as the hostname.',
	},
};

/** Matches a `fetch(...)` interface member or the Worker/DO fetch handler signature — a declaration, not a call. */
const DECLARATION_PATTERN = /^(async\s+)?fetch\s*\([^)]*\)\s*:\s*Promise/;

/** Matches a bare, non-member `fetch(` call: not preceded by `.` or a word character (so `x.fetch(`, `safeFetch(`, `dohFetch(` never match). */
const BARE_FETCH_CALL_PATTERN = /(^|[^.\w])fetch\s*\(/g;

/**
 * SQ-81 gap 2: `globalThis.fetch(`, `self.fetch(`, `window.fetch(` match the
 * `.fetch(` shape the member exemption above exists for, but unlike a real
 * service binding they resolve to the same raw global as a bare `fetch(` call
 * in the Workers runtime — so they must be treated as bare, not exempt.
 */
const GLOBAL_ALIAS_FETCH_CALL_PATTERN = /(^|[^.\w])(?:globalThis|self|window)\.fetch\s*\(/g;

/**
 * SQ-81 gap 1: the same three globals accessed via bracket-string notation
 * (`globalThis['fetch'](`, `self["fetch"](`, `window['fetch'](`) carry no
 * `fetch(` token at all, so BARE_FETCH_CALL_PATTERN never sees them.
 */
const GLOBAL_BRACKET_FETCH_CALL_PATTERN = /(^|[^.\w])(?:globalThis|self|window)\s*\[\s*['"]fetch['"]\s*\]\s*\(/g;

/**
 * SQ-81 gap 3: direct local aliasing of the raw global — `const f = fetch`,
 * `let g = globalThis.fetch` — before the alias is ever called, so the call
 * site itself (`f(url)`) carries no `fetch(` token either.
 *
 * Documented bound: tracing an alias identifier through the rest of a file
 * (reassignment, calls in a different function, calls in a different file) is
 * scope analysis, not something a line-oriented regex can do — and the ticket
 * explicitly rules out adding an AST parser for this. So this pattern flags
 * the ALIAS ASSIGNMENT itself rather than trying to follow its later uses:
 * the raw global is caught at the one point it's guaranteed to appear as
 * plain text, the moment it's captured under a new name. An assignment that
 * calls immediately (`= fetch(...)`) is excluded here (negative lookahead) —
 * that's an ordinary call already caught by BARE_FETCH_CALL_PATTERN or
 * GLOBAL_ALIAS_FETCH_CALL_PATTERN above, not an aliasing evasion. Object
 * shorthand (`{ fetch }`) and destructuring aliases are NOT covered — out of
 * bound, same reasoning.
 */
const FETCH_ALIAS_ASSIGNMENT_PATTERN =
	/(^|[^.\w])(?:const|let|var)\s+\w+\s*(?::[^=]+)?=\s*(?:globalThis\.|self\.|window\.)?fetch\b(?!\s*\()/g;

/** All patterns that count as an undocumented use of the raw global fetch. */
const EVASION_PATTERNS: readonly RegExp[] = [
	BARE_FETCH_CALL_PATTERN,
	GLOBAL_ALIAS_FETCH_CALL_PATTERN,
	GLOBAL_BRACKET_FETCH_CALL_PATTERN,
	FETCH_ALIAS_ASSIGNMENT_PATTERN,
];

function isCommentLine(trimmed: string): boolean {
	return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
}

function findBareFetchCalls(content: string): Array<{ line: number; snippet: string }> {
	const hits: Array<{ line: number; snippet: string }> = [];
	const lines = content.split('\n');
	lines.forEach((line, idx) => {
		const trimmed = line.trim();
		if (isCommentLine(trimmed)) return;
		if (DECLARATION_PATTERN.test(trimmed)) return;
		for (const pattern of EVASION_PATTERNS) {
			const matches = [...line.matchAll(pattern)];
			for (const _match of matches) {
				hits.push({ line: idx + 1, snippet: line.trim().slice(0, 140) });
			}
		}
	});
	return hits;
}

describe('safe-fetch-required (audit)', () => {
	it('scans a non-trivial set of src/ files (glob sanity check)', () => {
		// Guard against a glob typo silently matching nothing, which would make
		// the assertion below vacuously pass.
		expect(FILES.length).toBeGreaterThan(300);
	});

	it('every bare fetch() call in src/ is a documented, reviewed exception', () => {
		const byFile = new Map<string, Array<{ line: number; snippet: string }>>();
		for (const [path, content] of FILES) {
			const hits = findBareFetchCalls(content);
			if (hits.length > 0) byFile.set(path, hits);
		}

		const problems: string[] = [];

		for (const [path, hits] of byFile) {
			const entry = ALLOWLIST[path];
			if (!entry) {
				problems.push(
					`${path}: ${hits.length} bare fetch() call(s) NOT in ALLOWLIST:\n` +
						hits.map((h) => `    :${h.line}  ${h.snippet}`).join('\n'),
				);
				continue;
			}
			if (hits.length !== entry.count) {
				problems.push(
					`${path}: ALLOWLIST expects ${entry.count} bare fetch() call(s), found ${hits.length}:\n` +
						hits.map((h) => `    :${h.line}  ${h.snippet}`).join('\n'),
				);
			}
		}

		for (const path of Object.keys(ALLOWLIST)) {
			if (!byFile.has(path)) {
				problems.push(`${path}: ALLOWLIST entry expects ${ALLOWLIST[path].count} bare fetch() call(s), found 0 — stale entry, remove or correct it.`);
			}
		}

		expect(
			problems,
			`safe-fetch-required audit failed:\n\n${problems.join('\n\n')}\n\n` +
				`A raw fetch() call must route through safeFetch() (src/lib/safe-fetch.ts) whenever the ` +
				`destination host can come from scan/attacker-controlled data (a redirect target, a URL ` +
				`embedded in a scanned record like BIMI's l=/a=, or anything else not already validated as ` +
				`this request's own first-party target). A call to a Cloudflare service binding ` +
				`(env.BV_RECON.fetch(...), stub.fetch(...)) is exempt automatically — no change needed.\n` +
				`If this really is a new trusted-fixed-host or first-party call site (see the file header for ` +
				`the two accepted shapes), add or correct its entry in ALLOWLIST above with a one-line reason ` +
				`for why it does not need safeFetch.`,
		).toEqual([]);
	});
});
