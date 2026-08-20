#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
// Post-deploy verification: assert the LIVE Worker serves the expected version
// AND returns a sane scan_domain score (catches a stale dns-checks bundle
// where the version is right but scoring is broken), AND that the deployed
// build actually applies the control-presence predicate a customer's CI gate
// depends on (issue #725). Uses the workers.dev origin + owner key to bypass
// the custom domain's bot challenge.
import { fileURLToPath } from 'node:url';

const WORKERS_DEV = 'https://bv-dns-security-mcp.bv-edge.workers.dev/mcp';
const SANITY_DOMAIN = 'blackveilsecurity.com';

/**
 * ── Control-predicate smoke assertion (issue #725) ────────────────────────────
 *
 * #705/#706 replaced `check.passed` with `isSatisfiedControl()` in the two
 * surfaces that publish a per-control verdict. `passed` records whether a check
 * PENALIZED the domain, not whether the control exists — so before the fix,
 * `compare_baseline` with `require_caa: true` returned PASS for domains with no
 * CAA record at all. #706 was closed on merge, which is why the tracker read as
 * fixed while prod still served the false affirmative on 2026-08-20.
 *
 * A merge-closes-issue workflow cannot catch a deploy that never ran, so the
 * post-deploy verifier asserts the PREDICATE, not merely an HTTP 200: a domain
 * whose control is verified-absent MUST produce a violation.
 *
 * WHY `require_caa`, and why this is not a bet on third-party DNS:
 *
 *  - The absence is VERIFIED IN THE SAME RUN, against the SAME deploy. We first
 *    call `check_caa` and read `recordPresent === false` (the score-neutral
 *    observational signal, documented for exactly this kind of consumer), then
 *    require `compare_baseline` to violate. So the assertion is a DIFFERENTIAL
 *    between two surfaces of one deployment — the precise shape of the #725
 *    report, where `scan_domain` said "No CAA records" while `compare_baseline`
 *    said PASS. If the probe domain publishes CAA tomorrow, the precondition
 *    fails and we SKIP LOUDLY instead of failing a correct deploy: a flaky gate
 *    gets disabled, which is worse than no gate.
 *  - `caa` is the only `require_*` control that can never be declared
 *    NOT APPLICABLE. `isCategoryNonApplicable` (tools/scan/format-report.ts)
 *    only ever N/As `dkim`/`mta_sts`/`bimi`/`mx`/`dane`/`spf`/`dmarc`, and only
 *    under a `web_only`/`non_mail` profile. Using the issue's other example,
 *    `require_mta_sts`, would put the rule in `notApplicableRules` for any
 *    non-mail probe domain → `passed: null` → an indeterminate gate that tells
 *    us nothing about the deploy.
 *  - CAA absence is a *graded* medium finding with deliberately NO
 *    `missingControl`, so the category still scores 85 and `passed` stays TRUE.
 *    That makes it a crisp discriminator: a STALE build (bare `passed`) reports
 *    no violation; any build carrying `isSatisfiedControl` reports one.
 *
 * The candidate list is RFC 2606 documentation domains — names that exist to be
 * used in exactly this way — tried in order until one is verified-absent. An
 * operator who provisions a sentinel apex deliberately kept free of CAA should
 * point `VERIFY_BASELINE_DOMAINS` at it; that is the preferred long-term form,
 * since it is the only version whose absence we control rather than observe.
 */
const BASELINE_SMOKE_RULE = 'require_caa';
const BASELINE_SMOKE_TOOL = 'check_caa';
const DEFAULT_BASELINE_SMOKE_DOMAINS = ['example.com', 'example.net', 'example.org'];

export function assertVersion(serverInfo, expected) {
	if (!serverInfo || !serverInfo.version) throw new Error('verify failed: no serverInfo in initialize response');
	if (serverInfo.version !== expected) {
		throw new Error(`verify failed: live version ${serverInfo.version}, expected ${expected}`);
	}
}

/**
 * Pure guard for the post-deploy scan_domain sanity check: throws unless
 * structuredContent carries a finite numeric score. Returns the score on success.
 */
export function assertScoreSane(structuredContent) {
	if (!structuredContent) throw new Error('verify failed: no structuredContent in scan_domain response');
	const { score } = structuredContent;
	if (typeof score !== 'number' || !Number.isFinite(score)) {
		throw new Error(`verify failed: scan_domain score is not a finite number (got ${JSON.stringify(score)})`);
	}
	return score;
}

/**
 * Is the probe domain's control VERIFIED ABSENT, present, or simply unmeasured?
 *
 * Reads the live `check_caa` CheckResult exactly the way `isSatisfiedControl`'s
 * `isUnrebuttedAbsence` clause does (src/lib/control-presence.ts): only an explicit
 * `recordPresent === false` counts as absence, and an affirmative `controlPresent`
 * REBUTS it. `undefined` means the check did not report the signal or the query
 * failed — and absence of a signal is not evidence of absence.
 *
 * `checkStatus` is consulted FIRST: a check that errored or timed out measured
 * nothing, so its metadata may not be read as a verdict either way. Returns
 * `'unmeasured'` for every such case, which the caller treats as a loud SKIP
 * rather than a failure — a transient DNS blip must never fail a good deploy.
 *
 * @returns {{ state: 'absent'|'present'|'unmeasured', reason: string }}
 */
export function classifyControlProbe(checkResult) {
	if (!checkResult || typeof checkResult !== 'object') {
		return { state: 'unmeasured', reason: `${BASELINE_SMOKE_TOOL} returned no structuredContent` };
	}
	const { checkStatus, recordPresent, controlPresent } = checkResult;
	if (checkStatus !== undefined && checkStatus !== 'completed') {
		return { state: 'unmeasured', reason: `${BASELINE_SMOKE_TOOL} checkStatus=${checkStatus} (the probe measured nothing)` };
	}
	if (controlPresent === true || recordPresent === true) {
		return {
			state: 'present',
			reason: `CAA is published for this domain (recordPresent=${recordPresent}, controlPresent=${controlPresent})`,
		};
	}
	if (recordPresent === false) {
		return { state: 'absent', reason: 'recordPresent=false and no affirmative controlPresent — CAA is definitively absent' };
	}
	return { state: 'unmeasured', reason: 'recordPresent was not reported (undefined) — absence was never observed' };
}

/**
 * Given a verified-absent control, did the LIVE `compare_baseline` produce a violation?
 *
 * Three outcomes, and the split is the whole point of the gate:
 *
 *  - `violated`      — the deployed build applies the predicate. PASS.
 *  - `stale`         — the rule was evaluated and NOT violated for a control we
 *                      just verified absent. That is the #706 false affirmative,
 *                      i.e. a build that predates the fix. HARD FAIL, fail-closed.
 *  - `indeterminate` — the rule could not be evaluated (`passed === null` /
 *                      `inconclusiveRules`), or there is no structured payload at
 *                      all. Says nothing about the deploy → warn, do not fail.
 *
 * Deliberately asserts on the violated RULE KEY only, never on the message text:
 * `unsatisfiedReason` picks between an "absent" and a "present-but-deficient"
 * wording, and a medium-severity CAA-absence finding legitimately routes to the
 * latter. Pinning prose here would fail on a correct deploy.
 *
 * @returns {{ state: 'violated'|'stale'|'indeterminate', reason: string, violation?: object }}
 */
export function classifyBaselineVerdict(baselineResult, rule = BASELINE_SMOKE_RULE) {
	if (!baselineResult || typeof baselineResult !== 'object') {
		return { state: 'indeterminate', reason: 'compare_baseline returned no structuredContent' };
	}
	const violations = Array.isArray(baselineResult.violations) ? baselineResult.violations : [];
	const inconclusive = Array.isArray(baselineResult.inconclusiveRules) ? baselineResult.inconclusiveRules : [];
	const violation = violations.find((v) => v && v.rule === rule);
	if (violation) return { state: 'violated', reason: `${rule} violated as required`, violation };
	if (inconclusive.includes(rule) || baselineResult.passed === null) {
		return {
			state: 'indeterminate',
			reason: `${rule} could not be evaluated (passed=${baselineResult.passed}, inconclusiveRules=${JSON.stringify(inconclusive)})`,
		};
	}
	return {
		state: 'stale',
		reason:
			`${rule} was evaluated and NOT violated (passed=${baselineResult.passed}) for a domain whose CAA record this same deploy reports as absent. ` +
			'That is the #706 false affirmative: the deployed build is reading `check.passed` instead of `isSatisfiedControl()`. ' +
			'A customer CI gate asserting require_caa/require_mta_sts/require_dnssec is returning GREEN for controls that do not exist.',
	};
}

async function rpcWithHeaders(baseUrl, token, body, extraHeaders = {}) {
	const res = await fetch(baseUrl, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			accept: 'application/json, text/event-stream',
			authorization: `Bearer ${token}`,
			...extraHeaders,
		},
		body: JSON.stringify(body),
	});
	const text = await res.text();
	// Response may be JSON or an SSE frame; extract the first JSON object.
	const match = text.match(/\{[\s\S]*\}/);
	if (!match) throw new Error(`non-JSON response (${res.status}): ${text.slice(0, 200)}`);
	return { json: JSON.parse(match[0]), headers: res.headers };
}

async function rpc(baseUrl, token, body, extraHeaders = {}) {
	const { json } = await rpcWithHeaders(baseUrl, token, body, extraHeaders);
	return json;
}

export async function fetchServerInfo(baseUrl, token) {
	const r = await rpc(baseUrl, token, {
		jsonrpc: '2.0',
		id: 1,
		method: 'initialize',
		params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bv-load-test', version: '1.0.0' } },
	});
	return r.result?.serverInfo;
}

/** Opens an MCP session via `initialize` and returns its `Mcp-Session-Id`. */
async function openSession(baseUrl, token) {
	const { headers } = await rpcWithHeaders(baseUrl, token, {
		jsonrpc: '2.0',
		id: 1,
		method: 'initialize',
		params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bv-load-test', version: '1.0.0' } },
	});
	const sessionId = headers.get('mcp-session-id');
	if (!sessionId) throw new Error('verify failed: no Mcp-Session-Id header on initialize response');
	return sessionId;
}

/**
 * `tools/call` on an open session → the tool's `structuredContent`.
 *
 * A JSON-RPC error or a tool-level `isError` THROWS: both mean we never obtained
 * a measurement, and the callers below classify a throw as transient (retry, then
 * skip) rather than as evidence about the deployed build.
 */
async function callTool(baseUrl, token, sessionId, name, args, id = 2) {
	const { json } = await rpcWithHeaders(
		baseUrl,
		token,
		{ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } },
		{ 'mcp-session-id': sessionId },
	);
	if (json.error) throw new Error(`${name} returned a JSON-RPC error: ${json.error.code} ${json.error.message}`);
	if (json.result?.isError) throw new Error(`${name} returned isError: ${JSON.stringify(json.result?.content)?.slice(0, 200)}`);
	return json.result?.structuredContent;
}

/**
 * Opens a session via `initialize` (capturing the `Mcp-Session-Id` response
 * header), then calls `scan_domain` against SANITY_DOMAIN with that session
 * and returns the parsed `structuredContent`.
 */
export async function fetchScanSanityStructuredContent(baseUrl, token, domain = SANITY_DOMAIN) {
	const sessionId = await openSession(baseUrl, token);
	return callTool(baseUrl, token, sessionId, 'scan_domain', { domain, format: 'compact' });
}

/**
 * Run the #725 control-predicate smoke assertion against the LIVE deployment.
 *
 * For each candidate in turn: verify the control is absent with `check_caa`, then
 * require `compare_baseline` to violate `require_caa`. The FIRST candidate that
 * yields a definite answer decides — `stale` fails closed, `violated` passes.
 * A candidate that is `present` (gained a CAA record) or `unmeasured`/transient is
 * skipped and the next one tried; exhausting the list is a loud WARNING, never a
 * failure, because it says nothing about what was deployed.
 *
 * @returns {{ state: 'violated'|'stale'|'indeterminate', domain?: string, reason: string }}
 */
export async function runControlPredicateSmoke(baseUrl, token, domains = DEFAULT_BASELINE_SMOKE_DOMAINS, log = console.error) {
	const skipped = [];
	for (const domain of domains) {
		let probe;
		try {
			const sessionId = await openSession(baseUrl, token);
			const checkResult = await callTool(baseUrl, token, sessionId, BASELINE_SMOKE_TOOL, { domain, format: 'full' }, 2);
			probe = classifyControlProbe(checkResult);
			if (probe.state !== 'absent') {
				skipped.push(`${domain}: ${probe.reason}`);
				log(`control-predicate smoke: skipping ${domain} — ${probe.reason}`);
				continue;
			}
			log(
				`control-predicate smoke: ${domain} CAA verified absent by the live deploy — asserting compare_baseline violates ${BASELINE_SMOKE_RULE}`,
			);
			const baselineResult = await callTool(
				baseUrl,
				token,
				sessionId,
				'compare_baseline',
				// require_caa ONLY: any extra rule can go inconclusive/not-applicable and
				// poison `passed` to null, turning a decisive gate into a shrug.
				{ domain, format: 'full', baseline: { [BASELINE_SMOKE_RULE]: true } },
				3,
			);
			const verdict = classifyBaselineVerdict(baselineResult, BASELINE_SMOKE_RULE);
			if (verdict.state === 'indeterminate') {
				skipped.push(`${domain}: ${verdict.reason}`);
				log(`control-predicate smoke: skipping ${domain} — ${verdict.reason}`);
				continue;
			}
			return { ...verdict, domain };
		} catch (e) {
			// Transport/tool failure — NOT evidence about the deployed build.
			skipped.push(`${domain}: transient — ${e.message}`);
			log(`control-predicate smoke: ${domain} transient failure — ${e.message}`);
		}
	}
	return {
		state: 'indeterminate',
		reason: `no candidate domain yielded a decisive answer:\n  - ${skipped.join('\n  - ')}`,
	};
}

async function main() {
	const expected = process.env.EXPECTED_VERSION;
	const token = process.env.BV_INTERNAL_DEV_KEY;
	const baseUrl = process.env.VERIFY_URL || WORKERS_DEV;
	if (!expected) throw new Error('EXPECTED_VERSION not set');
	if (!token) throw new Error('BV_INTERNAL_DEV_KEY not set');

	let serverInfo;
	for (let attempt = 1; attempt <= 6; attempt++) {
		try {
			serverInfo = await fetchServerInfo(baseUrl, token);
			if (serverInfo?.version === expected) break;
			console.error(`attempt ${attempt}: live=${serverInfo?.version ?? 'n/a'} expected=${expected} (rollout lag?)`);
		} catch (e) {
			console.error(`attempt ${attempt} error: ${e.message}`);
		}
		await new Promise((r) => setTimeout(r, 10000));
	}
	assertVersion(serverInfo, expected);
	console.log(`Verified live version ${serverInfo.version}`);

	// Scan-sanity check: a stale dns-checks bundle can serve the right version
	// while scoring is broken. Retry a few times so a transient live-DNS
	// failure doesn't fail a good deploy, but a persistent broken bundle does.
	let score;
	let lastError;
	for (let attempt = 1; attempt <= 3; attempt++) {
		try {
			const structuredContent = await fetchScanSanityStructuredContent(baseUrl, token, SANITY_DOMAIN);
			score = assertScoreSane(structuredContent);
			lastError = undefined;
			break;
		} catch (e) {
			lastError = e;
			console.error(`scan-sanity attempt ${attempt} error: ${e.message}`);
			if (attempt < 3) await new Promise((r) => setTimeout(r, 10000));
		}
	}
	if (lastError) throw lastError;
	console.log(`Verified scan_domain sanity: ${SANITY_DOMAIN} score=${score}`);

	// Control-predicate smoke assertion (issue #725). Fails CLOSED on a stale
	// deploy; a transient/inconclusive run warns instead, so a DNS blip or a probe
	// domain that has since published CAA cannot fail a correct deploy.
	const smokeDomains = (process.env.VERIFY_BASELINE_DOMAINS ?? '')
		.split(',')
		.map((d) => d.trim())
		.filter(Boolean);
	const smoke = await runControlPredicateSmoke(baseUrl, token, smokeDomains.length > 0 ? smokeDomains : DEFAULT_BASELINE_SMOKE_DOMAINS);
	if (smoke.state === 'stale') {
		throw new Error(`verify failed: control-predicate smoke on ${smoke.domain} — ${smoke.reason}`);
	}
	if (smoke.state === 'indeterminate') {
		console.log(`::warning::control-predicate smoke inconclusive (deploy NOT verified against #705/#706) — ${smoke.reason}`);
	} else {
		console.log(`Verified control predicate: compare_baseline violates ${BASELINE_SMOKE_RULE} for ${smoke.domain} (CAA verified absent)`);
	}
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	main().catch((e) => {
		console.error(`::error::${e.message}`);
		process.exit(1);
	});
}
