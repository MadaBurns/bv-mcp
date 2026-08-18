import { describe, it, expect, afterEach, vi } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import { evaluateCompliance, formatCompliance, UNASSESSED_COMPLIANCE_CAVEAT, buildAllTransientCaveat } from '../src/tools/map-compliance';
import type { ComplianceReport } from '../src/tools/map-compliance';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse, tlsaResponse } from './helpers/dns-mock';

/** Helper to build a minimal CheckResult for compliance mapping tests. */
function makeCheckResult(category: string, passed: boolean, findings: Array<{ title: string; severity: string }> = []): CheckResult {
	return {
		category,
		passed,
		score: passed ? 100 : 0,
		findings: findings.map((f) => ({
			category,
			title: f.title,
			severity: f.severity,
			detail: '',
		})),
	} as CheckResult;
}

/** Build a full set of check results where every category passes. */
function makeAllPassing(): CheckResult[] {
	return [
		makeCheckResult('spf', true),
		makeCheckResult('dkim', true),
		makeCheckResult('dmarc', true),
		makeCheckResult('mta_sts', true),
		makeCheckResult('dane', true),
		makeCheckResult('tlsrpt', true),
		makeCheckResult('dnssec', true),
		makeCheckResult('caa', true),
		makeCheckResult('ssl', true),
		makeCheckResult('http_security', true),
		makeCheckResult('ns', true),
		makeCheckResult('mx', true),
		makeCheckResult('authoritative_dns_infra', true),
	];
}

describe('evaluateCompliance', () => {
	it('should mark all controls as pass when all checks pass', () => {
		const results = makeAllPassing();
		const report = evaluateCompliance(results, 'example.com', 95, 'A+');

		expect(report.domain).toBe('example.com');
		expect(report.score).toBe(95);
		expect(report.grade).toBe('A+');

		// Every framework should have 0 failing and 0 partial
		for (const fw of ['nist_800_177', 'pci_dss_4', 'soc2', 'cis_controls'] as const) {
			const summary = report.frameworks[fw];
			expect(summary.failing).toBe(0);
			expect(summary.partial).toBe(0);
			expect(summary.passing).toBe(summary.totalControls);
			expect(summary.percentage).toBe(100);
		}
	});

	it('should fail NIST email controls when SPF/DKIM/DMARC fail', () => {
		const results = makeAllPassing().map((r) => {
			if (r.category === 'spf' || r.category === 'dkim' || r.category === 'dmarc') {
				return makeCheckResult(r.category, false, [{ title: `${r.category.toUpperCase()} not configured`, severity: 'high' }]);
			}
			return r;
		});

		const report = evaluateCompliance(results, 'example.com', 40, 'F');
		const nist = report.frameworks.nist_800_177;

		// §4.3.1 (SPF), §4.3.2 (DKIM), §4.3.3 (DMARC) should all fail
		const spfControl = nist.mappings.find((m) => m.controlId === '§4.3.1');
		const dkimControl = nist.mappings.find((m) => m.controlId === '§4.3.2');
		const dmarcControl = nist.mappings.find((m) => m.controlId === '§4.3.3');

		expect(spfControl!.status).toBe('fail');
		expect(dkimControl!.status).toBe('fail');
		expect(dmarcControl!.status).toBe('fail');

		expect(spfControl!.relatedFindings).toContain('SPF not configured');
		expect(dkimControl!.relatedFindings).toContain('DKIM not configured');
		expect(dmarcControl!.relatedFindings).toContain('DMARC not configured');
	});

	it('should fail NIST §5.1 and mark SOC2 CC6.1 as partial when DNSSEC fails', () => {
		const results = makeAllPassing().map((r) => {
			if (r.category === 'dnssec') {
				return makeCheckResult('dnssec', false, [{ title: 'DNSSEC not enabled', severity: 'medium' }]);
			}
			return r;
		});

		const report = evaluateCompliance(results, 'example.com', 71, 'C+');

		// NIST §5.1 DNSSEC Validation — requirePass: true, single category → fail
		const dnssecControl = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§5.1');
		expect(dnssecControl!.status).toBe('fail');
		expect(dnssecControl!.relatedFindings).toContain('DNSSEC not enabled');

		// SOC2 CC6.1 — requirePass: false, categories: [spf, dkim, dmarc, dnssec]
		// 3 passing, 1 failing → partial
		const cc61 = report.frameworks.soc2.mappings.find((m) => m.controlId === 'CC6.1');
		expect(cc61!.status).toBe('partial');
	});

	it('maps authoritative DNS infra failures into DNS infrastructure controls', () => {
		const results = [
			...makeAllPassing(),
			makeCheckResult('authoritative_dns_infra', false, [{ title: 'Route leak or hijack signal observed', severity: 'critical' }]),
		];

		const report = evaluateCompliance(results, 'a.root-servers.net', 40, 'F');

		const cisDnsInfra = report.frameworks.cis_controls.mappings.find((m) => m.controlId === '12.1');
		expect(cisDnsInfra!.status).toBe('partial');
		expect(cisDnsInfra!.relatedFindings).toContain('Route leak or hijack signal observed');

		const socBoundary = report.frameworks.soc2.mappings.find((m) => m.controlId === 'CC6.6');
		expect(socBoundary!.status).toBe('partial');
		expect(socBoundary!.relatedFindings).toContain('Route leak or hijack signal observed');
	});

	it('should compute partial status for multi-category controls with mixed results', () => {
		const results = [
			makeCheckResult('spf', true),
			makeCheckResult('dkim', false, [{ title: 'DKIM missing', severity: 'high' }]),
			makeCheckResult('dmarc', true),
			makeCheckResult('mta_sts', false, [{ title: 'No MTA-STS record', severity: 'medium' }]),
			makeCheckResult('dane', false, [{ title: 'No DANE records', severity: 'low' }]),
			makeCheckResult('tlsrpt', true),
			makeCheckResult('dnssec', true),
			makeCheckResult('caa', true),
			makeCheckResult('ssl', true),
			makeCheckResult('http_security', true),
			makeCheckResult('ns', true),
		];

		const report = evaluateCompliance(results, 'mixed.com', 65, 'C');

		// PCI DSS 8.3.1 — [spf, dkim, dmarc], requirePass: false
		// 2 passing, 1 failing → partial
		const pci831 = report.frameworks.pci_dss_4.mappings.find((m) => m.controlId === '8.3.1');
		expect(pci831!.status).toBe('partial');
		expect(pci831!.relatedFindings).toContain('DKIM missing');

		// CIS 9.3 — [spf, dkim, dmarc, mta_sts], requirePass: false
		// 2 passing, 2 failing → partial
		const cis93 = report.frameworks.cis_controls.mappings.find((m) => m.controlId === '9.3');
		expect(cis93!.status).toBe('partial');

		// SOC2 CC6.7 — [ssl, mta_sts, dane], requirePass: false
		// 1 passing (ssl), 2 failing → partial
		const cc67 = report.frameworks.soc2.mappings.find((m) => m.controlId === 'CC6.7');
		expect(cc67!.status).toBe('partial');
	});

	it('should compute percentage correctly', () => {
		// NIST 800-177 has 8 controls. Make 5 pass, 3 fail.
		const results = [
			makeCheckResult('spf', true),
			makeCheckResult('dkim', true),
			makeCheckResult('dmarc', true),
			makeCheckResult('mta_sts', false, [{ title: 'Missing MTA-STS', severity: 'medium' }]),
			makeCheckResult('dane', false, [{ title: 'Missing DANE', severity: 'low' }]),
			makeCheckResult('tlsrpt', true),
			makeCheckResult('dnssec', true),
			makeCheckResult('caa', false, [{ title: 'Missing CAA', severity: 'medium' }]),
			makeCheckResult('ssl', true),
			makeCheckResult('http_security', true),
			makeCheckResult('ns', true),
		];

		const report = evaluateCompliance(results, 'pct.com', 70, 'C+');
		const nist = report.frameworks.nist_800_177;

		// 5 pass (spf, dkim, dmarc, tlsrpt, dnssec), 3 fail (mta_sts, dane, caa)
		expect(nist.passing).toBe(5);
		expect(nist.failing).toBe(3);
		expect(nist.partial).toBe(0);
		expect(nist.totalControls).toBe(8);
		expect(nist.percentage).toBe(63); // Math.round(5/8 * 100) = 63
	});

	it('should populate relatedFindings only from non-info severity findings', () => {
		const results = [
			makeCheckResult('spf', false, [
				{ title: 'SPF misconfigured', severity: 'high' },
				{ title: 'SPF note', severity: 'info' },
			]),
			makeCheckResult('dkim', true),
			makeCheckResult('dmarc', true),
			makeCheckResult('dnssec', true),
			makeCheckResult('ssl', true),
			makeCheckResult('http_security', true),
			makeCheckResult('ns', true),
			makeCheckResult('caa', true),
			makeCheckResult('mta_sts', true),
			makeCheckResult('dane', true),
			makeCheckResult('tlsrpt', true),
		];

		const report = evaluateCompliance(results, 'findings.com', 80, 'B');

		// NIST §4.3.1 SPF — should have the high finding but not info
		const spfControl = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.3.1');
		expect(spfControl!.relatedFindings).toContain('SPF misconfigured');
		expect(spfControl!.relatedFindings).not.toContain('SPF note');
	});

	it('should include all 4 frameworks in output', () => {
		const results = makeAllPassing();
		const report = evaluateCompliance(results, 'example.com', 95, 'A+');

		expect(Object.keys(report.frameworks)).toHaveLength(4);
		expect(report.frameworks.nist_800_177).toBeDefined();
		expect(report.frameworks.pci_dss_4).toBeDefined();
		expect(report.frameworks.soc2).toBeDefined();
		expect(report.frameworks.cis_controls).toBeDefined();
	});

	it('should report a control with NO check evidence as not_assessed, never as fail', () => {
		// Only provide SPF — all controls referencing other categories should reflect accordingly
		const results = [makeCheckResult('spf', true)];
		const report = evaluateCompliance(results, 'sparse.com', 20, 'F');

		// NIST §4.3.1 SPF — passes (single category, present and passing)
		const spfControl = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.3.1');
		expect(spfControl!.status).toBe('pass');

		// NIST §4.3.2 DKIM — no dkim check ran, so there is no evidence either way.
		// Reporting that as `fail` asserts a requirement was found unmet; it wasn't looked at.
		const dkimControl = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.3.2');
		expect(dkimControl!.status).toBe('not_assessed');

		// PCI 8.3.1 — [spf, dkim, dmarc], requirePass: false — only spf present and passes → partial.
		// A control with SOME evidence is still graded; only ZERO evidence abstains.
		const pci831 = report.frameworks.pci_dss_4.mappings.find((m) => m.controlId === '8.3.1');
		expect(pci831!.status).toBe('partial');

		// The framework summary drops the unassessable control from its denominator
		// rather than counting it as a failure.
		const nist = report.frameworks.nist_800_177;
		expect(nist.totalControls).toBe(8);
		expect(nist.notAssessed).toBe(7);
		expect(nist.assessedControls).toBe(1);
		expect(nist.passing + nist.failing + nist.partial).toBe(nist.assessedControls);
		// The one assessable control passed. Computing this over `totalControls`
		// instead would report 13% — a compliance number driven by how much was
		// never looked at. This assertion is what separates the two denominators.
		expect(nist.percentage).toBe(100);
	});
});

/**
 * A check that never COMPLETED (checkStatus 'timeout'/'error') must not grade as a
 * compliance FAIL. `buildDnsErrorResult`/`safeCheck` return transient failures as a
 * `CheckResult` with `passed: false` and `checkStatus: 'error' | 'timeout'` — indistinguishable
 * from a genuine failure unless the compliance mapper partitions on `checkStatus`. Every
 * case here goes through the REAL producer (`mapCompliance` → `scanDomain` → the actual
 * check modules) via DNS mocks, not a hand-built `CheckResult[]`, because the banked defect
 * is specifically about what the real pipeline hands `evaluateCompliance`.
 *
 * `.com` domains only — `.example` is a BLOCKED TLD that `validateDomain` rejects before
 * any mock is reached, which would make these tests pass for the wrong reason (never
 * reaching `matchedResults` at all).
 */
describe('map_compliance treats a never-completed check as not_assessed, not fail', () => {
	const { restore } = setupFetchMock();
	afterEach(() => restore());

	/**
	 * A full-scan DNS/HTTPS mock, healthy by default. Two knobs:
	 *  - `dmarc`: 'reject' makes the `_dmarc.<domain>` DoH query throw — check-dmarc.ts's
	 *    top-level catch converts that into `buildDnsErrorResult` (`checkStatus: 'error'`,
	 *    the dominant real-world transient-failure shape, byte-identical to a genuine
	 *    timeout for compliance-mapping purposes). 'missing' returns NODATA — dmarcTreeWalk
	 *    walks to the apex and gives a genuine completed high-severity "No DMARC record
	 *    found" (passed: false, score 0) — this is real, COMPLETED evidence of failure.
	 *  - `tlsrpt`: 'reject' makes the `_smtp._tls.<domain>` DoH query throw — check-tlsrpt.ts
	 *    (package function has no internal try/catch around this query) propagates the
	 *    throw to the Worker wrapper's catch, same transient shape as dmarc.
	 *
	 * `http_security` is deliberately NOT parameterized: this mock's generic `httpResponse`
	 * carries no CSP/X-Frame-Options/X-Content-Type-Options/Permissions-Policy/Referrer-Policy
	 * headers, so `check_http_security` deterministically scores 45 (< 50, `passed: false`) —
	 * a reliable completed genuine failure used as the mirror fixture's evidence.
	 */
	function mockFullScan(domain: string, opts: { dmarc?: 'missing' | 'reject'; tlsrpt?: 'reject' } = {}) {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('_dmarc.') && opts.dmarc === 'reject') return Promise.reject(new Error('Simulated check failure'));
			if (url.includes('_smtp._tls.') && opts.tlsrpt === 'reject') return Promise.reject(new Error('Simulated check failure'));

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=TXT') || url.includes('type=16')) {
					if (url.includes('_dmarc.')) {
						if (opts.dmarc === 'missing') return Promise.resolve(createDohResponse([{ name: `_dmarc.${domain}`, type: 16 }], []));
						return Promise.resolve(txtResponse(`_dmarc.${domain}`, ['v=DMARC1; p=reject']));
					}
					if (url.includes('_domainkey.')) return Promise.resolve(txtResponse(`default._domainkey.${domain}`, ['v=DKIM1; k=rsa; p=MIGf']));
					if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse(`_mta-sts.${domain}`, ['v=STSv1; id=20240101']));
					if (url.includes('_smtp._tls.'))
						return Promise.resolve(txtResponse(`_smtp._tls.${domain}`, [`v=TLSRPTv1; rua=mailto:tls@${domain}`]));
					if (url.includes('default._bimi.'))
						return Promise.resolve(txtResponse(`default._bimi.${domain}`, [`v=BIMI1; l=https://${domain}/logo.svg`]));
					return Promise.resolve(txtResponse(domain, ['v=spf1 include:_spf.google.com -all']));
				}
				if (url.includes('type=NS') || url.includes('type=2'))
					return Promise.resolve(nsResponse(domain, [`ns1.${domain}.`, `ns2.${domain}.`]));
				// This fixture mocks SPF, DKIM, DMARC, MTA-STS and TLS-RPT — i.e. it intends a
				// healthy MAIL domain — but published no MX, so `detectDomainContext` classified
				// it `web_only` and the scan declared every mail-only category NOT APPLICABLE.
				// That made the block comment below ("every other NIST category completed and
				// passed") false. Publishing MX restores the profile the fixture was written for.
				if (url.includes('type=MX') || url.includes('type=15'))
					return Promise.resolve(
						createDohResponse([{ name: domain, type: 15 }], [{ name: domain, type: 15, TTL: 300, data: `10 mail.${domain}.` }]),
					);
				// Publishing MX makes NIST §4.5 (DANE for SMTP) applicable, so the healthy
				// baseline has to actually publish TLSA to satisfy it.
				if (url.includes('type=TLSA') || url.includes('type=52'))
					return Promise.resolve(
						tlsaResponse(`_25._tcp.mail.${domain}`, [{ usage: 3, selector: 1, matchingType: 1, certData: 'abc123' }]),
					);
				if (url.includes('type=CAA') || url.includes('type=257'))
					return Promise.resolve(caaResponse(domain, ['0 issue "letsencrypt.org"']));
				// A signed zone publishes DNSKEY/DS as well as setting AD. Without these the
				// fixture claimed "healthy by default" while modelling an UNSIGNED zone
				// (`recordPresent: false`), which only read as healthy because the mapper was
				// grading on `passed` — the very defect under test elsewhere in this file.
				if (url.includes('type=DNSKEY') || url.includes('type=48'))
					return Promise.resolve(
						createDohResponse([{ name: domain, type: 48 }], [{ name: domain, type: 48, TTL: 300, data: '257 3 13 mdsswUyr3DPW...' }]),
					);
				if (url.includes('type=DS') || url.includes('type=43'))
					return Promise.resolve(
						createDohResponse([{ name: domain, type: 43 }], [{ name: domain, type: 43, TTL: 300, data: '12345 13 2 abc123...' }]),
					);
				if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse(domain, true));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('mta-sts.') && url.includes('.well-known')) {
				return Promise.resolve(httpResponse(`version: STSv1\nmode: enforce\nmx: *.${domain}\nmax_age: 86400`));
			}
			// Generic OK for SSL/HTTP-security/subdomain-takeover/etc. — no security headers,
			// which is what makes check_http_security a reliable deterministic completed-fail.
			return Promise.resolve(httpResponse('OK'));
		});
	}

	it('a control whose only check timed out is not_assessed, not fail', async () => {
		mockFullScan('nist-dmarc-transient.com', { dmarc: 'reject' });
		const { mapCompliance, formatCompliance: format } = await import('../src/tools/map-compliance');
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		const report = await mapCompliance('nist-dmarc-transient.com');

		// NIST §4.3.3 is the ONLY control mapping solely to `dmarc` — the exact "a control
		// whose matched checks ALL carry a transient checkStatus" shape.
		const nist = report.frameworks.nist_800_177;
		const dmarcControl = nist.mappings.find((m) => m.controlId === '§4.3.3');
		// Fixture-reachability guard: if the fixture never reached matchedResults (e.g. the
		// domain was rejected by validateDomain, or the mock never matched), this control
		// wouldn't even be found and the assertion below would throw, not pass vacuously.
		expect(dmarcControl).toBeDefined();
		expect(dmarcControl!.status).toBe('not_assessed');
		expect(dmarcControl!.relatedFindings).toEqual([]);

		// No framework summary counts a never-completed check as a failure. Every other
		// NIST category in this fixture completed and passed, so the only effect of the
		// transient dmarc check is to remove it from the denominator — not to zero it out
		// as one more failure.
		expect(nist.failing).toBe(0);
		expect(nist.notAssessed).toBe(1);
		expect(nist.assessedControls).toBe(7);
		expect(nist.passing).toBe(7);
		expect(nist.percentage).toBe(100);

		// The serialized wire payload — both machine channels — must not pair this specific
		// control with a fabricated "fail" verdict.
		const result = buildToolResult(format(report, 'full'), report, 'full');
		const wire = JSON.stringify(result.structuredContent);
		expect(wire).not.toContain('"controlId":"§4.3.3","controlName":"DMARC Policy","status":"fail"');
		expect(wire).toContain('"controlId":"§4.3.3","controlName":"DMARC Policy","status":"not_assessed"');
		const comment = result.content.map((c) => c.text).find((t) => t.includes('STRUCTURED_RESULT'));
		expect(comment).toBeDefined();
		expect(comment).not.toContain('"controlId":"§4.3.3","controlName":"DMARC Policy","status":"fail"');

		// Prose must not name DMARC as a failing control either — a customer's SOC 2 report
		// must not read "DMARC Policy — FAIL" for a check that never ran to completion.
		const prose = format(report, 'full');
		const dmarcLine = prose.split('\n').find((l) => l.includes('§4.3.3'));
		expect(dmarcLine).toBeDefined();
		expect(dmarcLine).toContain('NOT ASSESSED');
		expect(dmarcLine).not.toMatch(/\bFAIL\b/);
	}, 15_000);

	it('a control with one completed-failing and one timed-out check grades on the completed one', async () => {
		// SOC 2 CC7.1 (Monitoring and Detection) maps exactly [tlsrpt, dmarc], requirePass: false.
		// dmarc genuinely fails (completed, real evidence); tlsrpt errors out (transient).
		mockFullScan('soc2-mixed-evidence.com', { dmarc: 'missing', tlsrpt: 'reject' });
		const { mapCompliance } = await import('../src/tools/map-compliance');
		const report = await mapCompliance('soc2-mixed-evidence.com');

		const cc71 = report.frameworks.soc2.mappings.find((m) => m.controlId === 'CC7.1');
		expect(cc71).toBeDefined();
		// The completed DMARC failure is real evidence and must NOT be suppressed just
		// because a sibling category in the same control happened to time out — this is
		// the over-abstain mirror of the first test.
		expect(cc71!.status).toBe('fail');
		// Only the COMPLETED failure contributes a related finding; the transient tlsrpt
		// check contributes to neither the passing nor the failing count, so its "check
		// error" title must not appear here as if it were a graded finding.
		expect(cc71!.relatedFindings).toEqual(['No DMARC record found']);
	}, 15_000);

	it('mirror: a control whose checks all completed and failed still fails', async () => {
		// PCI DSS 6.4.2 (Web Application Firewall / CSP) maps solely to `http_security`,
		// requirePass: true. No transient statuses anywhere in this fixture — http_security
		// completes normally and genuinely fails (score 45, no security headers).
		mockFullScan('pci-mirror-baseline.com');
		const { mapCompliance } = await import('../src/tools/map-compliance');
		const report = await mapCompliance('pci-mirror-baseline.com');

		const pci = report.frameworks.pci_dss_4;
		const waf = pci.mappings.find((m) => m.controlId === '6.4.2');
		expect(waf).toBeDefined();
		expect(waf!.status).toBe('fail');

		// Nothing here is transient, so `completed === matchedResults` exactly — this
		// fixture's framework summary is untouched by the partition and must match the
		// values the pre-fix code already produced for it (a mutation that broke this
		// would be over-abstaining, not fixing the banked defect).
		expect(pci.totalControls).toBe(5);
		expect(pci.passing).toBe(3);
		expect(pci.failing).toBe(1);
		expect(pci.partial).toBe(1);
		expect(pci.notAssessed).toBe(0);
		expect(pci.assessedControls).toBe(5);
		expect(pci.percentage).toBe(60);
	}, 15_000);

	/**
	 * F1 (fix round 1): the completed/transient partition fixed *grading* on a
	 * transient category, but `totalCategories = control.categories.length` still
	 * counted the transient category itself in the denominator — so a multi-category
	 * control with one PASSING completed check and one transient check landed on
	 * 'partial' instead of 'pass' (a never-completed check silently costing a control
	 * its pass verdict, the same class of defect one level up from the original bug).
	 * Measured on this exact shape (SOC2 CC7.1, healthy domain, one transient category):
	 * before the fix, soc2/pci_dss_4/cis_controls percentages were all measurably lower
	 * than the honest value — see task-8-report.md's "Fix round 1" section for the full
	 * before/after table across all four frameworks.
	 */
	it('a control with one completed-passing and one timed-out check still passes (F1)', async () => {
		// SOC2 CC7.1 maps [tlsrpt, dmarc], requirePass: false. dmarc completes and
		// PASSES; tlsrpt times out (transient). The transient category must not occupy
		// a non-passing slot in the denominator either — this control has exactly one
		// piece of REAL evidence and it's clean, so the verdict must be 'pass', not
		// 'partial'.
		mockFullScan('soc2-transient-still-passes.com', { tlsrpt: 'reject' });
		const { mapCompliance } = await import('../src/tools/map-compliance');
		const mixedReport = await mapCompliance('soc2-transient-still-passes.com');

		const cc71Mixed = mixedReport.frameworks.soc2.mappings.find((m) => m.controlId === 'CC7.1');
		expect(cc71Mixed).toBeDefined();
		expect(cc71Mixed!.status).toBe('pass');
		expect(cc71Mixed!.relatedFindings).toEqual([]);

		// Same fixture, but tlsrpt completes and passes instead of timing out — the
		// ENTIRE soc2 framework summary must be identical, because the only thing that
		// changed between the two scans is which category carried the (already-passing,
		// otherwise irrelevant) evidence for CC7.1.
		mockFullScan('soc2-transient-baseline.com');
		const baselineReport = await mapCompliance('soc2-transient-baseline.com');
		const cc71Baseline = baselineReport.frameworks.soc2.mappings.find((m) => m.controlId === 'CC7.1');
		expect(cc71Baseline!.status).toBe('pass');

		expect(mixedReport.frameworks.soc2.percentage).toBe(baselineReport.frameworks.soc2.percentage);
		expect(mixedReport.frameworks.soc2.passing).toBe(baselineReport.frameworks.soc2.passing);
		expect(mixedReport.frameworks.soc2.failing).toBe(baselineReport.frameworks.soc2.failing);
		expect(mixedReport.frameworks.soc2.partial).toBe(baselineReport.frameworks.soc2.partial);
		expect(mixedReport.frameworks.soc2.notAssessed).toBe(baselineReport.frameworks.soc2.notAssessed);
	}, 20_000);
});

/**
 * F3 (fix round 1): a total DoH/network outage — every attempted check errors out —
 * previously reported `assessed: true, caveat: null` and rendered "No control could be
 * assessed — 0 of 8 had any check evidence (not measured)". That is FALSE: there were
 * N real `CheckResult`s, they just never completed (`checkStatus: 'error'`/`'timeout'`).
 * `isMeasured` (`checks.length > 0`) could not tell "19 healthy checks" apart from "19
 * checks that all timed out" — both were truthy. `assessed` must be `false` for the
 * outage case too, but with DISTINCT wording from the genuine no-evidence case: "no
 * checks ran" is itself false when 19 checks DID run.
 *
 * Built via hand-built `CheckResult[]` (mirrors this file's own `evaluateCompliance`
 * describe block above, and `evidence-gate-safety.spec.ts`'s `SCAN_CATEGORIES`-driven
 * fixture pattern) rather than a full DNS mock: several individual check modules
 * self-catch a raw DNS-query rejection into a low-severity COMPLETED finding rather
 * than propagating it as a transient `checkStatus` (e.g. `check-mta-sts.ts`'s package
 * function), so simulating a clean "all 19 categories transient" outage via `fetch`
 * mocking alone is unreliable — asserting directly on the shape `evaluateCompliance`
 * actually receives is the precise way to pin this invariant.
 */
describe('map_compliance: a total outage (all checks attempted, none completed) is honestly unassessed', () => {
	it('assessed is false with a truthful, distinct caveat, and every control is not_assessed', async () => {
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
		const { buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');

		// Every attempted check errored out — a total outage, NOT the zero-check
		// (NXDOMAIN/broken-zone) case: there IS a CheckResult per category, it just
		// never completed. Mirrors the buildDnsErrorResult/safeCheck shape exactly.
		const allTransient: CheckResult[] = SCAN_CATEGORIES.map((c) => ({
			...buildCheckResult(c, [createFinding(c, `${c} check error`, 'high', 'Check failed: DNS query failed')]),
			score: 0,
			passed: false,
			checkStatus: 'error' as const,
			partial: true,
		}));

		// Non-vacuity guard: prove check data actually existed (unlike the zero-check
		// case below) before asserting on it.
		expect(allTransient.length).toBeGreaterThan(10);

		const report = evaluateCompliance(allTransient, 'total-outage.example', null, null);

		expect(report.assessed).toBe(false);
		expect(report.caveat).toBe(buildAllTransientCaveat(allTransient.length));
		// Distinct from the genuine no-evidence wording — "no checks ran" would be
		// false here, since `allTransient.length` checks DID run.
		expect(report.caveat).not.toBe(UNASSESSED_COMPLIANCE_CAVEAT);
		expect(report.caveat).toMatch(/attempted/i);
		expect(report.caveat!.toLowerCase()).not.toContain('no checks ran');

		const allMappings = (['nist_800_177', 'pci_dss_4', 'soc2', 'cis_controls'] as const).flatMap((fw) => report.frameworks[fw].mappings);
		// Non-vacuity guard for the mapping-level assertions below.
		expect(allMappings.length).toBeGreaterThan(20);
		expect(allMappings.every((m) => m.status === 'not_assessed')).toBe(true);
		expect(allMappings.filter((m) => m.status === 'fail')).toEqual([]);
	});

	it('keeps the genuine no-evidence case (checks: []) byte-identical to its pre-F3 wording', () => {
		// The slice-2/Task-3 case: NXDOMAIN / broken zone — no CheckResults at all.
		// F3 must not touch this path's caveat text or its `assessed` value.
		const report = evaluateCompliance([], 'never-measured.example', null, null);
		expect(report.assessed).toBe(false);
		expect(report.caveat).toBe(UNASSESSED_COMPLIANCE_CAVEAT);
		expect(report.caveat).toBe(
			'No checks ran for this domain, so the controls below are NOT assessable — each is reported as NOT ASSESSED (absence of evidence), never as a requirement found unmet.',
		);
	});
});

/**
 * The banked defect. `map_compliance` returns `buildToolResult(text, result, format)`,
 * so the raw `ComplianceReport` becomes BOTH the MCP `structuredContent` and the
 * `STRUCTURED_RESULT` comment. Task 3 corrected the PROSE (a "not measured" score
 * line plus a caveat) but left the payload emitting, per control:
 *
 *     {"passing":0,"failing":5,"percentage":0,"status":"fail"}
 *
 * — a fabricated 0% compliance verdict, with no caveat field at all, for a domain
 * that was never assessed. `percentage: 0` is a number something will chart.
 * A domain that does not exist has not failed SOC 2.
 *
 * These assertions run against the SERIALIZED wire payload deliberately: a
 * prose-only fix is exactly the defect being closed, so asserting on rendered
 * text could not have caught it.
 */
describe('map_compliance structured payload — a domain that was never measured', () => {
	const FRAMEWORKS = ['nist_800_177', 'pci_dss_4', 'soc2', 'cis_controls'] as const;

	async function unmeasuredReport() {
		const { evaluateCompliance: evaluate } = await import('../src/tools/map-compliance');
		return evaluate([], 'never-measured.example', null, null);
	}

	it('marks every control not_assessed — absence of evidence is not a failed requirement', async () => {
		const report = await unmeasuredReport();
		const mappings = FRAMEWORKS.flatMap((fw) => report.frameworks[fw].mappings);

		// Fixture-reachability guard: with an empty mappings list every assertion
		// below would hold vacuously and this test would protect nothing.
		expect(mappings.length).toBeGreaterThan(20);
		expect(mappings.filter((m) => m.status === 'fail')).toEqual([]);
		expect(mappings.every((m) => m.status === 'not_assessed')).toBe(true);
	});

	it('omits the compliance percentage instead of reporting 0%', async () => {
		const report = await unmeasuredReport();
		for (const fw of FRAMEWORKS) {
			const summary = report.frameworks[fw];
			expect(summary.totalControls).toBeGreaterThan(0);
			expect(summary.percentage).toBeNull();
			expect(summary.assessedControls).toBe(0);
			expect(summary.notAssessed).toBe(summary.totalControls);
			expect(summary.failing).toBe(0);
			expect(summary.passing).toBe(0);
		}
	});

	it('carries the caveat as DATA, not only as prose', async () => {
		const report = await unmeasuredReport();
		expect(report.assessed).toBe(false);
		expect(report.caveat).toMatch(/not assessable/i);
	});

	it('emits no fabricated verdict on either machine channel (structuredContent AND the STRUCTURED_RESULT comment)', async () => {
		const { formatCompliance: format } = await import('../src/tools/map-compliance');
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		const report = await unmeasuredReport();
		const result = buildToolResult(format(report, 'full'), report, 'full');

		// Channel 1 — the MCP-standard structuredContent field.
		expect(result.structuredContent).toBeDefined();
		const wire = JSON.stringify(result.structuredContent);
		expect(wire).not.toContain('"status":"fail"');
		expect(wire).not.toContain('"percentage":0');
		expect(wire).toContain('"status":"not_assessed"');
		expect(wire).toContain('"assessed":false');

		// Channel 2 — the legacy STRUCTURED_RESULT comment some clients still parse.
		const comment = result.content.map((c) => c.text).find((t) => t.includes('STRUCTURED_RESULT'));
		expect(comment).toBeDefined();
		expect(comment).not.toContain('"status":"fail"');
		expect(comment).not.toContain('"percentage":0');
		expect(comment).toContain('"assessed":false');
	});

	it('still emits a real fail verdict and a numeric percentage for a MEASURED domain (control)', async () => {
		const { evaluateCompliance: evaluate, formatCompliance: format } = await import('../src/tools/map-compliance');
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		// 5 of the 8 NIST controls pass; mta_sts/dane/caa genuinely fail.
		const measured = evaluate(
			[
				makeCheckResult('spf', true),
				makeCheckResult('dkim', true),
				makeCheckResult('dmarc', true),
				makeCheckResult('mta_sts', false, [{ title: 'Missing MTA-STS', severity: 'medium' }]),
				makeCheckResult('dane', false, [{ title: 'Missing DANE', severity: 'low' }]),
				makeCheckResult('tlsrpt', true),
				makeCheckResult('dnssec', true),
				makeCheckResult('caa', false, [{ title: 'Missing CAA', severity: 'medium' }]),
				makeCheckResult('ssl', true),
				makeCheckResult('http_security', true),
				makeCheckResult('ns', true),
			],
			'measured.example',
			73,
			'C+',
		);
		const wire = JSON.stringify(buildToolResult(format(measured, 'full'), measured, 'full').structuredContent);

		// Without these the assertions above would all hold under an implementation
		// that reported EVERY control as not_assessed and every percentage as null.
		expect(measured.assessed).toBe(true);
		expect(measured.caveat).toBeNull();
		expect(wire).toContain('"status":"fail"');
		expect(measured.frameworks.nist_800_177.percentage).toBe(63);
		expect(measured.frameworks.nist_800_177.notAssessed).toBe(0);
		expect(measured.frameworks.nist_800_177.assessedControls).toBe(8);
	});
});

describe('formatCompliance', () => {
	function makeReport(): ComplianceReport {
		const results = [
			makeCheckResult('spf', true),
			makeCheckResult('dkim', true),
			makeCheckResult('dmarc', true),
			makeCheckResult('mta_sts', false, [{ title: 'No MTA-STS record', severity: 'medium' }]),
			makeCheckResult('dane', false, [{ title: 'No DANE records', severity: 'low' }]),
			makeCheckResult('tlsrpt', true),
			makeCheckResult('dnssec', false, [{ title: 'DNSSEC not enabled', severity: 'medium' }]),
			makeCheckResult('caa', true),
			makeCheckResult('ssl', true),
			makeCheckResult('http_security', true),
			makeCheckResult('ns', true),
		];
		return evaluateCompliance(results, 'fmt.com', 71, 'C+');
	}

	it('should produce compact format with status icons', () => {
		const report = makeReport();
		const output = formatCompliance(report, 'compact');

		expect(output).toContain('Compliance: fmt.com');
		expect(output).toContain('71/100 (C+)');
		expect(output).toContain('NIST 800-177:');
		expect(output).toContain('PCI DSS 4.0:');
		expect(output).toContain('SOC 2:');
		expect(output).toContain('CIS Controls:');
		// Check mark for passing control
		expect(output).toContain('\u2713 §4.3.1');
		// X mark for failing control
		expect(output).toContain('\u2717 §5.1');
	});

	it('should produce full format with markdown headers and details', () => {
		const report = makeReport();
		const output = formatCompliance(report, 'full');

		expect(output).toContain('# Compliance Report: fmt.com');
		expect(output).toContain('**Score:** 71/100 (C+)');
		expect(output).toContain('## NIST 800-177');
		expect(output).toContain('## PCI DSS 4.0');
		expect(output).toContain('## SOC 2');
		expect(output).toContain('## CIS Controls');
		// Should show related findings as sub-items
		expect(output).toContain('DNSSEC not enabled');
		expect(output).toContain('No MTA-STS record');
	});

	it.each(['compact', 'full'] as const)('renders "not measured" instead of null/100 (null) for an ungraded scan [%s]', async (format) => {
		const { evaluateCompliance: evaluate, formatCompliance: fmt } = await import('../src/tools/map-compliance');
		const report = evaluate([], 'never-measured.example', null, null);
		const text = fmt(report, format);

		expect(text).toContain('not measured');
		expect(text).not.toContain('null');
		expect(text).not.toContain('/100');
		// The per-control column must not read as a failure verdict either.
		expect(text).not.toMatch(/\bFAIL\b/);
		expect(text.toLowerCase()).toContain('not assessed');
	});

	it('should not show related findings for passing controls in compact format', () => {
		const results = makeAllPassing();
		const report = evaluateCompliance(results, 'pass.com', 95, 'A+');
		const output = formatCompliance(report, 'compact');

		// Passing controls should not have finding text appended
		const spfLine = output.split('\n').find((l) => l.includes('§4.3.1'));
		expect(spfLine).toBeDefined();
		expect(spfLine).not.toContain(' — ');
	});
});

/**
 * A control must not be reported as PASS on the strength of a check that observed no
 * published record.
 *
 * `passed` answers "did this check penalize the domain", NOT "does the control exist".
 * A check for an absent-but-unpenalized control still returns `passed: true` — that is
 * the documented reason `recordPresent` exists (see `CheckResult.recordPresent`, which
 * is explicitly score-neutral so that nothing in the scoring path reads it). This mapper
 * was reading `passed`, so a domain with NO DNSSEC and NO CAA was reported as passing
 * NIST 800-177 §5.1 and §5.2 — a published compliance claim the same scan simultaneously
 * contradicted with a high-severity "DNSSEC not enabled" finding.
 *
 * Measured 2026-08-19 against three live domains: cloudflare.com (DNSSEC signed,
 * `recordPresent: true`) correctly passed §5.1, while davidhf.com and codewithbullet.com
 * (both `recordPresent: false`, both carrying a HIGH "DNSSEC not enabled") ALSO passed it.
 * The control never discriminated.
 */
describe('map_compliance does not pass a control whose record was never published', () => {
	/**
	 * A check that COMPLETED, was not penalized, but published nothing.
	 *
	 * The flag pair is the shape MEASURED from production on 2026-08-19, not one invented
	 * in the mapper's own vocabulary: `check_dnssec` on davidhf.com and `check_caa` on the
	 * same domain both returned `passed: true` with `controlPresent: false` and
	 * `recordPresent: false` alongside a high/medium "not enabled" finding.
	 */
	function absentButUnpenalized(category: string, title: string, severity: string): CheckResult {
		return {
			category,
			passed: true,
			score: 60,
			controlPresent: false,
			recordPresent: false,
			findings: [{ category, title, severity, detail: '' }],
		} as CheckResult;
	}

	/**
	 * The registry-signed counter-fixture: no DNSKEY/DS of its own, but the chain
	 * validates. `check-dnssec` documents this exact `false`/`true` pair as "protected,
	 * not a contradiction", so it must keep passing.
	 */
	function absentRecordsButControlActive(category: string): CheckResult {
		return {
			category,
			passed: true,
			score: 85,
			controlPresent: true,
			recordPresent: false,
			findings: [{ category, title: 'DNSSEC is registry-managed', severity: 'medium', detail: '' }],
		} as CheckResult;
	}

	it('does not pass NIST §5.1 when the DNSSEC check observed no published record', () => {
		const results = makeAllPassing().map((r) =>
			r.category === 'dnssec' ? absentButUnpenalized('dnssec', 'DNSSEC not enabled', 'high') : r,
		);
		const report = evaluateCompliance(results, 'no-dnssec.com', 82, 'B');

		const control = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§5.1');
		expect(control).toBeDefined();
		expect(control!.status).not.toBe('pass');
	});

	it('does not pass NIST §5.2 when the CAA check observed no published record', () => {
		const results = makeAllPassing().map((r) => (r.category === 'caa' ? absentButUnpenalized('caa', 'No CAA records', 'medium') : r));
		const report = evaluateCompliance(results, 'no-caa.com', 82, 'B');

		const control = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§5.2');
		expect(control).toBeDefined();
		expect(control!.status).not.toBe('pass');
	});

	/**
	 * The registry-signed zone must keep passing. This is the guard that stops the fix
	 * from becoming the same defect with the opposite sign: a ccTLD-signed zone publishes
	 * no DNSKEY/DS of its own yet is cryptographically protected, and `check-dnssec`
	 * documents that `recordPresent: false` + `controlPresent: true` pair as exactly that
	 * state. Failing it would report a protected zone as non-compliant.
	 */
	it('still passes a control whose records are absent but whose control is affirmatively active', () => {
		const results = makeAllPassing().map((r) => (r.category === 'dnssec' ? absentRecordsButControlActive('dnssec') : r));
		const report = evaluateCompliance(results, 'registry-signed.com', 88, 'B');

		const control = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§5.1');
		expect(control).toBeDefined();
		expect(control!.status).toBe('pass');
	});

	/**
	 * Over-correction guard. `recordPresent: undefined` means "this check does not report
	 * the signal" (spf, dkim, ssl, ns, http_security never set it) or "the query failed".
	 * Neither is evidence of absence, so behaviour must be unchanged for those.
	 */
	it('still passes a control whose check does not report the presence signal at all', () => {
		const results = makeAllPassing(); // no recordPresent anywhere
		const report = evaluateCompliance(results, 'silent-signal.com', 95, 'A');

		for (const control of report.frameworks.nist_800_177.mappings) {
			expect(control.status).toBe('pass');
		}
	});

	/**
	 * The second over-correction guard, and the reason this fix is not a one-line
	 * predicate swap. On a `web_only`/`non_mail` domain the scan already declares the
	 * mail-only categories NOT APPLICABLE and nulls their scores. Those categories also
	 * report `recordPresent: false` (there genuinely is no MTA-STS record), so failing on
	 * absence alone would newly report "NIST §4.4 MTA-STS — FAIL" against a domain that
	 * accepts no mail. That trades a false PASS for a false FAIL: the same defect wearing
	 * the opposite sign. A control the scan declared inapplicable has no verdict to give.
	 */
	it('reports a not-applicable category as not_assessed rather than failing it on absence', () => {
		const results = makeAllPassing().map((r) =>
			r.category === 'mta_sts' ? absentButUnpenalized('mta_sts', 'No MTA-STS or TLS-RPT records found', 'low') : r,
		);
		const report = evaluateCompliance(results, 'web-only.com', 82, 'B', ['mta_sts']);

		const control = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.4');
		expect(control).toBeDefined();
		expect(control!.status).toBe('not_assessed');
		// And it must leave the denominator, not sit in it as a silent zero.
		expect(report.frameworks.nist_800_177.notAssessed).toBeGreaterThan(0);
	});
});

/**
 * `map_compliance` must render the SAME letter as every other rating surface.
 *
 * `ScanScore.grade` carries the engine's canonical NINE-band grade (A+/A/B+/B/C+/…);
 * the display SSOT is `displayGradeFor`, which `format-report.ts` uses for
 * `scan_domain`. This tool passed the raw nine-band value straight through, so the same
 * domain at the same score rendered `B+` here and `B` in `scan_domain` — measured
 * 2026-08-19 on codewithbullet.com (82 → "B+" vs "B") and davidhf.com (92 → "A+" vs "A",
 * where A+ additionally means ≥95 on the display scale).
 */
describe('map_compliance grade uses the display band SSOT', () => {
	const { restore } = setupFetchMock();
	afterEach(() => restore());

	it('never emits a letter outside the six-band display scale', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			const domain = 'band-ssot.com';
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=TXT') || url.includes('type=16')) {
					if (url.includes('_dmarc.')) return Promise.resolve(txtResponse(`_dmarc.${domain}`, ['v=DMARC1; p=quarantine']));
					if (url.includes('_domainkey.')) return Promise.resolve(createDohResponse([], []));
					return Promise.resolve(txtResponse(domain, ['v=spf1 include:_spf.google.com ~all']));
				}
				if (url.includes('type=NS') || url.includes('type=2')) return Promise.resolve(nsResponse(domain, [`ns1.${domain}.`]));
				if (url.includes('type=CAA') || url.includes('type=257')) return Promise.resolve(createDohResponse([], []));
				if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse(domain, false));
				return Promise.resolve(createDohResponse([], []));
			}
			return Promise.resolve(httpResponse('OK'));
		});

		const { mapCompliance } = await import('../src/tools/map-compliance');
		const { nistScoreToGrade } = await import('@blackveil/dns-checks/scoring');
		const report = await mapCompliance('band-ssot.com');

		// Fixture-reachability guard: a null score would make the assertions vacuous.
		expect(report.score).not.toBeNull();
		expect(report.grade).toBe(nistScoreToGrade(report.score!));
		expect(['A+', 'A', 'B', 'C', 'D', 'F']).toContain(report.grade);
	});
});
