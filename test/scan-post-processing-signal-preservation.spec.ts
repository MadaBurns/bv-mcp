import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type CheckResult, buildCheckResult, createFinding } from '../src/lib/scoring';
import { resetProviderSignatureState } from '../src/lib/provider-signatures';

/**
 * #994 — `scan_domain` post-processing rebuilt every adjusted check with
 * `buildCheckResult(category, findings)`, a TWO-argument call against a
 * FIVE-argument signature, so `controlPresent`, `recordPresent` and `metadata`
 * were silently discarded on every rebuild.
 *
 * Why this file exists as a separate suite, and why it enters through
 * `applyScanPostProcessing` rather than the private helpers: the defect lived in
 * exactly the gap between "the package's check output is correct" (which
 * `packages/dns-checks`' own contract tests already prove, by calling the checks
 * DIRECTLY) and "what `scan_domain` actually ships". A test that asserts the
 * check output proves nothing about the pipeline — that independence is the
 * point. Each case below drives ONE post-processing adjustment path end-to-end
 * and asserts the three structured signals survive it.
 *
 * They are INPUTS, not outputs: `passed`/`score` are re-derived from findings
 * (and must be), but `controlPresent`/`recordPresent`/`metadata` record what the
 * probe OBSERVED. Every adjustment here rewrites finding severity and prose to
 * express APPLICABILITY ("this control does not apply to a non-mail domain"), not
 * a new observation — so none of them invalidate an observation, and carrying it
 * forward is correct at all of them.
 */

/** The two SGE readers added in #987: `spfAllQualifier()` / `mtaStsPolicyMode()` read these. */
const SPF_SIGNALS = { controlPresent: true, recordPresent: true, metadata: { spfAll: '-all' } } as const;
const MTA_STS_SIGNALS = { controlPresent: true, recordPresent: true, metadata: { mtaStsMode: 'enforce' } } as const;

function withSignals(
	result: CheckResult,
	signals: { controlPresent?: boolean; recordPresent?: boolean; metadata?: Record<string, unknown> },
) {
	return { ...result, ...signals };
}

/** An MX result that affirmatively declares real inbound mail routing. */
function mailBearingMx(): CheckResult {
	return withSignals(
		buildCheckResult('mx', [createFinding('mx', 'MX records configured', 'info', 'Mail is routed to mail.example.com.')]),
		{
			controlPresent: true,
		},
	);
}

/** An MX result that affirmatively declares NO inbound mail (RFC 7505 shape). */
function nullMx(): CheckResult {
	return withSignals(buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'No inbound mail is configured.')]), {
		controlPresent: false,
	});
}

/** An SPF result whose record publishes `-all` with no authorizing mechanisms (the no-send shape). */
function noSendSpf(): CheckResult {
	return withSignals(
		buildCheckResult('spf', [
			createFinding('spf', 'SPF record rejects all mail', 'info', 'v=spf1 -all', { noSendPolicy: true, includeDomains: [] }),
		]),
		SPF_SIGNALS,
	);
}

describe('#994 — scan post-processing preserves controlPresent / recordPresent / metadata', () => {
	beforeEach(() => {
		resetProviderSignatureState();
	});

	it('addOutboundProviderInference keeps the SPF signals when a provider is inferred', async () => {
		// The live A/B in #994: health.govt.nz (provider inferred → SPF rebuilt →
		// spfAllQualifier() undefined) vs cloudflare.com (no inference → SPF intact).
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			withSignals(
				buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'Healthy SPF', { includeDomains: ['google.com'] })]),
				SPF_SIGNALS,
			),
			buildCheckResult('dkim', []),
			mailBearingMx(),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((result) => result.category === 'spf');

		// Positive control: the rebuild really did happen on this path.
		expect(spf?.findings.some((finding) => finding.title === 'Outbound email provider inferred')).toBe(true);
		expect(spf?.metadata?.spfAll).toBe('-all');
		expect(spf?.controlPresent).toBe(true);
		expect(spf?.recordPresent).toBe(true);
	});

	it('clarifyMtaStsForMailDomain keeps the MTA-STS signals on an MX-bearing domain', async () => {
		// This adjustment runs on EVERY MX-bearing domain — the widest-reach site.
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			mailBearingMx(),
			withSignals(
				buildCheckResult('mta_sts', [createFinding('mta_sts', 'MTA-STS policy in enforce mode', 'info', 'Policy fetched; mode: enforce.')]),
				MTA_STS_SIGNALS,
			),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const mtaSts = updated.find((result) => result.category === 'mta_sts');

		expect(mtaSts?.metadata?.mtaStsMode).toBe('enforce');
		expect(mtaSts?.controlPresent).toBe(true);
		expect(mtaSts?.recordPresent).toBe(true);
	});

	it('adjustForNonMailDomain keeps the SPF signals while downgrading severity', async () => {
		vi.doMock('../src/lib/dns', () => ({
			queryTxtRecords: vi.fn().mockResolvedValue(['v=DMARC1; p=reject']),
		}));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			nullMx(),
			withSignals(
				buildCheckResult('spf', [createFinding('spf', 'No SPF record found', 'critical', 'No SPF record found for app.example.com.')]),
				{ controlPresent: false, recordPresent: false, metadata: { spfAll: 'no-all-mechanism' } },
			),
		];

		const updated = await applyScanPostProcessing('app.example.com', results);
		const spf = updated.find((result) => result.category === 'spf');

		// Positive control: the downgrade (and therefore the rebuild) really fired.
		expect(spf?.findings[0].severity).toBe('info');
		expect(spf?.metadata?.spfAll).toBe('no-all-mechanism');
		// `false` is a MEASURED negative and must not collapse to `undefined`
		// ("could not be determined") — the two are different facts.
		expect(spf?.controlPresent).toBe(false);
		expect(spf?.recordPresent).toBe(false);
		vi.doUnmock('../src/lib/dns');
	});

	it('adjustForNonApexNonMailHost keeps the MTA-STS signals on a non-apex host', async () => {
		vi.doMock('../src/lib/dns', () => ({
			queryTxtRecords: vi.fn().mockResolvedValue([]),
		}));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			nullMx(),
			withSignals(
				buildCheckResult('mta_sts', [createFinding('mta_sts', 'No MTA-STS record found', 'high', 'No _mta-sts TXT record.')]),
				MTA_STS_SIGNALS,
			),
		];

		const updated = await applyScanPostProcessing('www.example.com', results, { nonApexHost: true });
		const mtaSts = updated.find((result) => result.category === 'mta_sts');

		expect(mtaSts?.findings[0].severity).toBe('info');
		expect(mtaSts?.metadata?.mtaStsMode).toBe('enforce');
		expect(mtaSts?.controlPresent).toBe(true);
		expect(mtaSts?.recordPresent).toBe(true);
		vi.doUnmock('../src/lib/dns');
	});

	it('adjustForNoSendDomain keeps the MTA-STS signals under an SPF -all no-send policy', async () => {
		// The SIXTH rebuild site — not named in #994's root-cause list.
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			mailBearingMx(),
			noSendSpf(),
			withSignals(
				buildCheckResult('mta_sts', [createFinding('mta_sts', 'No MTA-STS record found', 'high', 'No _mta-sts TXT record.')]),
				MTA_STS_SIGNALS,
			),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const mtaSts = updated.find((result) => result.category === 'mta_sts');

		expect(mtaSts?.findings[0].detail).toContain('domain SPF policy rejects all outbound mail');
		expect(mtaSts?.metadata?.mtaStsMode).toBe('enforce');
		expect(mtaSts?.controlPresent).toBe(true);
		expect(mtaSts?.recordPresent).toBe(true);
	});

	it('adjustBimiForNonMailDomain keeps the BIMI signals', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			mailBearingMx(),
			noSendSpf(),
			withSignals(
				buildCheckResult('bimi', [
					createFinding(
						'bimi',
						'No BIMI record found',
						'info',
						'No BIMI record found at default._bimi.example.com. Domain is eligible for BIMI.',
					),
				]),
				{ controlPresent: false, recordPresent: false, metadata: { bimiProbe: 'completed' } },
			),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const bimi = updated.find((result) => result.category === 'bimi');

		expect(bimi?.findings[0].detail).toContain('does not appear to send email');
		expect(bimi?.metadata?.bimiProbe).toBe('completed');
		expect(bimi?.controlPresent).toBe(false);
		expect(bimi?.recordPresent).toBe(false);
	});

	it('escalateDmarcForImpersonation keeps the DMARC signals (recordPresent true for a published p=none)', async () => {
		// `recordPresent: true` + `controlPresent: false` is the documented
		// "published but weak" state. Dropping it downgraded a MEASURED publication
		// to "could not be determined".
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			mailBearingMx(),
			withSignals(
				buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy set to none', 'high', 'p=none provides no enforcement.')]),
				{
					controlPresent: false,
					recordPresent: true,
					metadata: { dmarcPolicy: 'none' },
				},
			),
			buildCheckResult('lookalikes', [
				createFinding('lookalikes', 'Active lookalike domain detected', 'high', 'examp1e.com resolves with mail infrastructure.'),
			]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const dmarc = updated.find((result) => result.category === 'dmarc');

		expect(dmarc?.findings[0].severity).toBe('critical');
		expect(dmarc?.metadata?.dmarcPolicy).toBe('none');
		expect(dmarc?.controlPresent).toBe(false);
		expect(dmarc?.recordPresent).toBe(true);
	});

	it('an ABSTAINED result is returned untouched — signals included, adjustments not applied', async () => {
		// `rebuildUnlessAbstained` returns the ORIGINAL object for a non-completed
		// check, so its signals were never at risk; asserting it here pins the
		// behaviour so a future "just carry them forward everywhere" refactor cannot
		// accidentally start rebuilding (and thus falsely scoring) an abstention.
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const mtaStsAbstained: CheckResult = {
			...withSignals(
				buildCheckResult('mta_sts', [
					createFinding('mta_sts', 'MTA-STS not assessed', 'info', 'The policy fetch never reached the origin.', {
						inconclusive: true,
						errorKind: 'fetch_error',
					}),
				]),
				{ metadata: { probeAttempts: 2 } },
			),
			score: 0,
			passed: false,
			partial: true,
			checkStatus: 'error',
		};

		const updated = await applyScanPostProcessing('example.com', [mailBearingMx(), mtaStsAbstained]);
		const mtaSts = updated.find((result) => result.category === 'mta_sts');

		expect(mtaSts?.checkStatus).toBe('error');
		expect(mtaSts?.partial).toBe(true);
		expect(mtaSts?.score).toBe(0);
		expect(mtaSts?.metadata?.probeAttempts).toBe(2);
		// Abstained → NOT determined. The signals must stay absent rather than be
		// synthesised, and no adjustment prose may be applied.
		expect(mtaSts?.controlPresent).toBeUndefined();
		expect(mtaSts?.recordPresent).toBeUndefined();
	});

	it('restoring the signals does NOT move the profile — controlPresent is score-bearing, but not on any rebuilt category', async () => {
		// `controlPresent` IS read by the scoring path: `detectDomainContext` selects
		// the weight table from it, so restoring it could in principle re-grade
		// domains. It does not, and this pins why rather than asserting it.
		//
		// The profile-DECIDING reads are `mx`, `ssl`, `caa` and `dmarc`
		// (`packages/dns-checks/src/scoring/profiles.ts`). `mx`/`ssl`/`caa` appear in
		// NO rebuild list in post-processing.ts, so they are never rebuilt. `dmarc` is
		// rebuilt on three paths, and on all three `dmarcEnforcing` is unreachable or
		// unchanged:
		//   - escalateDmarcForImpersonation is gated on `dmarcIsWeak`, and check-dmarc
		//     sets `controlPresent = p===quarantine||reject`, so the two trigger titles
		//     ("No DMARC record found", "DMARC policy set to none") can only ever occur
		//     with controlPresent false. undefined→false; `=== true` is false either way.
		//   - adjustForNonMailDomain / adjustForNonApexNonMailHost run only under
		//     `mxDeclaresNoInboundMail`, and detectDomainContext's no-MX / unknown-MX
		//     branches return before `dmarcEnforcing` is ever consulted.
		//
		// `recordPresent` and `metadata` are score-neutral by construction: every
		// `result.metadata` reader in scoring/model.ts (spfAllQualifier,
		// mtaStsPolicyMode, dmarcPctTagPresent, dmarcRecordInheritedFromParent) is
		// consumed only by `sge/evaluate.ts`, which produces a compliance verdict and
		// no score. The scoring engine reads FINDING metadata, never result metadata.
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');
		const { detectDomainContext } = await import('@blackveil/dns-checks/scoring');

		// The worst case for the argument: an enforcing DMARC on an enterprise mail
		// domain, where a flipped `dmarcEnforcing` WOULD change the profile.
		const enterprise = (): CheckResult[] => [
			withSignals(buildCheckResult('mx', [createFinding('mx', 'MX records configured', 'info', 'Mail is routed via Google Workspace.')]), {
				controlPresent: true,
			}),
			withSignals(buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy set to reject', 'info', 'p=reject.')]), {
				controlPresent: true,
				recordPresent: true,
				metadata: { dmarcPolicy: 'reject' },
			}),
			withSignals(
				buildCheckResult('mta_sts', [createFinding('mta_sts', 'MTA-STS policy in enforce mode', 'info', 'mode: enforce.')]),
				MTA_STS_SIGNALS,
			),
		];

		const processed = await applyScanPostProcessing('example.com', enterprise());
		const rawContext = detectDomainContext(enterprise());
		const processedContext = detectDomainContext(processed);

		// NEGATIVE CONTROL FIRST — an invariance assertion is worthless unless the
		// instrument can detect the thing it claims is absent. Strip `controlPresent`
		// from the two profile-deciding categories and the profile MUST move; if it
		// does not, the assertions below are vacuous and prove nothing.
		const stripped = enterprise().map((result) =>
			result.category === 'mx' || result.category === 'dmarc' ? { ...result, controlPresent: undefined } : result,
		);
		expect(detectDomainContext(stripped).profile).not.toBe(rawContext.profile);

		expect(rawContext.profile).toBe('enterprise_mail');
		expect(processedContext.profile).toBe(rawContext.profile);
		expect(processedContext.weights).toEqual(rawContext.weights);
	});

	it('appendCdnFinding keeps the http_security signals when a heuristic CDN finding is appended', async () => {
		// Latent today (nothing on the `http_security` path sets these two — verified
		// by grep), but the same two-argument rebuild, so it is closed here too.
		vi.doMock('../src/lib/dns-records', () => ({
			queryDnsRecords: vi.fn().mockResolvedValue([]),
		}));
		vi.doMock('../src/lib/cdn-fallback-detection', () => ({
			detectCloudflareFallback: vi.fn().mockReturnValue({ isCloudflare: true, confidence: 'heuristic', signals: ['ns', 'ip'] }),
		}));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			mailBearingMx(),
			withSignals(
				buildCheckResult('http_security', [createFinding('http_security', 'HSTS enabled', 'info', 'Strict-Transport-Security present.')]),
				{ controlPresent: true, recordPresent: true, metadata: { tlsVersion: 'TLSv1.3' } },
			),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const http = updated.find((result) => result.category === 'http_security');

		expect(http?.metadata?.tlsVersion).toBe('TLSv1.3');
		expect(http?.controlPresent).toBe(true);
		expect(http?.recordPresent).toBe(true);
		vi.doUnmock('../src/lib/cdn-fallback-detection');
		vi.doUnmock('../src/lib/dns-records');
	});
});
