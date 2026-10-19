// SPDX-License-Identifier: BUSL-1.1

/**
 * Exact-output pins for the tool-output formatters split under the CRAP ceiling (SQ-375).
 *
 * The neighbouring specs assert with `toContain`, which tolerates reordered lines, dropped
 * separators and changed glyphs. These pins capture the base (pre-split) output byte for byte so
 * a behaviour-preserving split cannot drift unnoticed:
 *   - formatFixPlan / formatCompliance / formatSupplyChain / formatSgeQuickscan: full rendered
 *     strings for every format and branch.
 *   - resolveImpactNarrative: readable tier cases plus an exhaustive input sweep digest, so the
 *     match precedence cannot change.
 *   - filterBucketPayload (private; reached through scanBucketsFindings): the exact filtered shape
 *     of the recon payload, because a field leaking through would be a data-exposure regression.
 */

import { describe, it, expect } from 'vitest';
import type { CheckResult, Finding } from '../src/lib/scoring';
import type { FixPlanResult } from '../src/tools/generate-fix-plan';
import type { SupplyChainMap } from '../src/tools/map-supply-chain';

/** FNV-1a over a string; stable digest for large exhaustive sweeps. */
function digest(text: string): string {
	let h = 0x811c9dc5;
	for (let i = 0; i < text.length; i++) {
		h ^= text.charCodeAt(i);
		h = Math.imul(h, 0x01000193) >>> 0;
	}
	return `${h.toString(16)}:${text.length}`;
}

describe('resolveImpactNarrative pins', () => {
	const cases: Array<[string, Record<string, string | undefined>]> = [
		['signature outranks bucket entry', { checkType: 'spf', status: 'fail', detail: 'SPF record requires 10/10 DNS lookups.' }],
		['signature via category', { category: 'spf', severity: 'high', detail: 'SPF record requires 10/10 DNS lookups.' }],
		['type+status bucket entry', { checkType: 'dmarc', status: 'missing' }],
		['category-derived status entry', { category: 'dmarc', status: 'missing' }],
		[
			'specific rule (weak dkim)',
			{ category: 'dkim', severity: 'critical', title: 'Weak RSA key: selector1', detail: 'DKIM RSA key is weak' },
		],
		['severity entry via category', { category: 'dmarc', severity: 'low', title: 'Relaxed SPF alignment (aspf=r)', detail: 'x' }],
		['severity entry via type', { checkType: 'dmarc', severity: 'low' }],
		['category fallback via type', { checkType: 'ssl', severity: 'weird' }],
		['category fallback via category', { category: 'ssl', severity: 'weird' }],
		['severity fallback', { severity: 'high' }],
		['severity fallback unknown', { severity: 'weird' }],
		['empty', {}],
	];

	it('pins each precedence tier output', async () => {
		const { resolveImpactNarrative } = await import('../src/tools/explain-finding');
		const out = Object.fromEntries(cases.map(([name, params]) => [name, resolveImpactNarrative(params)]));
		expect(out).toMatchInlineSnapshot(`
			{
			  "category fallback via category": {
			    "adverseConsequences": "Sensitive user data may be exposed and browser trust can decline.",
			    "impact": "Transport security guarantees are reduced, increasing interception and tampering risk.",
			  },
			  "category fallback via type": {
			    "adverseConsequences": "Sensitive user data may be exposed and browser trust can decline.",
			    "impact": "Transport security guarantees are reduced, increasing interception and tampering risk.",
			  },
			  "category-derived status entry": {
			    "adverseConsequences": "Forged messages are more likely to reach users and erode brand trust.",
			    "impact": "DMARC enforcement is reduced or absent at receiving systems.",
			  },
			  "empty": {},
			  "severity entry via category": {
			    "adverseConsequences": "Borderline spoofing techniques may pass alignment and some diagnostic detail is unavailable.",
			    "impact": "Alignment is looser or reporting is less complete than the strictest posture.",
			  },
			  "severity entry via type": {
			    "adverseConsequences": "Borderline spoofing techniques may pass alignment and some diagnostic detail is unavailable.",
			    "impact": "Alignment is looser or reporting is less complete than the strictest posture.",
			  },
			  "severity fallback": {
			    "adverseConsequences": "Business operations, user trust, and response workload can be negatively affected.",
			    "impact": "This weakness materially increases attack surface and failure risk.",
			  },
			  "severity fallback unknown": {},
			  "signature outranks bucket entry": {
			    "adverseConsequences": "Legitimate mail can be rejected or spam-foldered, and because DMARC cannot rely on an SPF PermError the domain also loses that half of its anti-spoofing protection.",
			    "impact": "SPF evaluation is one added include away from PermError — or already failing — so the domain gets no reliable SPF result at receivers.",
			  },
			  "signature via category": {
			    "adverseConsequences": "Legitimate mail can be rejected or spam-foldered, and because DMARC cannot rely on an SPF PermError the domain also loses that half of its anti-spoofing protection.",
			    "impact": "SPF evaluation is one added include away from PermError — or already failing — so the domain gets no reliable SPF result at receivers.",
			  },
			  "specific rule (weak dkim)": {
			    "adverseConsequences": "A forged but validly-signed message would pass DKIM and DMARC, making impersonation highly credible.",
			    "impact": "The authenticity guarantee DKIM provides for this selector is weaker than intended.",
			  },
			  "type+status bucket entry": {
			    "adverseConsequences": "Forged messages are more likely to reach users and erode brand trust.",
			    "impact": "DMARC enforcement is reduced or absent at receiving systems.",
			  },
			}
		`);
	});

	it('pins the exhaustive input sweep (tier precedence digest)', async () => {
		const { resolveImpactNarrative } = await import('../src/tools/explain-finding');
		const checkTypes = [undefined, 'SPF', 'dmarc', 'DKIM', 'SSL', 'ZZZ'];
		const categories = [undefined, 'spf', 'dkim', 'dmarc', 'ssl', 'weird'];
		const statuses = [undefined, 'FAIL', 'missing', 'pass'];
		const severities = [undefined, 'high', 'low', 'critical', 'weird'];
		const titles = [undefined, 'Weak RSA key: selector1', 'No aggregate reporting', 'zzz'];
		const details = [
			undefined,
			'SPF record requires 10/10 DNS lookups.',
			'DKIM RSA key is weak',
			'No aggregate report URI (rua=) specified',
			'unrelated',
		];
		const rows: string[] = [];
		let tiers = 0;
		for (const checkType of checkTypes)
			for (const category of categories)
				for (const status of statuses)
					for (const severity of severities)
						for (const title of titles)
							for (const detail of details) {
								const n = resolveImpactNarrative({ checkType, category, status, severity, title, detail });
								rows.push(JSON.stringify(n));
								tiers++;
							}
		expect(tiers).toBe(14400);
		expect(digest(rows.join('\n'))).toMatchInlineSnapshot(`"d32cd2ac:3082529"`);
	});
});

describe('formatFixPlan pins', () => {
	const action = (n: number, over: Partial<FixPlanResult['actions'][number]> = {}) => ({
		priority: n,
		category: 'spf' as const,
		action: `Fix thing ${n}`,
		severity: 'high' as const,
		effort: 'low' as const,
		impact: 'medium' as const,
		dependencies: [] as string[],
		findingTitle: `finding ${n}`,
		...over,
	});
	const base = (over: Partial<FixPlanResult>): FixPlanResult => ({
		domain: 'fp.example',
		score: 71,
		grade: 'C+',
		maturityStage: 2,
		totalActions: 0,
		actions: [],
		assessed: true,
		caveat: null,
		transientCategories: [],
		...over,
	});
	const seven = Array.from({ length: 7 }, (_, i) =>
		action(i + 1, { category: i % 2 ? 'dmarc' : 'spf', severity: i % 3 ? 'medium' : 'critical' }),
	);
	const plans: Record<string, FixPlanResult> = {
		unassessed: base({ score: null, grade: null, maturityStage: null, assessed: false, caveat: 'Nothing ran.' }),
		unassessedNoCaveat: base({ assessed: false, caveat: null }),
		transientOne: base({ transientCategories: ['dkim'] }),
		transientTwo: base({ transientCategories: ['dkim', 'ssl'] }),
		clean: base({ score: 95, grade: 'A+', maturityStage: 4 }),
		oneAction: base({ totalActions: 1, actions: [action(1)] }),
		sevenActions: base({ totalActions: 7, actions: seven }),
		sevenActionsTransient: base({ totalActions: 7, actions: seven, transientCategories: ['ns', 'caa'] }),
		withDeps: base({
			totalActions: 2,
			actions: [
				action(1, { dependencies: ['Publish SPF', 'Publish DKIM'] }),
				action(2, { effort: 'high', impact: 'critical', action: 'x'.repeat(200) }),
			],
			transientCategories: ['mx'],
		}),
	};

	it.each(['compact', 'full'] as const)('renders every branch exactly [%s]', async (format) => {
		const { formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const out = Object.fromEntries(Object.entries(plans).map(([name, plan]) => [name, formatFixPlan(plan, format)]));
		expect(out).toMatchSnapshot();
	});
});

describe('formatCompliance pins', () => {
	function res(category: string, passed: boolean, findings: Array<{ title: string; severity: string }> = []): CheckResult {
		return {
			category,
			passed,
			score: passed ? 100 : 40,
			findings: findings.map((f) => ({ category, title: f.title, severity: f.severity, detail: f.title })) as Finding[],
		} as CheckResult;
	}
	const all = ['spf', 'dkim', 'dmarc', 'mta_sts', 'dane', 'tlsrpt', 'dnssec', 'caa', 'ssl', 'http_security', 'ns'];

	it.each(['compact', 'full'] as const)('renders every branch exactly [%s]', async (format) => {
		const { evaluateCompliance, formatCompliance } = await import('../src/tools/map-compliance');
		const mixed = [
			...all.filter((c) => !['mta_sts', 'dnssec', 'spf'].includes(c)).map((c) => res(c, true)),
			res('mta_sts', false, [{ title: 'No MTA-STS record', severity: 'medium' }]),
			res('dnssec', false, [
				{ title: 'DNSSEC not enabled', severity: 'high' },
				{ title: 'second finding', severity: 'low' },
			]),
			res('spf', true, [{ title: 'TXT RRset exceeds UDP limit', severity: 'medium' }]),
		];
		const reports = {
			mixed: evaluateCompliance(mixed, 'fmt.example', 71, 'C+'),
			allPassing: evaluateCompliance(
				all.map((c) => res(c, true)),
				'pass.example',
				95,
				'A+',
			),
			ungraded: evaluateCompliance([], 'never-measured.example', null, null),
			sparse: evaluateCompliance(
				[res('spf', true), res('dmarc', false, [{ title: 'p=none', severity: 'medium' }])],
				'sparse.example',
				50,
				'D',
			),
		};
		const out = Object.fromEntries(Object.entries(reports).map(([name, report]) => [name, formatCompliance(report, format)]));
		expect(out).toMatchSnapshot();
	});

	it('uses the generic fallback when an unassessed report somehow lacks a caveat', async () => {
		const { evaluateCompliance, formatCompliance } = await import('../src/tools/map-compliance');
		const report = { ...evaluateCompliance([], 'nocaveat.example', null, null), caveat: undefined } as never;
		expect(formatCompliance(report, 'compact')).toMatchSnapshot();
		expect(formatCompliance(report, 'full')).toMatchSnapshot();
	});
});

describe('formatSgeQuickscan pins', () => {
	function result(category: string, over: Partial<CheckResult> = {}): CheckResult {
		return { category, passed: true, score: 100, findings: [] as Finding[], ...over } as CheckResult;
	}
	const MX = result('mx', { controlPresent: true });
	const GOOD: CheckResult[] = [
		MX,
		result('dmarc', { controlPresent: true, recordPresent: true }),
		result('spf', { metadata: { spfAll: '-all' } }),
		result('dkim', { controlPresent: true }),
		result('mta_sts', { recordPresent: true, metadata: { mtaStsMode: 'enforce' } }),
		result('tlsrpt', { recordPresent: true }),
	];
	const BAD: CheckResult[] = [
		MX,
		result('dmarc', { controlPresent: false, recordPresent: true }),
		result('spf', { metadata: { spfAll: '~all' } }),
		result('dkim', { controlPresent: true }),
		result('mta_sts', { recordPresent: true, metadata: { mtaStsMode: 'testing' } }),
		result('tlsrpt', { recordPresent: false }),
	];
	const ABSTAIN: CheckResult[] = ['mx', 'dmarc', 'spf', 'dkim', 'mta_sts', 'tlsrpt'].map((c) =>
		result(c, { checkStatus: 'timeout' } as Partial<CheckResult>),
	);

	it.each(['compact', 'full'] as const)('renders every branch exactly [%s]', async (format) => {
		const { buildSgeQuickscanReport, formatSgeQuickscan } = await import('../src/tools/sge-quickscan');
		const good = buildSgeQuickscanReport('good.example', GOOD);
		const withAdvisories = {
			...buildSgeQuickscanReport('adv.example', BAD),
			advisories: [
				{
					id: 'a1',
					label: 'Exposed thing',
					severity: 'exposure',
					relatedControl: 'dmarc',
					summary: 'An exposure summary.',
					evidence: [
						{ signal: 'sig_a', value: 'text' },
						{ signal: 'sig_b', value: true },
						{ signal: 'sig_c', value: 7 },
						{ signal: 'sig_d', value: undefined },
					],
				},
				{ id: 'a2', label: 'Note', severity: 'advisory', relatedControl: 'spf', summary: 'A note.', evidence: [] },
			],
		} as never;
		const reports = {
			good,
			bad: buildSgeQuickscanReport('bad.example', BAD),
			abstaining: buildSgeQuickscanReport('abstain.example', ABSTAIN),
			noMx: buildSgeQuickscanReport('nomx.example', [result('mx', { controlPresent: false }), ...GOOD.slice(1)]),
			withAdvisories,
		};
		const out = Object.fromEntries(Object.entries(reports).map(([name, report]) => [name, formatSgeQuickscan(report, format)]));
		expect(out).toMatchSnapshot();
	});
});

describe('formatSupplyChain pins', () => {
	const summary = { totalProviders: 4, critical: 1, high: 1, medium: 1, low: 1 };
	const dep = (provider: string, trustLevel: 'critical' | 'high' | 'medium' | 'low') => ({
		provider,
		roles: ['mail', 'dns'],
		trustLevel,
		sources: ['mx', 'txt'],
	});
	const maps: Record<string, SupplyChainMap> = {
		allTrustLevels: {
			domain: 'sc.example',
			dependencies: [dep('Prov A', 'critical'), dep('Prov B', 'high'), dep('Prov C', 'medium'), dep('Prov D', 'low')],
			signals: [
				{ type: 'concentration', severity: 'high', detail: 'High signal.' },
				{ type: 'excessive_includes', severity: 'medium', detail: 'Medium signal.' },
				{ type: 'stale_integration', severity: 'low', detail: 'Low signal.' },
				{ type: 'null_mx', severity: 'info', detail: 'Info signal.' },
			],
			summary,
		},
		depsWithUnmeasured: {
			domain: 'sc.example',
			dependencies: [dep('Prov A', 'high')],
			signals: [],
			summary: { totalProviders: 1, critical: 0, high: 1, medium: 0, low: 0 },
			unmeasured: [
				{ source: 'txt', reason: 'inconclusive' },
				{ source: 'ns', reason: 'rejected' },
			],
		},
		emptyUnmeasured: {
			domain: 'empty.example',
			dependencies: [],
			signals: [{ type: 'caa_no_issuance', severity: 'info', detail: 'CAA forbids issuance.' }],
			summary: { totalProviders: 0, critical: 0, high: 0, medium: 0, low: 0 },
			unmeasured: [{ source: 'mx', reason: 'inconclusive' }],
		},
		emptyClean: {
			domain: 'clean.example',
			dependencies: [],
			signals: [],
			summary: { totalProviders: 0, critical: 0, high: 0, medium: 0, low: 0 },
		},
		emptyUnmeasuredList: {
			domain: 'emptylist.example',
			dependencies: [],
			signals: [],
			summary: { totalProviders: 0, critical: 0, high: 0, medium: 0, low: 0 },
			unmeasured: [],
		},
	};

	it.each(['compact', 'full'] as const)('renders every branch exactly [%s]', async (format) => {
		const { formatSupplyChain } = await import('../src/tools/map-supply-chain');
		const out = Object.fromEntries(Object.entries(maps).map(([name, map]) => [name, formatSupplyChain(map, format)]));
		expect(out).toMatchSnapshot();
	});
});

describe('filterBucketPayload pins (via scanBucketsFindings)', () => {
	function binding(body: unknown) {
		return { fetch: async () => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }) };
	}
	async function run(payload: unknown, args: { target?: string; providers?: string[] }) {
		const { scanBucketsFindings } = await import('../src/tools/scan-buckets');
		const r = await scanBucketsFindings({ scanId: 's1', ...args }, { reconBinding: binding(payload), reconAuthToken: 't' });
		return { detail: String(r.findings[0]!.detail), metadata: r.findings[0]!.metadata };
	}

	it('passes the payload through untouched with no scope or no array', async () => {
		const noScope = await run({ success: true, data: [{ bucketName: 'a' }, { bucketName: 'b' }], count: 2 }, {});
		const noArray = await run({ success: true, data: 'nope', findings: 'nope', count: 2 }, { target: 'acme.test', providers: ['aws'] });
		expect({ noScope, noArray }).toMatchInlineSnapshot(`
			{
			  "noArray": {
			    "detail": "{"success":true,"data":"nope","findings":"nope","count":2}",
			    "metadata": {
			      "confidence": "deterministic",
			      "count": 2,
			      "data": "nope",
			      "findings": "nope",
			      "success": true,
			      "summary": true,
			    },
			  },
			  "noScope": {
			    "detail": "{"success":true,"data": {"bucketName":"a"},{"bucketName":"b"} ,"count":2}",
			    "metadata": {
			      "confidence": "deterministic",
			      "count": 2,
			      "data": [
			        {
			          "bucketName": "a",
			        },
			        {
			          "bucketName": "b",
			        },
			      ],
			      "success": true,
			      "summary": true,
			    },
			  },
			}
		`);
	});

	it('drops out-of-scope rows, keeps non-object rows, samples at most 5 names', async () => {
		const rows = [
			{ bucketName: 'acme-keep', provider: 's3', secret: 'kept-as-is' },
			{ bucket: 'other-1', provider: 's3' },
			{ name: 'other-2', provider: 's3' },
			{ containerName: 'OTHER-3', provider: 's3' },
			{ endpoint: 'https://other-4.s3.amazonaws.com', provider: 's3' },
			{ provider: 's3' },
			{ bucketName: 'other-6', provider: 's3' },
			{ bucketName: 'other-7', provider: 's3' },
			{ endpoint: 'acme.s3.amazonaws.com', provider: 'aws_s3' },
			null,
			'a-string-row',
			[1, 2],
			{ bucketName: 'acme-azure', provider: 'azure_blob' },
			{ bucketName: 'acme-noprovider' },
			{ bucketName: 'acme-numprovider', provider: 7 },
		];
		const out = await run(
			{ success: true, data: rows, count: rows.length, extra: 'x' },
			{ target: 'https://Acme.test/path', providers: ['aws'] },
		);
		expect(out).toMatchInlineSnapshot(`
			{
			  "detail": "Bucket findings filtered 8 out-of-scope upstream candidate(s). {"success":true,"data": {"bucketName":"acme-keep","provider":"s3","secret":"kept-as-is"},{"endpoint":"acme.s3.amazonaws.com","provider":"aws_s3"},null,"a-string-row", 1,2 ,{"bucketName":"acme-noprovider"},{"bucketName":"acme-numprovider","provider":7} ,"count":7,"extra":"x","originalCount":15,"filteredOutOfScopeCount":8,"filteredOutOfScopeSamples": "other-1","other-2","other-3","https://other-4.s3.amazonaws.com","(unnamed bucket)" ,"targetScope":"acme.test","providerScope": "aws" }",
			  "metadata": {
			    "confidence": "deterministic",
			    "count": 7,
			    "data": [
			      {
			        "bucketName": "acme-keep",
			        "provider": "s3",
			        "secret": "kept-as-is",
			      },
			      {
			        "endpoint": "acme.s3.amazonaws.com",
			        "provider": "aws_s3",
			      },
			      null,
			      "a-string-row",
			      [
			        1,
			        2,
			      ],
			      {
			        "bucketName": "acme-noprovider",
			      },
			      {
			        "bucketName": "acme-numprovider",
			        "provider": 7,
			      },
			    ],
			    "extra": "x",
			    "filteredOutOfScopeCount": 8,
			    "filteredOutOfScopeSamples": [
			      "other-1",
			      "other-2",
			      "other-3",
			      "https://other-4.s3.amazonaws.com",
			      "(unnamed bucket)",
			    ],
			    "originalCount": 15,
			    "providerScope": [
			      "aws",
			    ],
			    "success": true,
			    "summary": true,
			    "targetScope": "acme.test",
			  },
			}
		`);
	});

	it('filters the `findings` array key and leaves count undefined when upstream sent none', async () => {
		const out = await run(
			{
				success: true,
				findings: [
					{ bucketName: 'acme-a', provider: 's3' },
					{ bucketName: 'zzz-b', provider: 's3' },
				],
			},
			{ target: 'acme.test' },
		);
		expect(out).toMatchInlineSnapshot(`
			{
			  "detail": "Bucket findings filtered 1 out-of-scope upstream candidate(s). {"success":true,"findings": {"bucketName":"acme-a","provider":"s3"} ,"originalCount":2,"filteredOutOfScopeCount":1,"filteredOutOfScopeSamples": "zzz-b" ,"targetScope":"acme.test"}",
			  "metadata": {
			    "confidence": "deterministic",
			    "count": undefined,
			    "filteredOutOfScopeCount": 1,
			    "filteredOutOfScopeSamples": [
			      "zzz-b",
			    ],
			    "findings": [
			      {
			        "bucketName": "acme-a",
			        "provider": "s3",
			      },
			    ],
			    "originalCount": 2,
			    "providerScope": undefined,
			    "success": true,
			    "summary": true,
			    "targetScope": "acme.test",
			  },
			}
		`);
	});

	it('filters by provider alone when there is no target', async () => {
		const out = await run(
			{
				success: true,
				data: [
					{ bucketName: 'a', provider: 'gcp_storage' },
					{ bucketName: 'b', provider: 'azure_blob' },
					{ bucketName: 'c', provider: 'digitalocean_spaces' },
					{ bucketName: 'd', provider: '!!!' },
				],
				count: 4,
			},
			{ providers: ['gcp', 'azure'] },
		);
		expect(out).toMatchInlineSnapshot(`
			{
			  "detail": "Bucket findings filtered 1 out-of-scope upstream candidate(s). {"success":true,"data": {"bucketName":"a","provider":"gcp_storage"},{"bucketName":"b","provider":"azure_blob"},{"bucketName":"d","provider":"!!!"} ,"count":3,"originalCount":4,"filteredOutOfScopeCount":1,"filteredOutOfScopeSamples": "c" ,"providerScope": "gcp","azure" }",
			  "metadata": {
			    "confidence": "deterministic",
			    "count": 3,
			    "data": [
			      {
			        "bucketName": "a",
			        "provider": "gcp_storage",
			      },
			      {
			        "bucketName": "b",
			        "provider": "azure_blob",
			      },
			      {
			        "bucketName": "d",
			        "provider": "!!!",
			      },
			    ],
			    "filteredOutOfScopeCount": 1,
			    "filteredOutOfScopeSamples": [
			      "c",
			    ],
			    "originalCount": 4,
			    "providerScope": [
			      "gcp",
			      "azure",
			    ],
			    "success": true,
			    "summary": true,
			    "targetScope": undefined,
			  },
			}
		`);
	});

	it('returns the payload unchanged when everything is in scope', async () => {
		const out = await run(
			{ success: true, data: [{ bucketName: 'acme-1', provider: 's3' }], count: 1 },
			{ target: 'acme.test', providers: ['aws'] },
		);
		expect(out).toMatchInlineSnapshot(`
			{
			  "detail": "{"success":true,"data": {"bucketName":"acme-1","provider":"s3"} ,"count":1}",
			  "metadata": {
			    "confidence": "deterministic",
			    "count": 1,
			    "data": [
			      {
			        "bucketName": "acme-1",
			        "provider": "s3",
			      },
			    ],
			    "success": true,
			    "summary": true,
			  },
			}
		`);
	});

	it('caps the emitted array and marks truncation, with and without filtered rows and upstream count', async () => {
		const inScope = Array.from({ length: 205 }, (_, i) => ({ bucketName: `acme-${i}`, provider: 's3' }));
		const summarise = (o: Awaited<ReturnType<typeof run>>) => {
			const { data, findings, ...rest } = o.metadata as Record<string, unknown>;
			const arr = (data ?? findings) as Array<{ bucketName: string }>;
			return { detailPrefix: o.detail.slice(0, 70), length: arr.length, first: arr[0]?.bucketName, last: arr.at(-1)?.bucketName, rest };
		};
		const withCount = await run({ success: true, data: inScope, count: 300 }, { target: 'acme.test', providers: ['aws'] });
		const withoutCount = await run({ success: true, data: inScope }, { target: 'acme.test', providers: ['aws'] });
		const withFiltered = await run(
			{ success: true, data: [...inScope, { bucketName: 'zzz', provider: 's3' }], count: 206 },
			{ target: 'acme.test', providers: ['aws'] },
		);
		expect({ withCount: summarise(withCount), withoutCount: summarise(withoutCount), withFiltered: summarise(withFiltered) })
			.toMatchInlineSnapshot(`
			{
			  "withCount": {
			    "detailPrefix": "{"success":true,"data": {"bucketName":"acme-0","provider":"s3"},{"buck",
			    "first": "acme-0",
			    "last": "acme-199",
			    "length": 200,
			    "rest": {
			      "confidence": "deterministic",
			      "count": 205,
			      "filteredOutOfScopeCount": 0,
			      "filteredOutOfScopeSamples": [],
			      "keptCap": 200,
			      "keptTotal": 205,
			      "keptTruncated": true,
			      "originalCount": 300,
			      "providerScope": [
			        "aws",
			      ],
			      "success": true,
			      "summary": true,
			      "targetScope": "acme.test",
			    },
			  },
			  "withFiltered": {
			    "detailPrefix": "Bucket findings filtered 1 out-of-scope upstream candidate(s). {"succe",
			    "first": "acme-0",
			    "last": "acme-199",
			    "length": 200,
			    "rest": {
			      "confidence": "deterministic",
			      "count": 205,
			      "filteredOutOfScopeCount": 1,
			      "filteredOutOfScopeSamples": [
			        "zzz",
			      ],
			      "keptCap": 200,
			      "keptTotal": 205,
			      "keptTruncated": true,
			      "originalCount": 206,
			      "providerScope": [
			        "aws",
			      ],
			      "success": true,
			      "summary": true,
			      "targetScope": "acme.test",
			    },
			  },
			  "withoutCount": {
			    "detailPrefix": "{"success":true,"data": {"bucketName":"acme-0","provider":"s3"},{"buck",
			    "first": "acme-0",
			    "last": "acme-199",
			    "length": 200,
			    "rest": {
			      "confidence": "deterministic",
			      "count": undefined,
			      "filteredOutOfScopeCount": 0,
			      "filteredOutOfScopeSamples": [],
			      "keptCap": 200,
			      "keptTotal": 205,
			      "keptTruncated": true,
			      "originalCount": 205,
			      "providerScope": [
			        "aws",
			      ],
			      "success": true,
			      "summary": true,
			      "targetScope": "acme.test",
			    },
			  },
			}
		`);
	});
});
