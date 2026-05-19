// SPDX-License-Identifier: BUSL-1.1

const ACCEPTANCE_REDUCTION_TARGET = 0.4;

/**
 * @param {{ rows: Array<Record<string, unknown>> }} input
 */
export function summarizeBenchmark(input) {
	const rows = Array.isArray(input?.rows) ? input.rows : [];
	const byDomain = new Map();
	for (const r of rows) {
		if (!r || typeof r !== 'object') continue;
		const domain = typeof r.domain === 'string' ? r.domain : null;
		if (!domain) continue;
		if (!byDomain.has(domain)) byDomain.set(domain, { observe: null, enforce: null });
		const bucket = byDomain.get(domain);
		if (r.mode === 'observe') bucket.observe = r;
		else if (r.mode === 'enforce') bucket.enforce = r;
	}

	const pairs = [];
	for (const [domain, { observe, enforce }] of byDomain) {
		const observeProbes = readProbes(observe);
		const enforceProbes = readProbes(enforce);
		const reductionPct =
			observeProbes != null && enforceProbes != null && observeProbes > 0
				? (1 - enforceProbes / observeProbes) * 100
				: null;
		const reductionMeets40 = reductionPct != null && reductionPct >= ACCEPTANCE_REDUCTION_TARGET * 100;
		const observeSurfaced = readSurfaced(observe);
		const enforceSurfaced = readSurfaced(enforce);
		const surfacedDelta = observeSurfaced != null && enforceSurfaced != null ? enforceSurfaced - observeSurfaced : null;
		const surfacedUnchanged = surfacedDelta != null && surfacedDelta >= 0;
		const bucketCountsDelta = compareBuckets(observe, enforce);
		const bucketCountsUnchanged = bucketCountsDelta != null && Object.values(bucketCountsDelta).every((v) => v === 0);
		const elapsedDeltaMs =
			typeof enforce?.elapsedMs === 'number' && typeof observe?.elapsedMs === 'number'
				? enforce.elapsedMs - observe.elapsedMs
				: null;
		const artifactsGenerated =
			Boolean(observe?.artifactJsonPath) && Boolean(enforce?.artifactJsonPath);
		const pdfsGenerated = Boolean(observe?.artifactPdfPath) && Boolean(enforce?.artifactPdfPath);
		pairs.push({
			domain,
			observe,
			enforce,
			observeProbes,
			enforceProbes,
			reductionPct,
			reductionMeets40,
			observeSurfaced,
			enforceSurfaced,
			surfacedDelta,
			surfacedUnchanged,
			bucketCountsDelta,
			bucketCountsUnchanged,
			elapsedDeltaMs,
			artifactsGenerated,
			pdfsGenerated,
		});
	}

	const overall = {
		domainsTested: pairs.length,
		pairsHittingReductionTarget: pairs.filter((p) => p.reductionMeets40).length,
		pairsWithSurfacedUnchanged: pairs.filter((p) => p.surfacedUnchanged).length,
		pairsWithAllArtifacts: pairs.filter((p) => p.artifactsGenerated && p.pdfsGenerated).length,
	};

	return { pairs, overall };
}

function readProbes(row) {
	if (!row || typeof row !== 'object') return null;
	const metrics = row.metrics;
	if (!metrics || typeof metrics !== 'object') return null;
	const direct = metrics.candidateSignalProbes;
	if (typeof direct === 'number' && Number.isFinite(direct)) return direct;
	const eff = metrics.plannerEfficiency;
	if (eff && typeof eff === 'object' && typeof eff.candidateSignalProbes === 'number') {
		return eff.candidateSignalProbes;
	}
	return null;
}

function readSurfaced(row) {
	if (!row || typeof row !== 'object') return null;
	const metrics = row.metrics;
	if (!metrics || typeof metrics !== 'object') return null;
	const eff = metrics.plannerEfficiency;
	if (eff && typeof eff === 'object' && typeof eff.surfacedCandidates === 'number') {
		return eff.surfacedCandidates;
	}
	const surfaced = metrics.candidateUniverse?.surfaced;
	return typeof surfaced === 'number' ? surfaced : null;
}

function compareBuckets(observe, enforce) {
	const a = observe?.metrics?.counts;
	const b = enforce?.metrics?.counts;
	if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return null;
	const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
	const delta = {};
	for (const key of keys) {
		const av = typeof a[key] === 'number' ? a[key] : 0;
		const bv = typeof b[key] === 'number' ? b[key] : 0;
		delta[key] = bv - av;
	}
	return delta;
}

/**
 * @param {ReturnType<typeof summarizeBenchmark>} summary
 */
export function formatAcceptanceSummary(summary) {
	const lines = [];
	lines.push('Acceptance Summary');
	lines.push('='.repeat(80));
	lines.push(
		[
			padRight('domain', 26),
			padLeft('reduction', 10),
			padLeft('surfacedDelta', 14),
			padLeft('bucketsΔ', 10),
			padLeft('elapsedΔms', 11),
			padLeft('artifacts', 10),
			padRight(' verdict', 10),
		].join(''),
	);
	lines.push('-'.repeat(80));

	for (const pair of summary.pairs) {
		const reductionText = pair.reductionPct == null ? 'n/a' : `${pair.reductionPct.toFixed(1)}%`;
		const surfacedText = pair.surfacedDelta == null ? 'n/a' : String(pair.surfacedDelta);
		const bucketsText = pair.bucketCountsDelta == null ? 'n/a' : bucketDeltaSummary(pair.bucketCountsDelta);
		const elapsedText = pair.elapsedDeltaMs == null ? 'n/a' : String(pair.elapsedDeltaMs);
		const artifactsText = pair.artifactsGenerated && pair.pdfsGenerated ? 'ok' : pair.artifactsGenerated ? 'json' : 'missing';
		const verdictText = verdictForPair(pair);
		lines.push(
			[
				padRight(pair.domain, 26),
				padLeft(reductionText, 10),
				padLeft(surfacedText, 14),
				padLeft(bucketsText, 10),
				padLeft(elapsedText, 11),
				padLeft(artifactsText, 10),
				padRight(' ' + verdictText, 10),
			].join(''),
		);
	}

	lines.push('-'.repeat(80));
	lines.push(
		`domains=${summary.overall.domainsTested} ` +
			`pairsHittingReductionTarget=${summary.overall.pairsHittingReductionTarget} ` +
			`pairsWithSurfacedUnchanged=${summary.overall.pairsWithSurfacedUnchanged} ` +
			`pairsWithAllArtifacts=${summary.overall.pairsWithAllArtifacts}`,
	);
	const enforceReady =
		summary.overall.domainsTested > 0 &&
		summary.overall.pairsHittingReductionTarget >= Math.ceil(summary.overall.domainsTested * 0.66) &&
		summary.overall.pairsWithSurfacedUnchanged >= Math.ceil(summary.overall.domainsTested * 0.66) &&
		summary.overall.pairsWithAllArtifacts === summary.overall.domainsTested;
	lines.push(`enforce-ready: ${enforceReady ? 'PASS' : 'FAIL'}`);

	return lines.join('\n');
}

function verdictForPair(pair) {
	const passes = pair.reductionMeets40 && pair.surfacedUnchanged && pair.artifactsGenerated && pair.pdfsGenerated;
	return passes ? 'PASS' : 'FAIL';
}

function bucketDeltaSummary(delta) {
	const entries = Object.entries(delta).filter(([, v]) => v !== 0);
	if (entries.length === 0) return '0';
	return entries.map(([k, v]) => `${k[0]}${v > 0 ? '+' : ''}${v}`).join(',');
}

function padRight(s, n) {
	const str = String(s);
	return str.length >= n ? str.slice(0, n) : str + ' '.repeat(n - str.length);
}

function padLeft(s, n) {
	const str = String(s);
	return str.length >= n ? str.slice(0, n) : ' '.repeat(n - str.length) + str;
}
