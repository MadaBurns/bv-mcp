import { describe, expect, it } from 'vitest';
import postProcessingSource from '../src/tools/scan/post-processing.ts?raw';

/**
 * #994 tripwire — a two-argument `buildCheckResult(category, findings)` call
 * COMPILES FINE against the five-argument signature, which is exactly why the
 * signal drop shipped and survived a live production release. The behavioural
 * proof lives in `scan-post-processing-signal-preservation.spec.ts`; this audit
 * exists so a NEW rebuild site added tomorrow cannot re-open the same hole
 * silently, in a path no behavioural test happens to cover.
 *
 * The rule: inside `src/tools/scan/post-processing.ts`, `buildCheckResult` may be
 * called from exactly ONE place — `rebuildPreservingSignals`, which forwards
 * `controlPresent` / `recordPresent` / `metadata` from the source result. Any
 * other call must carry an explicit `bv-signals-checked:` marker stating why
 * there is nothing to carry. A marker is a decision on the record, not a silent
 * omission.
 */
describe('post-processing buildCheckResult chokepoint (#994)', () => {
	const lines = postProcessingSource.split('\n');
	// Skip COMMENT lines. A census that counts prose reads a docblock explaining the
	// rule as a violation of it — this audit's first run tripped on its own three
	// explanatory comments, and an audit that cries wolf gets its marker pasted in
	// everywhere, which is how the rule dies.
	const isComment = (text: string) => /^\s*(\/\/|\/\*|\*)/.test(text);
	const callLines = lines
		.map((text, index) => ({ text, line: index + 1 }))
		.filter(({ text }) => /\bbuildCheckResult\s*\(/.test(text) && !isComment(text));

	it('positive control: the audit can see buildCheckResult calls at all', () => {
		// A zero here would make every assertion below vacuously green.
		expect(callLines.length).toBeGreaterThan(0);
	});

	it('every buildCheckResult call is either the chokepoint or explicitly signals-checked', () => {
		const offenders = callLines.filter(({ text, line }) => {
			// The chokepoint itself.
			if (text.includes('buildCheckResult(source.category, adjusted, source.controlPresent, source.recordPresent, source.metadata)')) {
				return false;
			}
			// An explicit, reasoned exemption on the immediately preceding line.
			const previous = lines[line - 2] ?? '';
			return !previous.includes('bv-signals-checked:');
		});

		expect(
			offenders.map(({ line, text }) => `post-processing.ts:${line}  ${text.trim()}`),
			'A rebuild here must go through rebuildPreservingSignals (#994), or carry a `// bv-signals-checked: <why>` comment on the line above.',
		).toEqual([]);
	});

	it('the chokepoint helper still forwards all three signals', () => {
		// Guards the other direction: an edit that keeps the helper's NAME but drops
		// an argument would make the rule above pass while re-creating the defect.
		expect(postProcessingSource).toContain(
			'return buildCheckResult(source.category, adjusted, source.controlPresent, source.recordPresent, source.metadata);',
		);
	});
});
