// SPDX-License-Identifier: BUSL-1.1

/**
 * Output pin for checkSVCBHTTPS and its (module-private) RFC 3597 wire parser (SQ-378, CRAP H1).
 *
 * Each case snapshots the COMPLETE CheckResult and the DNS query sequence, so a
 * behaviour-preserving split of parseHttpsRecordWire / checkSVCBHTTPS cannot move a finding,
 * its order, severity, title, detail or metadata. Snapshots were captured from the pre-split
 * implementation and must not be regenerated to make a refactor pass.
 */

import { describe, it, expect } from 'vitest';
import { checkSVCBHTTPS } from '../src/checks/check-svcb-https';
import type { DNSQueryFunction } from '../src/types';

const hex = (bytes: number[]) => bytes.map((b) => b.toString(16).padStart(2, '0')).join('');

/** Build an RFC 3597 `\# <len> <hex>` HTTPS rdata string. */
function wire(opts: { priority: number; target?: number[]; alpn?: string[]; ech?: boolean; extra?: number[] }): string {
	const bytes: number[] = [(opts.priority >> 8) & 0xff, opts.priority & 0xff, ...(opts.target ?? [0])];
	if (opts.alpn) {
		const value = opts.alpn.flatMap((p) => [p.length, ...Array.from(p).map((c) => c.charCodeAt(0))]);
		bytes.push(0, 1, 0, value.length, ...value);
	}
	if (opts.ech) bytes.push(0, 5, 0, 2, 0xaa, 0xbb);
	if (opts.extra) bytes.push(...opts.extra);
	return `\\# ${bytes.length} ${hex(bytes)}`;
}

async function pin(records: string[] | Error, opts?: { timeout?: number }) {
	const calls: string[] = [];
	const queryDNS = (async (name: string, type: string, o?: { timeout?: number }) => {
		calls.push(`${type} ${name} timeout=${o?.timeout}`);
		if (records instanceof Error) throw records;
		return records;
	}) as DNSQueryFunction;
	const result = await checkSVCBHTTPS('example.com', queryDNS, opts);
	return { result, calls };
}

describe('checkSVCBHTTPS output pin', () => {
	it('query throws: not assessed', async () => {
		expect(await pin(new Error('timeout'))).toMatchSnapshot();
	});

	it('no HTTPS record', async () => {
		expect(await pin([])).toMatchSnapshot();
	});

	it('custom timeout is passed to the single HTTPS query', async () => {
		expect(await pin(['1 . alpn=h2'], { timeout: 777 })).toMatchSnapshot();
	});

	describe('presentation format', () => {
		it('service mode with h2,h3 and ech', async () => {
			expect(await pin(['1 . alpn=h2,h3 ech=AEn+DQA']) ).toMatchSnapshot();
		});

		it('quoted alpn list with spaces', async () => {
			expect(await pin(['1 . alpn="h2, h3"'])).toMatchSnapshot();
		});

		it('service mode h2 only', async () => {
			expect(await pin(['1 . alpn=h2'])).toMatchSnapshot();
		});

		it('service mode without ALPN', async () => {
			expect(await pin(['1 . port=443'])).toMatchSnapshot();
		});

		it('service mode with ALPN but no h2', async () => {
			expect(await pin(['1 . alpn=http/1.1'])).toMatchSnapshot();
		});

		it('alias mode only', async () => {
			expect(await pin(['0 cdn.example.net.'])).toMatchSnapshot();
		});

		it('alias first then service without ALPN: missing-ALPN and no-h2 findings are suppressed', async () => {
			expect(await pin(['0 cdn.example.net.', '1 . port=443'])).toMatchSnapshot();
		});

		it('service without ALPN first then alias: missing-ALPN fires, no-h2 suppressed by alias', async () => {
			expect(await pin(['1 . port=443', '0 cdn.example.net.'])).toMatchSnapshot();
		});

		it('multiple service records aggregating h2 and h3 across records', async () => {
			expect(await pin(['1 . alpn=h2', '2 . alpn=h3 ech=xyz'])).toMatchSnapshot();
		});

		it('unparseable priority is treated as service mode with null priority', async () => {
			expect(await pin(['garbage'])).toMatchSnapshot();
		});
	});

	describe('wire format (RFC 3597)', () => {
		it('service mode h2,h3 + ECH', async () => {
			expect(await pin([wire({ priority: 1, alpn: ['h2', 'h3'], ech: true })])).toMatchSnapshot();
		});

		it('service mode h2 only, no ECH', async () => {
			expect(await pin([wire({ priority: 1, alpn: ['h2'] })])).toMatchSnapshot();
		});

		it('service mode with no params at all', async () => {
			expect(await pin([wire({ priority: 1 })])).toMatchSnapshot();
		});

		it('alias mode (priority 0)', async () => {
			expect(await pin([wire({ priority: 0, target: [3, 0x63, 0x64, 0x6e, 0] })])).toMatchSnapshot();
		});

		it('non-root TargetName labels are skipped', async () => {
			expect(await pin([wire({ priority: 1, target: [3, 0x77, 0x77, 0x77, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0], alpn: ['h2'] })])).toMatchSnapshot();
		});

		it('bare `#` prefix (no backslash) is accepted', async () => {
			const w = wire({ priority: 1, alpn: ['h2'] }).replace('\\#', '#');
			expect(await pin([w])).toMatchSnapshot();
		});

		it('unknown param keys are skipped; ECH key sets the flag', async () => {
			expect(await pin([wire({ priority: 1, alpn: ['h2'], extra: [0, 3, 0, 2, 0x01, 0xbb, 0, 5, 0, 0] })])).toMatchSnapshot();
		});

		it('truncated trailing param stops the parse but keeps what was read', async () => {
			expect(await pin([wire({ priority: 1, alpn: ['h2'], extra: [0, 9, 0, 50, 1, 2] })])).toMatchSnapshot();
		});

		it('truncated ALPN entry inside the value is dropped', async () => {
			// key=1, len=3, value = [5, 'a', 'b'] -> first string length overruns the value
			expect(await pin([wire({ priority: 1, extra: [0, 1, 0, 3, 5, 0x61, 0x62] })])).toMatchSnapshot();
		});

		it('declared length mismatch falls back to presentation parsing', async () => {
			expect(await pin(['\\# 9 00010000'])).toMatchSnapshot();
		});

		it('declared length below the 3-byte floor falls back', async () => {
			expect(await pin(['\\# 2 0001'])).toMatchSnapshot();
		});

		it('non-numeric declared length falls back', async () => {
			expect(await pin(['\\# xx 000100'])).toMatchSnapshot();
		});

		it('non-hex byte falls back', async () => {
			expect(await pin(['\\# 3 0001zz'])).toMatchSnapshot();
		});

		it('compression pointer in TargetName falls back', async () => {
			expect(await pin([`\\# 5 ${hex([0, 1, 0xc0, 0x0c, 0])}`])).toMatchSnapshot();
		});

		it('TargetName label overrunning the buffer falls back', async () => {
			expect(await pin([`\\# 4 ${hex([0, 1, 9, 0x61])}`])).toMatchSnapshot();
		});

		it('hex split across whitespace-separated groups is joined', async () => {
			expect(await pin(['\\# 7 0001 00 0001 0000'])).toMatchSnapshot();
		});

		it('# without a following length falls back', async () => {
			expect(await pin(['#'])).toMatchSnapshot();
		});
	});

	it('invariant: an absent HTTPS record is advisory (low, no penalty), never a missing control', async () => {
		const { result } = await pin([]);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]).toMatchObject({ title: 'No HTTPS record found', severity: 'low' });
		expect(result.findings[0].metadata?.missingControl).toBeUndefined();
		expect(result.recordPresent).toBe(false);
	});
});
