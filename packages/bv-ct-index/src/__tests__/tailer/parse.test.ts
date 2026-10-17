// SPDX-License-Identifier: BUSL-1.1
/**
 * The tailer's pure parts on real CT data: the TBSCertificate walker, RFC 6962 leaves, static-ct data
 * tiles and tile paths, the log-list filter, observations (wildcard fold, siblings, the 32-apex cap), the
 * cross-log dedupe and the message split.
 */

import { describe, expect, it } from 'vitest';
import { nameKey, siblingKey } from '../../codec';
import { checkpointTreeSize, parseDataTile, precertTbsFromLeafInput, selectLogs, tilePath } from '../../tailer/ct';
import { MAX_MESSAGE_BYTES, newObservationSet, newRows, observeCert, toBatches } from '../../tailer/observations';
import { parseTbsCertificate } from '../../tailer/x509';
import type { NameObservation, RunRow } from '../../types';
import {
	LOG_LIST,
	MULTI_APEX_FACTS,
	MULTI_APEX_TILE_LEAF,
	RFC6962_PRECERT_FACTS,
	RFC6962_PRECERT_LEAF_INPUT,
	RFC6962_X509_LEAF_INPUT,
	STATIC_PRECERT_FACTS,
	STATIC_PRECERT_TILE_LEAF,
	STATIC_X509_TILE_LEAF,
} from './fixtures';

const bytes = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
const OCT_17 = Date.parse('2026-10-17T06:00:00Z');

function onlyTbs(tileLeaf: string): Uint8Array {
	const [tbs] = parseDataTile(bytes(tileLeaf));
	if (!tbs) throw new Error('fixture is not a precert entry');
	return tbs;
}

function factsOf(expected: { names: string[]; notBefore: number; notAfter: number; issuer: string }) {
	return { names: expected.names, notBefore: expected.notBefore, notAfter: expected.notAfter, issuer: expected.issuer };
}

describe('parseTbsCertificate on real precert leaves', () => {
	it('reads SAN dNSNames, validity and issuer CN from an RFC 6962 precert leaf, matching node:crypto', () => {
		const tbs = precertTbsFromLeafInput(RFC6962_PRECERT_LEAF_INPUT);
		expect(tbs).not.toBeNull();
		expect(parseTbsCertificate(tbs!)).toEqual(factsOf(RFC6962_PRECERT_FACTS));
	});

	it('reads the same facts from a static-ct TileLeaf precert', () => {
		expect(parseTbsCertificate(onlyTbs(STATIC_PRECERT_TILE_LEAF))).toEqual(factsOf(STATIC_PRECERT_FACTS));
	});

	it('reads every SAN name of the multi-apex precert', () => {
		const facts = parseTbsCertificate(onlyTbs(MULTI_APEX_TILE_LEAF));
		expect(facts.names).toHaveLength(MULTI_APEX_FACTS.nameCount);
		expect(facts).toMatchObject({
			notBefore: MULTI_APEX_FACTS.notBefore,
			notAfter: MULTI_APEX_FACTS.notAfter,
			issuer: MULTI_APEX_FACTS.issuer,
		});
	});

	it('throws on truncated DER rather than reading past it', () => {
		const tbs = precertTbsFromLeafInput(RFC6962_PRECERT_LEAF_INPUT)!;
		expect(() => parseTbsCertificate(tbs.subarray(0, tbs.length - 40))).toThrow(RangeError);
		expect(() => parseTbsCertificate(new Uint8Array([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]))).toThrow(RangeError);
	});
});

describe('RFC 6962 leaves and static-ct tiles', () => {
	it('skips an x509 leaf without decoding its certificate', () => {
		expect(precertTbsFromLeafInput(RFC6962_X509_LEAF_INPUT)).toBeNull();
		// Only the 12-byte header is decoded for an x509 entry: a garbage body after it does not matter.
		expect(precertTbsFromLeafInput(`${RFC6962_X509_LEAF_INPUT.slice(0, 16)}!!!!`)).toBeNull();
	});

	it('refuses a leaf that is not a v1 timestamped entry, or a precert body that is cut short', () => {
		expect(() => precertTbsFromLeafInput(`AQ${RFC6962_PRECERT_LEAF_INPUT.slice(2)}`)).toThrow(RangeError);
		expect(() => precertTbsFromLeafInput(RFC6962_PRECERT_LEAF_INPUT.slice(0, 200))).toThrow(RangeError);
	});

	it('splits a data tile into its entries: TBSCertificate for a precert, null for an x509 entry', () => {
		const tile = new Uint8Array([...bytes(STATIC_PRECERT_TILE_LEAF), ...bytes(STATIC_X509_TILE_LEAF), ...bytes(MULTI_APEX_TILE_LEAF)]);
		const entries = parseDataTile(tile);
		expect(entries.map((entry) => entry !== null)).toEqual([true, false, true]);
		expect(parseTbsCertificate(entries[2]!).names).toHaveLength(MULTI_APEX_FACTS.nameCount);
	});

	it('throws on a tile that does not parse to its end', () => {
		const leaf = bytes(STATIC_PRECERT_TILE_LEAF);
		expect(() => parseDataTile(leaf.subarray(0, leaf.length - 1))).toThrow(RangeError);
	});

	it.each([
		[0, '000'],
		[7, '007'],
		[999, '999'],
		[1000, 'x001/000'],
		[1234067, 'x001/x234/067'],
		[2496540, 'x002/x496/540'],
	])('encodes tile %i as %s', (index, path) => {
		expect(tilePath(index)).toBe(path);
	});

	it('reads the tree size from the second line of a checkpoint', () => {
		expect(checkpointTreeSize('willow.ct.example/2027h1\n639114496\nAbCd=\n\n— sig\n')).toBe(639114496);
		expect(() => checkpointTreeSize('origin\n12x\n')).toThrow(RangeError);
	});
});

describe('selectLogs on the Chrome log list v3', () => {
	type Listed = { description: string; url?: string; monitoring_url?: string };
	const listed = LOG_LIST.operators.flatMap((op) => [...op.logs, ...op.tiled_logs] as Listed[]);
	const urlOf = (description: string) => {
		const log = listed.find((entry) => entry.description === description)!;
		return (log.url ?? log.monitoring_url)!;
	};

	it('takes usable and qualified logs of both kinds whose interval has not ended, minus Geomys and IPng', () => {
		const logs = selectLogs(LOG_LIST, OCT_17);
		// Not taken: Sectigo Mammoth2026h2 (readonly), Let's Encrypt Oak2026h2 (retired), the Geomys and IPng logs.
		const expected = [
			'Google Argon2026h2',
			'Google Argon2027h1',
			'DigiCert Wyvern2027h1',
			'Sectigo Monument2027h1',
			"Let's Encrypt Willow2026h2",
			"Let's Encrypt Willow2027h1",
			"Let's Encrypt Willow2028h2",
		];
		expect(new Set(logs.map((log) => log.url))).toEqual(new Set(expected.map(urlOf)));
		expect(logs.find((log) => log.url === urlOf('DigiCert Wyvern2027h1'))?.kind).toBe('rfc6962');
		expect(logs.find((log) => log.url === urlOf("Let's Encrypt Willow2027h1"))?.kind).toBe('static');
		expect(logs.every((log) => log.url.endsWith('/'))).toBe(true);
		expect(logs.map((log) => log.logId)).toEqual([...logs.map((log) => log.logId)].sort());
	});

	it('excludes Geomys and IPng logs that are otherwise tailable', () => {
		const excluded = LOG_LIST.operators.filter((op) => /^(Geomys|IPng)/.test(op.name));
		expect(excluded.map((op) => op.name).sort()).toEqual(['Geomys', 'IPng Networks']);
		const urls = new Set(selectLogs(LOG_LIST, OCT_17).map((log) => log.url));
		for (const op of excluded) for (const log of op.tiled_logs) expect(urls.has(log.monitoring_url)).toBe(false);
		// The same logs under another operator name are selected: the operator is the only reason they are out.
		const renamed = { operators: excluded.map((op) => ({ ...op, name: `Renamed ${op.name}` })) };
		expect(selectLogs(renamed, OCT_17)).toHaveLength(excluded.reduce((n, op) => n + op.tiled_logs.length, 0));
	});

	it('drops a shard once its temporal interval has ended', () => {
		const later = new Set(selectLogs(LOG_LIST, Date.parse('2027-01-02T00:00:00Z')).map((log) => log.url));
		expect(later.has(urlOf('Google Argon2026h2'))).toBe(false);
		expect(later.has(urlOf('Google Argon2027h1'))).toBe(true);
	});

	it('refuses a list without operators', () => {
		expect(() => selectLogs({}, OCT_17)).toThrow(TypeError);
	});
});

describe('observeCert', () => {
	it('emits one folded name row per name, keyed by the codec, and sibling rows for each ordered apex pair', () => {
		const set = newObservationSet();
		const skips = { badNames: 0, noApex: 0 };
		observeCert(parseTbsCertificate(onlyTbs(STATIC_PRECERT_TILE_LEAF)), set, skips);
		const { notBefore, notAfter, issuer } = STATIC_PRECERT_FACTS;
		expect(set.names.get(nameKey('bluemoonstudio.au').key)).toEqual({
			key: nameKey('bluemoonstudio.au').key,
			name: 'bluemoonstudio.au',
			apex: 'bluemoonstudio.au',
			firstSeen: notBefore,
			notAfter,
			issuer,
			wildcard: true,
		});
		expect([...set.names.values()].map((row) => row.name).sort()).toEqual([
			'bluemoonstudio.au',
			'totallyrenewableyack.org.au',
			'www.totallyrenewableyack.bluemoonstudio.au',
			'www.totallyrenewableyack.org.au',
		]);
		expect([...set.siblings.values()]).toEqual([
			{
				key: siblingKey('bluemoonstudio.au', 'totallyrenewableyack.org.au'),
				apex: 'bluemoonstudio.au',
				sibling: 'totallyrenewableyack.org.au',
				firstSeen: notBefore,
				notAfter,
			},
			{
				key: siblingKey('totallyrenewableyack.org.au', 'bluemoonstudio.au'),
				apex: 'totallyrenewableyack.org.au',
				sibling: 'bluemoonstudio.au',
				firstSeen: notBefore,
				notAfter,
			},
		]);
		expect(skips).toEqual({ badNames: 0, noApex: 0 });
	});

	it('folds x and *.x into one row with wildcard set, and emits no siblings for a single apex', () => {
		const set = newObservationSet();
		observeCert(parseTbsCertificate(precertTbsFromLeafInput(RFC6962_PRECERT_LEAF_INPUT)!), set, { badNames: 0, noApex: 0 });
		expect([...set.names.values()]).toMatchObject([{ name: '4f6k.com', apex: '4f6k.com', wildcard: true }]);
		expect(set.siblings.size).toBe(0);
	});

	it('emits no sibling rows for a cert spanning more than 32 apexes, but keeps its names', () => {
		const set = newObservationSet();
		observeCert(parseTbsCertificate(onlyTbs(MULTI_APEX_TILE_LEAF)), set, { badNames: 0, noApex: 0 });
		expect(new Set([...set.names.values()].map((row) => row.apex)).size).toBe(MULTI_APEX_FACTS.apexCount);
		expect(MULTI_APEX_FACTS.apexCount).toBeGreaterThan(32);
		expect(set.siblings.size).toBe(0);
	});

	it('emits siblings at exactly 32 apexes', () => {
		const set = newObservationSet();
		const names = Array.from({ length: 32 }, (_, i) => `www.apex${i}.example`);
		observeCert({ names, notBefore: 1, notAfter: 2, issuer: 'CA' }, set, { badNames: 0, noApex: 0 });
		expect(set.siblings.size).toBe(32 * 31);
	});

	it('skips and counts names the codec refuses or that have no apex, and falls back to nothing else', () => {
		const set = newObservationSet();
		const skips = { badNames: 0, noApex: 0 };
		observeCert(
			{ names: ['bad name.example', 'a..example', 'co.uk', '192.0.2.1', 'ok.example'], notBefore: 1, notAfter: 2, issuer: 'CA' },
			set,
			skips,
		);
		expect([...set.names.values()].map((row) => row.name)).toEqual(['ok.example']);
		expect(skips).toEqual({ badNames: 2, noApex: 2 });
	});

	it('cuts an oversized issuer', () => {
		const set = newObservationSet();
		observeCert({ names: ['ok.example'], notBefore: 1, notAfter: 2, issuer: 'I'.repeat(5000) }, set, { badNames: 0, noApex: 0 });
		expect([...set.names.values()][0]!.issuer).toHaveLength(256);
	});
});

const nameRow = (name: string, notAfter: number, issuer = 'CA'): NameObservation => ({
	...nameKey(name),
	apex: name.split('.').slice(-2).join('.'),
	firstSeen: 1,
	notAfter,
	issuer,
});

describe('newRows (tick-wide dedupe)', () => {
	it('drops a later log row that adds nothing and emits the merged row when it does', () => {
		const emitted = new Map<string, RunRow>();
		const first = newObservationSet();
		first.names.set(nameKey('a.example').key, nameRow('a.example', 100));
		first.names.set(nameKey('b.example').key, nameRow('b.example', 100));
		expect(newRows(first, emitted).names).toHaveLength(2);

		const second = newObservationSet();
		second.names.set(nameKey('a.example').key, nameRow('a.example', 100)); // covered: dropped
		second.names.set(nameKey('b.example').key, nameRow('b.example', 200, 'Later CA')); // extends notAfter
		second.names.set(nameKey('c.example').key, nameRow('c.example', 100)); // new
		const rows = newRows(second, emitted);
		expect(rows.names.map((row) => [row.name, row.notAfter, row.issuer])).toEqual([
			['b.example', 200, 'Later CA'],
			['c.example', 100, 'CA'],
		]);
	});
});

describe('toBatches', () => {
	it('splits rows into messages under the size limit, each carrying the log range', () => {
		const names = Array.from({ length: 3000 }, (_, i) => nameRow(`host-${i}-${'x'.repeat(40)}.example`, 100));
		const siblings = [{ key: siblingKey('a.example', 'b.example'), apex: 'a.example', sibling: 'b.example', firstSeen: 1, notAfter: 2 }];
		const batches = toBatches('log-a', 10, 20, { names, siblings });
		expect(batches.length).toBeGreaterThan(2);
		for (const batch of batches) {
			expect(new TextEncoder().encode(JSON.stringify(batch)).byteLength).toBeLessThanOrEqual(MAX_MESSAGE_BYTES);
			expect(batch).toMatchObject({ logId: 'log-a', startIndex: 10, endIndex: 20 });
		}
		expect(batches.flatMap((batch) => batch.names)).toEqual(names);
		expect(batches.flatMap((batch) => batch.siblings)).toEqual(siblings);
	});

	it('returns no batch when there are no rows', () => {
		expect(toBatches('log-a', 10, 20, { names: [], siblings: [] })).toEqual([]);
	});
});
