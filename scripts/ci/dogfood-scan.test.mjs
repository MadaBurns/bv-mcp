// SPDX-License-Identifier: BUSL-1.1
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gradeRank, meetsMinimum, parseScanResult } from './dogfood-scan.mjs';

test('gradeRank: better grades rank lower; unknown is worst', () => {
	assert.ok(gradeRank('A+') < gradeRank('B'));
	assert.ok(gradeRank('B') < gradeRank('C'));
	assert.ok(gradeRank('ZZ') > gradeRank('F'));
});

test('meetsMinimum: A+ and B pass B; C+ fails B', () => {
	assert.equal(meetsMinimum('A+', 'B'), true);
	assert.equal(meetsMinimum('B', 'B'), true);
	assert.equal(meetsMinimum('B+', 'B'), true);
	assert.equal(meetsMinimum('C+', 'B'), false);
	assert.equal(meetsMinimum('F', 'B'), false);
});

test('parseScanResult: extracts structuredContent from the id:2 line', () => {
	const stdout = [
		JSON.stringify({ jsonrpc: '2.0', id: 1, result: { serverInfo: { version: '9.9.9' } } }),
		JSON.stringify({ jsonrpc: '2.0', id: 2, result: { structuredContent: { score: 87, grade: 'A', maturityStage: 3 } } }),
	].join('\n');
	assert.deepEqual(parseScanResult(stdout), { score: 87, grade: 'A', maturityStage: 3 });
});

test('parseScanResult: throws on a tool error', () => {
	const stdout = JSON.stringify({ jsonrpc: '2.0', id: 2, error: { message: 'boom' } });
	assert.throws(() => parseScanResult(stdout), /boom/);
});
