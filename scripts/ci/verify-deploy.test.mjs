// SPDX-License-Identifier: BUSL-1.1
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertVersion, assertScoreSane } from './verify-deploy.mjs';

test('assertVersion passes on exact match', () => {
	assert.doesNotThrow(() => assertVersion({ version: '3.32.0' }, '3.32.0'));
});

test('assertVersion throws on mismatch', () => {
	assert.throws(() => assertVersion({ version: '3.31.2' }, '3.32.0'), /expected 3\.32\.0/);
});

test('assertVersion throws on missing serverInfo', () => {
	assert.throws(() => assertVersion(undefined, '3.32.0'), /no serverInfo/i);
});

test('assertScoreSane passes and returns the score when finite', () => {
	let score;
	assert.doesNotThrow(() => {
		score = assertScoreSane({ score: 87 });
	});
	assert.equal(score, 87);
});

test('assertScoreSane throws when structuredContent is missing', () => {
	assert.throws(() => assertScoreSane(undefined), /no structuredContent/i);
	assert.throws(() => assertScoreSane(null), /no structuredContent/i);
});

test('assertScoreSane throws when score is absent or non-finite', () => {
	assert.throws(() => assertScoreSane({}), /not a finite number/i);
	assert.throws(() => assertScoreSane({ score: null }), /not a finite number/i);
	assert.throws(() => assertScoreSane({ score: NaN }), /not a finite number/i);
	assert.throws(() => assertScoreSane({ score: 'n/a' }), /not a finite number/i);
});
