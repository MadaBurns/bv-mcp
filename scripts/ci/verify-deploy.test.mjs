// SPDX-License-Identifier: BUSL-1.1
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertVersion } from './verify-deploy.mjs';

test('assertVersion passes on exact match', () => {
	assert.doesNotThrow(() => assertVersion({ version: '3.32.0' }, '3.32.0'));
});

test('assertVersion throws on mismatch', () => {
	assert.throws(() => assertVersion({ version: '3.31.2' }, '3.32.0'), /expected 3\.32\.0/);
});

test('assertVersion throws on missing serverInfo', () => {
	assert.throws(() => assertVersion(undefined, '3.32.0'), /no serverInfo/i);
});
