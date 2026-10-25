// SPDX-License-Identifier: BUSL-1.1
// Run without package installs: node --experimental-strip-types --test scripts/ct-index-catalog-index.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { deleteUnreferenced } from '../packages/bv-ct-index/src/indexer/catalog.ts';

const sql = (name) => readFileSync(new URL(`../packages/bv-ct-index/migrations/${name}`, import.meta.url), 'utf8');
const lookup = 'SELECT DISTINCT r2_key FROM runs WHERE r2_key IN (SELECT value FROM json_each(?1))';

test('migration replaces the catalog scan and preserves cross-generation cleanup', async () => {
	const db = new DatabaseSync(':memory:');
	try {
		db.exec(sql('0002_catalog.sql'));
		const keys = JSON.stringify(['runs/retained', 'runs/garbage']);
		const plan = () =>
			db
				.prepare(`EXPLAIN QUERY PLAN ${lookup}`)
				.all({ 1: keys })
				.map((row) => row.detail)
				.join('\n');
		assert.match(plan(), /SCAN runs/); // Negative control: the original schema reproduces the defect.
		db.exec(sql('0004_runs_r2_key.sql'));
		assert.match(plan(), /SEARCH runs USING COVERING INDEX runs_r2_key/);
		assert.doesNotMatch(plan(), /SCAN runs|TEMP B-TREE FOR DISTINCT/);
		db.exec(
			"INSERT INTO runs (id, generation, r2_key) VALUES ('1:retained', 1, 'runs/retained'); INSERT INTO meta VALUES ('current_generation', '2');",
		);
		const objects = new Set(['runs/retained', 'runs/garbage']);
		const adapter = {
			prepare(query) {
				return {
					bind(value) {
						return {
							async all() {
								return { results: db.prepare(query).all({ 1: value }) };
							},
						};
					},
				};
			},
		};
		const bucket = {
			async delete(batch) {
				for (const key of batch) objects.delete(key);
			},
		};
		assert.equal(await deleteUnreferenced(adapter, bucket, ['runs/retained', 'runs/garbage', 'runs/garbage']), 1);
		assert.deepEqual([...objects], ['runs/retained']);
		assert.equal(await deleteUnreferenced(adapter, bucket, []), 0);
	} finally {
		db.close();
	}
});
