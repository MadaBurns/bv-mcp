// SPDX-License-Identifier: BUSL-1.1
import { beforeEach, describe, expect, it } from 'vitest';
import { deleteUnreferenced } from '../indexer/catalog';
import { applyCatalog, objectKeys, testEnv } from './indexer-harness';

beforeEach(applyCatalog);

describe('catalog cleanup reference lookup', () => {
	it('uses a covering index instead of scanning the catalog', async () => {
		const { CURSORS } = testEnv();
		const { results } = await CURSORS.prepare(
			'EXPLAIN QUERY PLAN SELECT DISTINCT r2_key FROM runs WHERE r2_key IN (SELECT value FROM json_each(?1))',
		)
			.bind(JSON.stringify(['runs/example']))
			.all<{ detail: string }>();
		const plan = results.map((row) => row.detail).join('\n');
		expect(plan).toContain('SEARCH runs USING COVERING INDEX runs_r2_key');
		expect(plan).not.toContain('SCAN runs');
	});

	it('preserves objects referenced only by a retained generation', async () => {
		const { CURSORS, INDEX } = testEnv();
		await CURSORS.prepare('INSERT INTO runs (id, generation, r2_key) VALUES (?1, ?2, ?3)')
			.bind('1:runs/retained', 1, 'runs/retained')
			.run();
		await CURSORS.prepare("INSERT INTO meta (k, v) VALUES ('current_generation', '2')").run();
		await INDEX.put('runs/retained', 'snapshot');
		await INDEX.put('runs/garbage', 'unreferenced');
		expect(await deleteUnreferenced(CURSORS, INDEX, ['runs/retained', 'runs/garbage', 'runs/garbage'])).toBe(1);
		expect(await objectKeys()).toEqual(['runs/retained']);
	});
});
