import { describe, expect, it } from 'vitest';

describe('queryGeoRollup', () => {
	it('groups tool_call by country/region/city/asn over a window and selects the geo blobs', async () => {
		const { queryGeoRollup } = await import('../src/lib/analytics-queries');
		const sql = queryGeoRollup('7');
		expect(sql).toContain("index1 = 'tool_call'");
		expect(sql).toContain('blob5'); // country
		expect(sql).toContain('blob13'); // region (Task 6 position)
		expect(sql).toContain('blob15'); // asn
		expect(sql).toMatch(/INTERVAL '7' DAY|toDateTime/);
	});
});
