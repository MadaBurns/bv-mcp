// test/access-log-enrich-wiring.spec.ts
// Guards that the enrichment fields exist on ExecuteMcpRequestOptions and are
// read at the index.ts seam. Source-level assertion (no Worker boot needed).
import { describe, expect, it } from 'vitest';

const execSrc = (import.meta.glob('../src/mcp/execute.ts', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)['../src/mcp/execute.ts'];
const indexSrc = (import.meta.glob('../src/index.ts', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)['../src/index.ts'];

describe('access-log enrichment wiring', () => {
	it('ExecuteMcpRequestOptions declares the new enrichment fields', () => {
		for (const f of ['region?', 'city?', 'latitude?', 'longitude?', 'asn?', 'asOrg?', 'analyticsQueue?', 'analyticsPiiLevel?']) {
			expect(execSrc).toContain(f);
		}
	});
	it('index.ts reads cf.asn/asOrganization and passes analyticsQueue + pii level', () => {
		expect(indexSrc).toContain('asOrganization');
		expect(indexSrc).toContain('analyticsQueue: c.env.MCP_ANALYTICS_QUEUE');
		expect(indexSrc).toContain('parseAnalyticsPiiLevel(c.env.ANALYTICS_PII_LEVEL)');
	});
});
