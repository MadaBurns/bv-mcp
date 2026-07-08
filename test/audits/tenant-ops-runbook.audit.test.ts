// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import runbook from '../../docs/tenant-ops-runbook.md?raw';

describe('tenant operations runbook audit', () => {
	it('documents production overlay gates, data lifecycle, recovery, and cost controls', () => {
		expect(runbook).toContain('## Production Overlay Gates');
		expect(runbook).toContain('REJECT_QUERY_API_KEY');
		expect(runbook).toContain('OAUTH_ISSUER');
		expect(runbook).toContain('REQUIRE_PRODUCTION_BINDINGS');
		expect(runbook).toContain('ALERT_WEBHOOK_URL');
		expect(runbook).toContain('## Data Lifecycle and Recovery');
		expect(runbook).toContain('retention');
		expect(runbook).toContain('export');
		expect(runbook).toContain('erasure');
		expect(runbook).toContain('restore drill');
		expect(runbook).toContain('## Cost Governance');
		expect(runbook).toContain('identity-secops');
		expect(runbook).toContain('brand audit');
	});
});
