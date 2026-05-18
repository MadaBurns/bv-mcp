// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import script from '../../scripts/generate-report.sh?raw';

describe('generate-report script safety', () => {
	it('passes TARGET_DOMAIN through the environment without mutating the Vitest spec', () => {
		expect(script).toContain('export TARGET_DOMAIN=$1');
		expect(script).toContain('test/generate-discovery-report.spec.ts');
		expect(script).not.toContain('sed -i');
		expect(script).not.toContain('SPEC_FILE.bak');
		expect(script).not.toContain('mv "$SPEC_FILE.bak"');
	});
});
