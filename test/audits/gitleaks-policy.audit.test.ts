// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import gitleaksConfig from '../../.gitleaks.toml?raw';

describe('gitleaks policy', () => {
	it('allowlists the same synthetic fixture domains as the repo safety scanner', () => {
		expect(gitleaksConfig).toContain(`'''@([a-zA-Z0-9.\\-]+\\.)?example\\.(com|org|net|test|invalid)'''`);
	});

	it('allowlists deliberate repo safety scanner secret-shape fixtures', () => {
		expect(gitleaksConfig).toContain("'''test/audits/repo-safety-scanner\\.audit\\.test\\.ts$'''");
	});
});
