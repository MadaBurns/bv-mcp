// SPDX-License-Identifier: BUSL-1.1

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { MCP_SECURITY_CRITICAL_SECRET_KEYS } from '../../src/lib/security-capabilities';

const EXPLICIT_NON_CAPABILITY_CONFIG = new Set([
	// URL/feature/version metadata, not bearer/HMAC/encryption authority.
	'BV_DOH_ENDPOINT',
	'MCP_ACCESS_LOG_IP_KEY_VERSION',
	'REJECT_QUERY_API_KEY',
]);

function sourceFiles(root: string): string[] {
	return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
		const path = join(root, entry.name);
		if (entry.isDirectory()) return sourceFiles(path);
		return entry.isFile() && path.endsWith('.ts') ? [path] : [];
	});
}

describe('MCP security capability inventory', () => {
	it('classifies the operator reconstruction manifest and every source-read secret-shaped field', () => {
		const runbook = readFileSync('docs/operator-runbook.md', 'utf8');
		const manifestBlock = runbook.match(/4\. Secrets \(`wrangler secret list`[\s\S]*?Values in the secret\s+manager/);
		expect(manifestBlock, 'operator secret reconstruction block').not.toBeNull();
		const manifestNames = new Set(manifestBlock![0].match(/[A-Z][A-Z0-9_]{3,}/g) ?? []);

		const discovered = new Set<string>();
		const propertyPattern = /\b[A-Za-z_$][\w$]*\.([A-Z][A-Z0-9_]*(?:(?:SECRET|TOKEN|KEY)(?:_\d|_PRIOR|_VERSION)?))\b/g;
		const allSource = sourceFiles('src')
			.map((file) => readFileSync(file, 'utf8'))
			.join('\n');
		for (const match of allSource.matchAll(propertyPattern)) discovered.add(match[1]);

		const classified = new Set<string>([...MCP_SECURITY_CRITICAL_SECRET_KEYS, ...EXPLICIT_NON_CAPABILITY_CONFIG]);
		expect([...manifestNames].filter((key) => !classified.has(key)).sort()).toEqual([]);
		expect([...discovered].filter((key) => !classified.has(key)).sort()).toEqual([]);
	});

	it('keeps every shared-inventory entry tied to runtime source or the operator manifest', () => {
		const runbook = readFileSync('docs/operator-runbook.md', 'utf8');
		const allSource = sourceFiles('src')
			.map((file) => readFileSync(file, 'utf8'))
			.join('\n');
		expect(MCP_SECURITY_CRITICAL_SECRET_KEYS.filter((key) => !allSource.includes(key) && !runbook.includes(key))).toEqual([]);
	});
});
