// SPDX-License-Identifier: BUSL-1.1

/**
 * Direct unit coverage for the pure `ssl-analysis.ts` helpers.
 *
 * Ported from the now-deleted `test/ssl-analysis.spec.ts`, which exercised a
 * runtime-dead duplicate at `src/tools/ssl-analysis.ts` (no importer besides
 * that spec — `src/tools/check-ssl.ts` has always delegated to this package's
 * `checkSSL`). `getHttpsFindings` and `getHttpsErrorFinding` had no direct
 * unit test anywhere in this package — only indirect exercise via
 * `checkSSL`-level integration tests (`check-remaining.test.ts`,
 * `check-ssl-robots.test.ts`) and the worker-level `test/check-ssl.spec.ts`.
 * `getHttpRedirectFindings` is intentionally NOT duplicated here: it already
 * gets direct unit coverage (200/404/418/301-downgrade/301-https-clean) from
 * `ssl-no-content.test.ts` (issue #806 / PR #819).
 */

import { describe, it, expect } from 'vitest';
import { getHttpsErrorFinding, getHttpsFindings } from '../../checks/ssl-analysis';

describe('getHttpsFindings', () => {
	it('flags HTTPS downgrade and missing HSTS', () => {
		const findings = getHttpsFindings('example.com', 'http://example.com/', null);
		expect(findings.map((finding) => finding.title)).toEqual(['HTTPS redirects to HTTP', 'No HSTS header']);
	});

	it('flags short HSTS max-age and missing includeSubDomains', () => {
		const findings = getHttpsFindings('example.com', 'https://example.com/', 'max-age=3600');
		expect(findings.find((finding) => finding.title === 'HSTS max-age too short')?.severity).toBe('low');
		expect(findings.find((finding) => finding.title === 'HSTS missing includeSubDomains')?.severity).toBe('low');
	});

	it('is clean for a well-formed HSTS header on an https response', () => {
		const findings = getHttpsFindings('example.com', 'https://example.com/', 'max-age=31536000; includeSubDomains');
		expect(findings).toEqual([]);
	});
});

describe('getHttpsErrorFinding', () => {
	it('maps a timeout/abort message to a high "HTTPS connection timeout" finding', () => {
		const finding = getHttpsErrorFinding('example.com', 'The operation was aborted due to timeout');
		expect(finding.title).toBe('HTTPS connection timeout');
		expect(finding.severity).toBe('high');
	});

	it('maps any other connection error to a critical "HTTPS connection failed" finding', () => {
		const finding = getHttpsErrorFinding('example.com', 'ECONNREFUSED');
		expect(finding.title).toBe('HTTPS connection failed');
		expect(finding.severity).toBe('critical');
	});
});
