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
	// A thrown fetch means the scanner never reached the origin — this must read as an
	// unmeasured abstention (info + inconclusive/errorKind), never a scored high/critical
	// security deficiency (#638 law: we did not measure, we failed to connect).
	it('maps a timeout/abort message to an info, inconclusive abstention finding', () => {
		const finding = getHttpsErrorFinding('example.com', 'The operation was aborted due to timeout');
		expect(finding.title).toBe('HTTPS connection not assessed (scanner timeout)');
		expect(finding.severity).toBe('info');
		expect(finding.metadata).toMatchObject({ inconclusive: true, confidence: 'heuristic', errorKind: 'timeout' });
	});

	it('maps any other connection error to an info, inconclusive abstention finding', () => {
		const finding = getHttpsErrorFinding('example.com', 'ECONNREFUSED');
		expect(finding.title).toBe('HTTPS connection not assessed (transport error)');
		expect(finding.severity).toBe('info');
		expect(finding.metadata).toMatchObject({ inconclusive: true, confidence: 'heuristic', errorKind: 'transport_error' });
	});

	it('never interpolates the raw upstream error message into the finding detail (MISSING_CONTROL_REGEX safety)', () => {
		// A raw upstream message containing a MISSING_CONTROL_REGEX trigger word must not be
		// able to reach the finding text and falsely arm the missing-control gate — the same
		// #345-class incident redactSubjectData exists to guard against for scanned-domain data.
		const finding = getHttpsErrorFinding('example.com', 'required certificate not found: missing SNI extension');
		expect(finding.detail).not.toContain('required certificate not found');
		expect(finding.detail).not.toContain('missing SNI extension');
		expect(finding.severity).toBe('info');
	});
});
