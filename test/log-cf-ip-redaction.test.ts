// Regression: pre-fix SENSITIVE_KEY_PATTERN used `^ip$` which only matched the bare
// key "ip" and let cf-connecting-ip leak through to Cloudflare tail logs in the
// global error-handler path (src/index.ts unhandled-exception sanitizeHeadersForLog).

import { describe, expect, it } from 'vitest';
import { sanitizeHeadersForLog, sanitizeLogValue } from '../src/lib/log';

describe('log redaction: cf-connecting-ip', () => {
	it('redacts cf-connecting-ip header (Headers and plain object)', () => {
		const fromObj = sanitizeHeadersForLog({
			'cf-connecting-ip': '203.0.113.42',
			'CF-Connecting-IP': '198.51.100.7',
			'content-type': 'application/json',
		});
		expect(fromObj['cf-connecting-ip']).toBe('[redacted]');
		expect(fromObj['content-type']).toBe('application/json');

		const fromHeaders = sanitizeHeadersForLog(
			new Headers({ 'cf-connecting-ip': '203.0.113.42' }),
		);
		expect(fromHeaders['cf-connecting-ip']).toBe('[redacted]');
	});

	it('still redacts the bare ip key (regression of original ^ip$ behavior)', () => {
		expect(sanitizeLogValue({ ip: '203.0.113.42', other: 'visible' })).toEqual({
			ip: '[redacted]',
			other: 'visible',
		});
	});
});
