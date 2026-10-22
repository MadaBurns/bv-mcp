// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it } from 'vitest';
import { CERTSTREAM_CALLER, certstreamHeaders } from '../../src/lib/certstream-headers';

describe('certstreamHeaders', () => {
	it('names bv-mcp as the caller and sends the bearer when a token is configured', () => {
		expect(certstreamHeaders('read-key')).toEqual({ 'X-BV-Caller': 'bv-mcp', Authorization: 'Bearer read-key' });
	});

	it.each([undefined, ''])('names the caller but sends no bearer when the token is %j', (token) => {
		expect(certstreamHeaders(token)).toEqual({ 'X-BV-Caller': CERTSTREAM_CALLER });
	});
});
