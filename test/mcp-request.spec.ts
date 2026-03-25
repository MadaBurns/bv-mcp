import { describe, expect, it } from 'vitest';
import {
	normalizeHeaders,
	parseAllowedHosts,
	parseJsonRpcRequest,
	readRequestBody,
	summarizeParamsForLog,
	validateContentType,
	validateJsonRpcRequest,
} from '../src/mcp/request';

describe('mcp-request helpers', () => {
	it('parseAllowedHosts trims, lowercases, and removes empty values', () => {
		expect(parseAllowedHosts(' Example.COM, api.example.com , , ')).toEqual(['example.com', 'api.example.com']);
		expect(parseAllowedHosts('   ')).toBeUndefined();
	});

	it('summarizeParamsForLog returns sorted keys and ignores arrays', () => {
		expect(summarizeParamsForLog({ zebra: 1, alpha: 2, middle: 3 })).toEqual({
			keys: ['alpha', 'middle', 'zebra'],
		});
		expect(summarizeParamsForLog(['a', 'b'])).toBeUndefined();
	});

	it('normalizeHeaders lowercases header names', () => {
		const headers = new Headers({ 'Content-Type': 'application/json', 'Mcp-Session-Id': 'abc123' });
		expect(normalizeHeaders(headers)).toEqual({
			'content-type': 'application/json',
			'mcp-session-id': 'abc123',
		});
	});

	it('parseJsonRpcRequest returns parse error payload for invalid JSON', () => {
		const result = parseJsonRpcRequest('{not valid json');
		expect(result.ok).toBe(false);
		expect(result.status).toBe(400);
		expect(result.payload?.error.message).toContain('Parse error');
	});

	it('validateJsonRpcRequest rejects invalid protocol version and invalid id type', () => {
		const invalidVersion = validateJsonRpcRequest({ jsonrpc: '1.0', id: 1, method: 'ping' });
		expect(invalidVersion?.status).toBe(400);
		expect(invalidVersion?.payload.error.message).toContain('Invalid JSON-RPC 2.0 request');

		const invalidId = validateJsonRpcRequest({ jsonrpc: '2.0', id: true as never, method: 'ping' });
		expect(invalidId?.status).toBe(400);
		expect(invalidId?.payload.error.message).toContain('Invalid JSON-RPC id');
	});

	it('parseJsonRpcRequest accepts JSON-RPC batch arrays', () => {
		const result = parseJsonRpcRequest('[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]');
		expect(result.ok).toBe(true);
		expect(result.isBatch).toBe(true);
		expect(Array.isArray(result.body)).toBe(true);
		expect((result.body as unknown[])).toHaveLength(2);
	});

	it('parseJsonRpcRequest rejects empty JSON-RPC batch arrays', () => {
		const result = parseJsonRpcRequest('[]');
		expect(result.ok).toBe(false);
		expect(result.status).toBe(400);
		expect(result.payload?.error.code).toBe(-32600);
		expect(result.payload?.error.message).toContain('empty');
	});

	it('validateContentType accepts application/json', () => {
		expect(validateContentType('application/json')).toBeUndefined();
	});

	it('validateContentType accepts application/json with charset', () => {
		expect(validateContentType('application/json; charset=utf-8')).toBeUndefined();
	});

	it('validateContentType accepts missing Content-Type', () => {
		expect(validateContentType(undefined)).toBeUndefined();
		expect(validateContentType(null)).toBeUndefined();
		expect(validateContentType('')).toBeUndefined();
	});

	it('validateContentType rejects text/plain', () => {
		const result = validateContentType('text/plain');
		expect(result?.ok).toBe(false);
		expect(result?.status).toBe(415);
		expect(result?.payload?.error.message).toContain('Unsupported Media Type');
	});

	it('validateContentType rejects application/xml', () => {
		const result = validateContentType('application/xml');
		expect(result?.ok).toBe(false);
		expect(result?.status).toBe(415);
	});

	it('validateContentType rejects multipart/form-data', () => {
		const result = validateContentType('multipart/form-data');
		expect(result?.ok).toBe(false);
		expect(result?.status).toBe(415);
	});

	it('validateContentType is case-insensitive', () => {
		expect(validateContentType('Application/JSON')).toBeUndefined();
		expect(validateContentType('APPLICATION/JSON; CHARSET=UTF-8')).toBeUndefined();
	});

	it('readRequestBody returns payload too large for oversized bodies', async () => {
		const request = new Request('http://example.com/mcp', {
			method: 'POST',
			body: '12345',
		});

		const result = await readRequestBody(request, 4);
		expect(result.ok).toBe(false);
		expect(result.status).toBe(413);
		expect(result.payload?.error.message).toContain('too large');
	});
});