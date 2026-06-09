import { describe, it, expect } from 'vitest';
import { JSON_RPC_ERRORS } from '../src/lib/json-rpc';

describe('JSON_RPC_ERRORS', () => {
	it('defines an UPGRADE_REQUIRED code distinct from the others', () => {
		expect(JSON_RPC_ERRORS.UPGRADE_REQUIRED).toBe(-32003);
		const codes = Object.values(JSON_RPC_ERRORS);
		expect(new Set(codes).size).toBe(codes.length);
	});
});
