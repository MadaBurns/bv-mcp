import { describe, it, expect, beforeAll } from 'vitest';
// @ts-ignore
import wasm from '../crates/bv-wasm-core/pkg/bv_wasm_core_bg.wasm';
// @ts-ignore
import { initSync, estimateTokens, checkPermission } from '../crates/bv-wasm-core/pkg/bv_wasm_core.js';

describe('Wasm Integration', () => {
    beforeAll(async () => {
        initSync(wasm);
    });

    it('estimates tokens correctly', () => {
        expect(estimateTokens('A simple test string')).toBeGreaterThan(0);
        expect(estimateTokens('A simple test string')).toBe(6);
    });

    it('enforces read-only permissions', () => {
        expect(checkPermission('read-only', 'write_file')).toBe(false);
        expect(checkPermission('read-only', 'read_file')).toBe(true);
    });

    it('enforces workspace-write permissions', () => {
        expect(checkPermission('workspace-write', 'write_file')).toBe(true);
        expect(checkPermission('workspace-write', 'danger_tool')).toBe(false);
    });
});
