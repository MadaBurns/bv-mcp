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
        // check_spf is ReadOnly
        expect(checkPermission('read-only', 'check_spf')).toBe(true);
        // generate_fix_plan is WorkspaceWrite
        expect(checkPermission('read-only', 'generate_fix_plan')).toBe(false);
    });

    it('enforces workspace-write permissions', () => {
        // generate_fix_plan is WorkspaceWrite
        expect(checkPermission('workspace-write', 'generate_fix_plan')).toBe(true);
        // check_spf is ReadOnly, so workspace-write (higher) should allow it
        expect(checkPermission('workspace-write', 'check_spf')).toBe(true);
        // Any unknown tool defaults to DangerFullAccess
        expect(checkPermission('workspace-write', 'unknown_tool')).toBe(false);
    });
});
