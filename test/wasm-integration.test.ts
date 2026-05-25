import { describe, it, expect, beforeAll } from 'vitest';
// @ts-expect-error WASM module import for testing
import wasm from '../crates/bv-wasm-core/pkg/bv_wasm_core_bg.wasm';
// @ts-expect-error WASM module import for testing
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
        // generate_fix_plan generates suggested DNS text and is ReadOnly in TOOLS annotations
        expect(checkPermission('read-only', 'generate_fix_plan')).toBe(true);
    });

    it('enforces workspace-write permissions', () => {
        // register_brand_audit_watch is WorkspaceWrite
        expect(checkPermission('workspace-write', 'register_brand_audit_watch')).toBe(true);
        // check_spf is ReadOnly, so workspace-write (higher) should allow it
        expect(checkPermission('workspace-write', 'check_spf')).toBe(true);
        // Any unknown tool defaults to DangerFullAccess
        expect(checkPermission('workspace-write', 'unknown_tool')).toBe(false);
    });

    it('enforces permissions for generated current tool names', () => {
        expect(checkPermission('read-only', 'check_fast_flux')).toBe(true);
        expect(checkPermission('read-only', 'register_brand_audit_watch')).toBe(false);
        expect(checkPermission('workspace-write', 'register_brand_audit_watch')).toBe(true);
        expect(checkPermission('workspace-write', 'delete_brand_audit_watch')).toBe(false);
        expect(checkPermission('danger-full-access', 'delete_brand_audit_watch')).toBe(true);
    });
});
