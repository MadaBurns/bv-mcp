import { describe, it, expect, beforeAll } from 'vitest';

/**
 * crates/bv-wasm-core/pkg/ is wasm-pack build output (`npm run build:wasm`), not checked in.
 * typecheck-tests CI has no Rust toolchain and never builds it (see .github/workflows/ci.yml),
 * so real file-based resolution for these two imports fails there with TS2307 — while
 * build-and-test's `npm test` builds wasm first, so the same imports resolve for real there and
 * report no error at all (the module exists; `allowSyntheticDefaultImports` in the root
 * tsconfig.json covers the .wasm file's lack of an explicit default export, and the generated
 * bv_wasm_core.js carries its own `@ts-self-types` pointer to bv_wasm_core.d.ts).
 *
 * That's exactly why `@ts-expect-error` bimodally flipped the ratchet: it's correct only in the
 * unbuilt state and becomes an "Unused '@ts-expect-error' directive" (TS2578) error in the
 * built one. `@ts-ignore` doesn't have that failure mode — it suppresses an error when one is
 * present and is silently inert when the line is already clean — so both states now agree, and
 * a signature mismatch surfacing here in the built state (the one place the real
 * wasm-bindgen-generated types actually exist) still fails the build for real.
 *
 * A `declare module` alternative (matching test/raw-modules.d.ts's `*?raw` ambient pattern) was
 * evaluated first and rejected on hard evidence, not preference: TypeScript resolves a relative
 * specifier through the filesystem either way, so `declare module '../crates/.../foo'` is
 * treated as a genuine ambient declaration ONLY while the real file is absent, and as an
 * AUGMENTATION of the real module once pkg/ is built — which then rejects `export default` and
 * a re-declared `type` alias with TS2666/TS2300 (confirmed empirically). A wildcard shorthand
 * dodges that specific clash but TypeScript only accepts a wildcard ambient module in a global
 * (non-module) file — this spec file is itself a module via its `vitest` import, so a wildcard
 * declared here reports TS2664 "Invalid module name in augmentation" in BOTH states (also
 * confirmed empirically). A real fix along that path needs a new ambient .d.ts file alongside
 * raw-modules.d.ts, which is outside this ticket's declared scope (test/wasm-integration.test.ts,
 * test/tsconfig.json only).
 */
// eslint-disable-next-line @typescript-eslint/ban-ts-comment -- see file-level comment: @ts-ignore (not @ts-expect-error) is required here so the directive doesn't itself flip pass/fail depending on whether crates/bv-wasm-core/pkg has been built
// @ts-ignore WASM module import: only resolvable after `npm run build:wasm`
import wasm from '../crates/bv-wasm-core/pkg/bv_wasm_core_bg.wasm';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment -- see file-level comment: @ts-ignore (not @ts-expect-error) is required here so the directive doesn't itself flip pass/fail depending on whether crates/bv-wasm-core/pkg has been built
// @ts-ignore WASM module import: only resolvable after `npm run build:wasm`
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
        // generate produces suggested DNS text and is ReadOnly in TOOLS annotations
        expect(checkPermission('read-only', 'generate')).toBe(true);
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
