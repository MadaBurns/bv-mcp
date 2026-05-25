// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import generatedPermissions from '../../crates/bv-wasm-core/src/generated_tool_permissions.rs?raw';
import wasmLib from '../../crates/bv-wasm-core/src/lib.rs?raw';
import { TOOLS } from '../../src/schemas/tool-definitions';

function expectedMode(tool: (typeof TOOLS)[number]): string {
	if (tool.annotations.destructiveHint) return 'DangerFullAccess';
	if (tool.annotations.readOnlyHint) return 'ReadOnly';
	return 'WorkspaceWrite';
}

describe('WASM permission policy SSOT audit', () => {
	it('uses generated permissions instead of a hand-maintained match list', () => {
		expect(wasmLib).toContain('generated_tool_permissions::required_mode_for_tool');
		expect(wasmLib).not.toContain('"check_mx" | "check_spf"');
	});

	it('keeps generated Rust permissions aligned with TOOLS', () => {
		for (const tool of TOOLS) {
			expect(generatedPermissions).toContain(`"${tool.name}" => PermissionMode::${expectedMode(tool)}`);
		}
	});
});
