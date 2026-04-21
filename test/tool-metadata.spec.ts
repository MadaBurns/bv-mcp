import { describe, it, expect } from 'vitest';
import { TOOLS } from '../src/schemas/tool-definitions';

describe('tool metadata', () => {
	it('includes intelligence and remediation tools', () => {
		const toolNames = TOOLS.map((t) => t.name);
		expect(toolNames).toContain('map_supply_chain');
		expect(toolNames).toContain('analyze_drift');
		expect(toolNames).toContain('validate_fix');
		expect(toolNames).toContain('generate_rollout_plan');
	});

	it('new tools are not included in scan_domain', () => {
		const newTools = TOOLS.filter((t) =>
			['map_supply_chain', 'analyze_drift', 'validate_fix', 'generate_rollout_plan'].includes(t.name),
		);
		for (const tool of newTools) {
			expect(tool.scanIncluded).toBe(false);
		}
	});

	it('has exactly 51 tools', () => {
		expect(TOOLS).toHaveLength(51);
	});
});
