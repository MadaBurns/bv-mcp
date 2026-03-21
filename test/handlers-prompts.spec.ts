import { describe, it, expect } from 'vitest';
import { handlePromptsList, handlePromptsGet } from '../src/handlers/prompts';

describe('handlePromptsList', () => {
	it('returns an object with a prompts array of exactly 5 items', () => {
		const result = handlePromptsList();
		expect(result).toHaveProperty('prompts');
		expect(result.prompts).toHaveLength(5);
	});

	it('each prompt has name, description, and arguments', () => {
		const { prompts } = handlePromptsList();
		for (const prompt of prompts) {
			expect(prompt).toHaveProperty('name');
			expect(prompt).toHaveProperty('description');
			expect(prompt).toHaveProperty('arguments');
			expect(Array.isArray(prompt.arguments)).toBe(true);
		}
	});

	it('includes all expected prompt names', () => {
		const { prompts } = handlePromptsList();
		const names = prompts.map((p) => p.name);
		expect(names).toContain('full-security-audit');
		expect(names).toContain('email-auth-check');
		expect(names).toContain('policy-compliance-check');
	});

	it('all prompts require a domain argument', () => {
		const { prompts } = handlePromptsList();
		for (const prompt of prompts) {
			const domainArg = prompt.arguments.find((a) => a.name === 'domain');
			expect(domainArg).toBeDefined();
			expect(domainArg!.required).toBe(true);
		}
	});

	it('policy-compliance-check has an optional minimum_grade argument', () => {
		const { prompts } = handlePromptsList();
		const prompt = prompts.find((p) => p.name === 'policy-compliance-check')!;
		const gradeArg = prompt.arguments.find((a) => a.name === 'minimum_grade');
		expect(gradeArg).toBeDefined();
		expect(gradeArg!.required).toBe(false);
	});
});

describe('handlePromptsGet', () => {
	it('returns messages for full-security-audit', () => {
		const result = handlePromptsGet({ name: 'full-security-audit', arguments: { domain: 'example.com' } });
		expect(result).toHaveProperty('description');
		expect(result).toHaveProperty('messages');
		expect(result.messages).toHaveLength(1);
		expect(result.messages[0].role).toBe('user');
		expect(result.messages[0].content.type).toBe('text');
		expect(result.messages[0].content.text).toContain('example.com');
		expect(result.messages[0].content.text).toContain('scan_domain');
	});

	it('returns messages for email-auth-check', () => {
		const result = handlePromptsGet({ name: 'email-auth-check', arguments: { domain: 'test.org' } });
		expect(result.messages).toHaveLength(1);
		expect(result.messages[0].content.text).toContain('test.org');
		expect(result.messages[0].content.text).toContain('check_spf');
		expect(result.messages[0].content.text).toContain('check_dmarc');
		expect(result.messages[0].content.text).toContain('check_dkim');
		expect(result.messages[0].content.text).toContain('check_mta_sts');
	});

	it('returns messages for policy-compliance-check with default grade', () => {
		const result = handlePromptsGet({ name: 'policy-compliance-check', arguments: { domain: 'corp.io' } });
		expect(result.messages).toHaveLength(1);
		expect(result.messages[0].content.text).toContain('corp.io');
		expect(result.messages[0].content.text).toContain('compare_baseline');
		expect(result.messages[0].content.text).toContain('"B"');
	});

	it('uses custom minimum_grade when provided', () => {
		const result = handlePromptsGet({
			name: 'policy-compliance-check',
			arguments: { domain: 'corp.io', minimum_grade: 'A' },
		});
		expect(result.messages[0].content.text).toContain('"A"');
	});

	it('throws for unknown prompt name', () => {
		expect(() => handlePromptsGet({ name: 'nonexistent' })).toThrow('Invalid prompt name');
	});

	it('throws when name parameter is missing', () => {
		expect(() => handlePromptsGet({})).toThrow('Missing required parameter: name');
	});

	it('throws when name is not a string', () => {
		expect(() => handlePromptsGet({ name: 42 })).toThrow('Missing required parameter: name');
	});
});
