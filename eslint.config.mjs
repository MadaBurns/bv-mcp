import tseslint from 'typescript-eslint';

export default tseslint.config(
	{
		ignores: ['coverage/**', 'node_modules/**', '.dev/**', '.firecrawl/**', '.worktrees/**', 'dist/**', 'crates/**/pkg/**', 'worker-configuration.d.ts'],
	},
	{
		files: ['**/*.ts', '**/*.mts'],
		extends: [...tseslint.configs.recommended],
		rules: {
			'no-console': 'off',
			'@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
		},
	},
	{
		files: ['**/*.d.ts'],
		rules: {
			'@typescript-eslint/no-empty-object-type': 'off',
		},
	},
);
