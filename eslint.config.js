import { createRequire } from 'node:module';

const require = createRequire(
	process.env.LINT_NODE_MODULES
		? `${process.env.LINT_NODE_MODULES}/package.json`
		: new URL('./web/package.json', import.meta.url)
);
const js = require('@eslint/js');
const globals = require('globals');
const svelte = require('eslint-plugin-svelte');
const ts = require('typescript-eslint');

export default [
	{ ignores: ['**/.svelte-kit/**', '**/build/**', '**/node_modules/**'] },
	js.configs.recommended,
	...ts.configs.recommended,
	...svelte.configs.recommended,
	{
		languageOptions: {
			globals: { ...globals.browser, ...globals.node }
		},
		linterOptions: { reportUnusedDisableDirectives: 'error' }
	},
	{
		files: ['**/*.svelte'],
		languageOptions: {
			parserOptions: {
				extraFileExtensions: ['.svelte'],
				parser: ts.parser
			}
		},
		rules: {
			'@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
			'no-undef': 'off'
		}
	}
];
