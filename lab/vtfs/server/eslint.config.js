import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';

export default [
    {
        files: ['**/*.ts'],
        plugins: {
            '@typescript-eslint': tsPlugin,
            import: true
        },
        languageOptions: {
            parser: tsParser,
            parserOptions: {
                project: './tsconfig.json'
            }
        },
        rules: {
            ...tsPlugin.configs['recommended-type-checked'].rules,
            'import/order': 'error',
            '@typescript-eslint/consistent-type-imports': 'error'
        }
    }
];
