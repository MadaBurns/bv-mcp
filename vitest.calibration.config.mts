import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['scripts/brand-audit-*.spec.ts'],
    environment: 'node',
    pool: 'threads',
    testTimeout: 3600000,
  },
});
