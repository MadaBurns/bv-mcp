import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['scripts/csc-*.spec.ts'],
    environment: 'node',
    pool: 'threads',
    testTimeout: 3600000,
  },
});
