import { defineConfig, devices } from '@playwright/test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The e2e suite runs the real Go relay and the production build of the web
// client, then drives two independent browser profiles against them.
const db = join(tmpdir(), `doommsg-e2e-${process.pid}.db`);
const server = process.env.DOOMMSG_SERVER_BIN ?? 'go run ../server/cmd/doommsg-server';

export default defineConfig({
  testDir: './e2e',
  timeout: 90_000,
  fullyParallel: false,
  workers: 1,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    baseURL: 'http://localhost:4173',
    trace: 'retain-on-failure',
    ...devices['Desktop Chrome'],
    launchOptions: {
      executablePath: process.env.PW_CHROMIUM_PATH || undefined,
      args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'],
    },
  },
  webServer: [
    {
      command: server,
      env: {
        DOOMMSG_LISTEN: '127.0.0.1:8080',
        DOOMMSG_METRICS_LISTEN: '',
        DOOMMSG_DB: db,
        DOOMMSG_LOG_LEVEL: 'warn',
      },
      url: 'http://127.0.0.1:8080/readyz',
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command: 'npx vite preview --port 4173 --strictPort',
      url: 'http://localhost:4173',
      reuseExistingServer: false,
    },
  ],
});
