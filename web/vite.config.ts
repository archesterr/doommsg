import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

const backend = process.env.DOOMMSG_BACKEND ?? 'http://127.0.0.1:8080';

// Mirrors deploy/Caddyfile so the e2e suite runs under the production CSP.
// Keep the two in sync.
export const securityHeaders = {
  'Content-Security-Policy': [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "font-src 'self'",
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "connect-src 'self'",
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
  ].join('; '),
  'Permissions-Policy': 'camera=(self), microphone=(self), geolocation=(), payment=(), usb=(), interest-cohort=()',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: backend, ws: true, changeOrigin: false },
    },
  },
  preview: {
    headers: securityHeaders,
  },
  build: {
    target: 'es2022',
    sourcemap: false,
    // Everything is bundled locally: no third-party CDNs, fonts or trackers.
    assetsInlineLimit: 0,
  },
  test: {
    environment: 'node',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.ts'],
  },
});
