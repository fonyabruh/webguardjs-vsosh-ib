import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fetch } from 'undici';
import { buildServer } from '../server';
import { defaultWebguardConfig } from '../webguardConfig';

describe('server webguard headers', () => {
  let app: ReturnType<typeof buildServer>;
  let baseUrl = '';

  beforeAll(async () => {
    app = buildServer();
    baseUrl = await app.listen({ port: 0, host: '127.0.0.1' });
  });

  afterAll(async () => {
    await app.close();
  });

  it('adds X-WebGuard headers for /api/v1/risk', async () => {
    for (let i = 0; i < 8; i += 1) {
      const response = await fetch(`${baseUrl}/api/v1/risk`, {
        headers: {
          'x-webguard-session': 'vitest-session',
          'user-agent': 'vitest-agent',
          'accept-language': 'en-US',
          'sec-ch-ua': '"Chromium";v="121"',
          'sec-fetch-site': 'same-origin'
        }
      });

      expect(response.status).toBe(200);
      const riskHeader = response.headers.get('X-WebGuard-Risk-Server');
      const decisionHeader = response.headers.get('X-WebGuard-Decision');

      expect(riskHeader).toBeTruthy();
      expect(decisionHeader).toBeTruthy();
      const risk = Number(riskHeader);
      expect(Number.isFinite(risk)).toBe(true);
      expect(risk).toBeGreaterThanOrEqual(0);
      expect(risk).toBeLessThanOrEqual(1);
    }
  });

  it('hides /api/v1/risk when debug is disabled', async () => {
    const config = defaultWebguardConfig();
    config.debug.enabled = false;

    const debugOffApp = buildServer(config);
    const debugOffBaseUrl = await debugOffApp.listen({ port: 0, host: '127.0.0.1' });

    try {
      const response = await fetch(`${debugOffBaseUrl}/api/v1/risk`, {
        headers: {
          'x-webguard-session': 'debug-off-session',
          'user-agent': 'vitest-agent'
        }
      });

      expect(response.status).toBe(404);
    } finally {
      await debugOffApp.close();
    }
  });
});
