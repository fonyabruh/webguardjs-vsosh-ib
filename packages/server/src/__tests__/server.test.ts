import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { fetch } from 'undici';
import { buildServer } from '../server';
import { query } from '../db';

const hasDb = Boolean(process.env.DATABASE_URL || process.env.PGHOST);
const describeDb = hasDb ? describe : describe.skip;

describeDb('server integration', () => {
  const apiKey = process.env.API_KEY || 'changeme';
  const sessionIds: string[] = [];
  let baseUrl = '';
  let app: ReturnType<typeof buildServer>;

  beforeAll(async () => {
    app = buildServer();
    const address = await app.listen({ port: 0, host: '127.0.0.1' });
    baseUrl = address;
  });

  afterAll(async () => {
    if (sessionIds.length > 0) {
      await query('DELETE FROM incidents WHERE session_id = ANY($1)', [sessionIds]);
    }
    await app.close();
  });

  it('accepts a valid incident and writes it to the DB', async () => {
    const sessionId = `test-session-${Date.now()}`;
    sessionIds.push(sessionId);
    const payload = buildPayload(sessionId, 0.92);

    const response = await fetch(`${baseUrl}/api/v1/incidents`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'X-API-Key': apiKey
      },
      body: JSON.stringify(payload)
    });

    expect(response.status).toBe(201);
    const body = await response.json();
    expect(body.id).toBeTruthy();

    const rows = await query<{ id: string }>(
      'SELECT id FROM incidents WHERE session_id = $1 LIMIT 1',
      [sessionId],
    );
    expect(rows.length).toBe(1);
  });

  it('rejects invalid payloads', async () => {
    const response = await fetch(`${baseUrl}/api/v1/incidents`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'X-API-Key': apiKey
      },
      body: JSON.stringify({ foo: 'bar' })
    });

    expect(response.status).toBe(400);
  });

  it('requires a valid API key', async () => {
    const response = await fetch(`${baseUrl}/api/v1/incidents`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'X-API-Key': 'invalid'
      },
      body: JSON.stringify(buildPayload(`bad-key-${Date.now()}`, 0.9))
    });

    expect(response.status).toBe(401);
  });

  it('filters incidents by risk and page id', async () => {
    const lowSession = `low-risk-${Date.now()}`;
    const highSession = `high-risk-${Date.now()}`;
    sessionIds.push(lowSession, highSession);

    await fetch(`${baseUrl}/api/v1/incidents`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'X-API-Key': apiKey
      },
      body: JSON.stringify(buildPayload(lowSession, 0.4, 'page-low'))
    });

    await fetch(`${baseUrl}/api/v1/incidents`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'X-API-Key': apiKey
      },
      body: JSON.stringify(buildPayload(highSession, 0.95, 'page-high'))
    });

    const response = await fetch(
      `${baseUrl}/api/v1/incidents?minRisk=0.8&pageId=page-high&limit=10&offset=0`,
    );

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.items.length).toBeGreaterThanOrEqual(1);
    expect(body.items[0].page_id).toBe('page-high');
  });
});

function buildPayload(sessionId: string, risk: number, pageId = 'page-test') {
  return {
    ts: Date.now(),
    sessionId,
    pageId,
    risk,
    topSignals: [
      {
        feature: 'copy_activity',
        contribution: 0.2,
        weight: 0.2,
        value: 5,
        normalized: 1
      }
    ],
    features: {
      values: {
        eventRate: 40,
        intervalCv: 0.1,
        repetitionRatio: 0.6,
        copyCutPerMin: 5,
        pastePerMin: 0,
        scrollEventsPerMin: 0,
        scrollDistancePerMin: 0,
        navigationPerMin: 0,
        exportPerMin: 0,
        mouseMoves: 1,
        keyboardAndClicks: 10,
        mouseAbsenceRatio: 10
      }
    },
    counters: {
      totalEvents: 10,
      byType: {
        click: 2,
        keydown: 3,
        input: 1,
        scroll: 0,
        copy: 2,
        cut: 1,
        paste: 0,
        mousemove: 1,
        navigation: 0,
        export: 0
      },
      windowSeconds: 60
    },
    userAgent: 'vitest'
  };
}
