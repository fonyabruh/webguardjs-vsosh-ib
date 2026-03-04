import { describe, expect, it } from 'vitest';
import { RequestAnalyzer } from '../requestAnalyzer';

describe('requestAnalyzer', () => {
  it('uses sessionId from header first, then cookie, then ip|ua fallback', () => {
    const analyzer = new RequestAnalyzer();

    const fromHeader = analyzer.resolveKey(
      {
        'x-webguard-session': 'sid-header',
        cookie: 'wg_sid=sid-cookie',
        'user-agent': 'ua-header'
      },
      '10.0.0.1',
    );
    expect(fromHeader.key).toBe('sid-header');
    expect(fromHeader.sessionId).toBe('sid-header');

    const fromCookie = analyzer.resolveKey(
      {
        cookie: 'wg_sid=sid-cookie-only',
        'user-agent': 'ua-cookie'
      },
      '10.0.0.2',
    );
    expect(fromCookie.key).toBe('sid-cookie-only');
    expect(fromCookie.sessionId).toBe('sid-cookie-only');

    const fallback = analyzer.resolveKey(
      {
        'user-agent': 'ua-fallback'
      },
      '10.0.0.3',
    );
    expect(fallback.key).toBe('10.0.0.3|ua-fallback');
    expect(fallback.sessionId).toBeUndefined();
  });

  it('raises risk for high RPS and regular intervals', () => {
    const analyzer = new RequestAnalyzer();
    const sessionId = 'sess-high-rps';

    for (let i = 0; i < 120; i += 1) {
      pushRequest(analyzer, {
        requestId: `rps-${i}`,
        ts: i * 200,
        path: '/api/v1/data',
        sessionId,
        statusCode: 200,
        headers: browserHeaders()
      });
    }

    const result = analyzer.getRiskByKey(sessionId, 120 * 200 + 100, false);
    expect(result.riskServer).toBeGreaterThan(0.35);
    expect(result.reasons).toContain('HIGH_RPS');
    expect(result.reasons).toContain('REGULAR_INTERVALS');
  });

  it('includes HIGH_ERROR_RATIO when many responses are 4xx/5xx', () => {
    const analyzer = new RequestAnalyzer();
    const sessionId = 'sess-errors';
    const timestamps = [0, 9000, 17000, 34000, 47000, 59000];

    for (let i = 0; i < timestamps.length; i += 1) {
      pushRequest(analyzer, {
        requestId: `err-${i}`,
        ts: timestamps[i],
        path: `/api/v1/resource/${i}`,
        sessionId,
        statusCode: i % 2 === 0 ? 500 : 404,
        headers: browserHeaders()
      });
    }

    const result = analyzer.getRiskByKey(sessionId, 59_500, false);
    expect(result.snapshot.errorRatio).toBeGreaterThan(0.9);
    expect(result.reasons).toContain('HIGH_ERROR_RATIO');
  });

  it('includes NO_TELEMETRY for high activity without heartbeat', () => {
    const analyzer = new RequestAnalyzer();
    const sessionId = 'sess-no-telemetry';

    for (let i = 0; i < 50; i += 1) {
      pushRequest(analyzer, {
        requestId: `no-tele-${i}`,
        ts: i * 400,
        path: `/api/v1/item/${i}`,
        sessionId,
        statusCode: 200,
        headers: browserHeaders()
      });
    }

    const result = analyzer.getRiskByKey(sessionId, 50 * 400 + 200, false);
    expect(result.snapshot.rps60).toBeGreaterThan(0.8);
    expect(result.reasons).toContain('NO_TELEMETRY');
  });

  it('applies EMA smoothing so risk does not jump to raw score immediately', () => {
    const analyzer = new RequestAnalyzer();
    const sessionId = 'sess-ema';

    for (let i = 0; i < 8; i += 1) {
      const ts = i * 8000;
      analyzer.markTelemetry(sessionId, ts);
      pushRequest(analyzer, {
        requestId: `base-${i}`,
        ts,
        path: `/api/v1/base/${i}`,
        sessionId,
        statusCode: 200,
        headers: browserHeaders()
      });
    }

    let transitionFound = false;
    for (let i = 0; i < 15; i += 1) {
      const result = pushRequest(analyzer, {
        requestId: `burst-${i}`,
        ts: 65_000 + i * 200,
        path: '/api/v1/burst',
        sessionId,
        statusCode: 200,
        headers: botLikeHeaders()
      });

      if (result.scoreRaw - result.riskServer > 0.05) {
        transitionFound = true;
        expect(result.riskServer).toBeLessThan(result.scoreRaw);
        break;
      }
    }

    expect(transitionFound).toBe(true);
  });

  it('flags SEQUENTIAL_ENUM for monotonic page enumeration', () => {
    const analyzer = new RequestAnalyzer();
    const sessionId = 'sess-sequential';
    analyzer.markTelemetry(sessionId, 0);

    for (let i = 1; i <= 7; i += 1) {
      pushRequest(analyzer, {
        requestId: `seq-${i}`,
        ts: i * 400,
        path: `/api/v1/items?page=${i}`,
        sessionId,
        statusCode: 200,
        headers: browserHeaders()
      });
    }

    const result = analyzer.getRiskByKey(sessionId, 7 * 400 + 200, false);
    expect(result.snapshot.sequentialEnumScore).toBe(1);
    expect(result.reasons).toContain('SEQUENTIAL_ENUM');
  });
});

function pushRequest(
  analyzer: RequestAnalyzer,
  input: {
    requestId: string;
    ts: number;
    path: string;
    sessionId: string;
    statusCode: number;
    headers: Record<string, string>;
  },
) {
  analyzer.beginRequest({
    requestId: input.requestId,
    ip: '127.0.0.1',
    method: 'GET',
    url: input.path,
    headers: {
      ...input.headers,
      'x-webguard-session': input.sessionId
    },
    now: input.ts
  });

  const result = analyzer.completeRequest({
    requestId: input.requestId,
    statusCode: input.statusCode,
    now: input.ts + 1
  });

  if (!result) {
    throw new Error('expected result from completeRequest');
  }

  return result;
}

function browserHeaders(): Record<string, string> {
  return {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'accept-language': 'en-US,en;q=0.9',
    'sec-ch-ua': '"Chromium";v="121"',
    'sec-fetch-site': 'same-origin',
    referer: 'https://demo.local/page'
  };
}

function botLikeHeaders(): Record<string, string> {
  return {
    'user-agent': 'curl/8.5.0'
  };
}
