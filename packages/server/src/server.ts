import Fastify, { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import { serverConfig } from './config';
import { pool, query } from './db';
import { IncidentRow, renderDashboard } from './dashboard';
import { buildIncidentQuery, IncidentFilters } from './queries';
import { checkRateLimit } from './rateLimit';
import {
  extractCookieValue,
  fuseRisk,
  RequestAnalyzer,
  resolveSessionIdFromHeaders,
  ServerRiskResult
} from './requestAnalyzer';
import { loadWebguardConfig, shouldEnforceRequest, WebguardConfig } from './webguardConfig';

const topSignalSchema = z.object({
  feature: z.string(),
  contribution: z.number(),
  weight: z.number(),
  value: z.number(),
  normalized: z.number()
});

const incidentSchema = z.object({
  ts: z.number(),
  sessionId: z.string(),
  pageId: z.string(),
  risk: z.number().min(0).max(1),
  topSignals: z.array(topSignalSchema),
  features: z.unknown(),
  counters: z.unknown(),
  userAgent: z.string()
});

const querySchema = z.object({
  minRisk: z.string().optional(),
  from: z.string().optional(),
  to: z.string().optional(),
  pageId: z.string().optional(),
  sessionId: z.string().optional(),
  limit: z.string().optional(),
  offset: z.string().optional()
});

const heartbeatSchema = z.object({
  sessionId: z.string().min(1),
  pageId: z.string().min(1),
  ts: z.number()
});

export function buildServer(webguardConfig: WebguardConfig = loadWebguardConfig()): FastifyInstance {
  const fastify = Fastify({ logger: false });
  const analyzer = new RequestAnalyzer(webguardConfig.analyzer);

  fastify.addHook('onRequest', async (request, reply) => {
    reply.header('Access-Control-Allow-Origin', '*');
    reply.header('Access-Control-Allow-Headers', 'content-type, x-api-key, x-webguard-session');
    reply.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (request.method === 'OPTIONS') {
      reply.status(204).send();
      return;
    }

    analyzer.beginRequest({
      requestId: request.id,
      ip: request.ip,
      method: request.method,
      url: request.url,
      headers: request.headers
    });

    syncSessionCookie(reply, request.headers, request.protocol);
  });

  fastify.addHook('preHandler', async (request, reply) => {
    if (!webguardConfig.enforcement.enabled) return;
    if (!shouldEnforceRequest(request.method, request.url, webguardConfig)) return;

    const now = Date.now();
    const riskState = analyzer.getRiskByRequestId(request.id, now, true);
    if (!riskState) return;

    if (riskState.decision === 'delay') {
      await sleep(randomInt(webguardConfig.enforcement.delayMinMs, webguardConfig.enforcement.delayMaxMs));
      return;
    }

    if (riskState.decision === 'challenge') {
      return reply.status(403).send({
        error: 'challenge',
        hint: 'enable js or pass telemetry',
        decision: 'challenge',
        riskServer: riskState.riskServer,
        reasons: riskState.reasons
      });
    }

    if (riskState.decision === 'ban') {
      const retryAfterSec = analyzer.getRetryAfterSec(riskState.key, now);
      return reply.status(429).send({
        error: 'banned',
        retryAfterSec,
        decision: 'ban',
        riskServer: riskState.riskServer,
        reasons: riskState.reasons
      });
    }
  });

  fastify.addHook('onSend', async (request, reply, payload) => {
    if (request.method === 'OPTIONS') return payload;

    const riskState = analyzer.completeRequest({
      requestId: request.id,
      statusCode: reply.statusCode,
      activateBan: webguardConfig.enforcement.enabled
    });

    if (riskState) {
      reply.header('X-WebGuard-Risk-Server', riskState.riskServer.toFixed(3));
      reply.header('X-WebGuard-Decision', riskState.decision);
    }

    return payload;
  });

  fastify.get('/api/v1/risk', async (request, reply) => {
    if (!webguardConfig.debug.enabled) {
      return reply.status(404).send({ error: 'Not Found' });
    }

    const riskState =
      analyzer.getRiskByRequestId(request.id, Date.now(), false) ?? resolveRiskForRequest(analyzer, request);
    return reply.send({
      key: riskState.key,
      riskServer: riskState.riskServer,
      decision: riskState.decision,
      reasons: riskState.reasons,
      snapshot: riskState.snapshot,
      updatedAt: riskState.updatedAt
    });
  });

  fastify.post('/api/v1/telemetry/heartbeat', async (request, reply) => {
    if (!isValidApiKey(request.headers['x-api-key'])) {
      return reply.status(401).send({ error: 'Unauthorized' });
    }

    const parseResult = heartbeatSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({ error: 'Invalid payload', details: parseResult.error.issues });
    }

    analyzer.markTelemetry(parseResult.data.sessionId, Date.now());
    return reply.send({ ok: true });
  });

  fastify.post('/api/v1/incidents', async (request, reply) => {
    if (!isValidApiKey(request.headers['x-api-key'])) {
      return reply.status(401).send({ error: 'Unauthorized' });
    }

    if (!checkRateLimit(request.ip)) {
      return reply.status(429).send({ error: 'Rate limit exceeded' });
    }

    const parseResult = incidentSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({ error: 'Invalid payload', details: parseResult.error.issues });
    }

    const payload = parseResult.data;
    const session = resolveSessionIdFromHeaders(request.headers);
    const key = payload.sessionId || session.sessionId || analyzer.resolveKey(request.headers, request.ip).key;
    const serverRisk = analyzer.getRiskByKey(key, Date.now(), false);
    const riskTotal = fuseRisk(payload.risk, serverRisk.riskServer);
    const features = mergeServerFeatures(payload.features, {
      riskServer: serverRisk.riskServer,
      riskClient: payload.risk,
      riskTotal,
      reasons: serverRisk.reasons,
      snapshot: serverRisk.snapshot
    });

    const rows = await query<{ id: string }>(
      `
      INSERT INTO incidents (id, ts, session_id, page_id, risk, top_signals, features, counters, user_agent)
      VALUES (gen_random_uuid(), to_timestamp($1 / 1000.0), $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8)
      RETURNING id
    `,
      [
        payload.ts,
        payload.sessionId,
        payload.pageId,
        riskTotal,
        JSON.stringify(payload.topSignals),
        JSON.stringify(features),
        JSON.stringify(payload.counters),
        payload.userAgent
      ],
    );

    return reply.status(201).send({ id: rows[0]?.id });
  });

  fastify.get('/api/v1/incidents', async (request, reply) => {
    const parseResult = querySchema.safeParse(request.query);
    if (!parseResult.success) {
      return reply.status(400).send({ error: 'Invalid query', details: parseResult.error.issues });
    }

    const filters = parseFilters(parseResult.data);
    const { sql, params } = buildIncidentQuery(filters);
    const rows = await query<IncidentRow>(sql, params);

    return reply.send({ items: rows });
  });

  fastify.get('/dashboard', async (request, reply) => {
    const parseResult = querySchema.safeParse(request.query);
    if (!parseResult.success) {
      return reply.status(400).send('Invalid query');
    }

    const filters = parseFilters(parseResult.data);
    const { sql, params } = buildIncidentQuery(filters);
    const rows = await query<IncidentRow>(sql, params);
    const html = renderDashboard(rows, filters);

    return reply.type('text/html').send(html);
  });

  fastify.addHook('onClose', async () => {
    await closePoolSafely();
  });

  return fastify;
}

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isValidApiKey(value: unknown): boolean {
  return typeof value === 'string' && value === serverConfig.apiKey;
}

function resolveRiskForRequest(
  analyzer: RequestAnalyzer,
  request: { headers: Record<string, string | string[] | undefined>; ip: string },
): ServerRiskResult {
  const identity = analyzer.resolveKey(request.headers, request.ip);
  return analyzer.getRiskByKey(identity.key, Date.now(), false);
}

function mergeServerFeatures(features: unknown, serverFeatures: Record<string, unknown>): Record<string, unknown> {
  if (isRecord(features)) {
    return {
      ...features,
      server: serverFeatures
    };
  }

  return {
    client: features,
    server: serverFeatures
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

async function closePoolSafely(): Promise<void> {
  try {
    await pool.end();
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes('Called end on pool more than once')
    ) {
      return;
    }
    throw error;
  }
}

function syncSessionCookie(
  reply: FastifyReply,
  headers: Record<string, string | string[] | undefined>,
  protocol: string,
): void {
  const session = resolveSessionIdFromHeaders(headers);
  if (!session.sessionId || session.source !== 'header') return;

  const cookieHeader = readHeaderValue(headers, 'cookie');
  const cookieSession = extractCookieValue(cookieHeader, 'wg_sid');
  if (cookieSession) return;

  const encoded = encodeURIComponent(session.sessionId);
  const secure = protocol === 'https' ? '; Secure' : '';
  appendSetCookie(
    reply,
    `wg_sid=${encoded}; Path=/; SameSite=Lax; Max-Age=2592000${secure}`,
  );
}

function appendSetCookie(reply: FastifyReply, cookieValue: string): void {
  const existing = reply.getHeader('set-cookie');
  if (!existing) {
    reply.header('Set-Cookie', cookieValue);
    return;
  }

  if (Array.isArray(existing)) {
    reply.header('Set-Cookie', [...existing, cookieValue]);
    return;
  }

  reply.header('Set-Cookie', [String(existing), cookieValue]);
}

function readHeaderValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const value = headers[name] ?? headers[name.toLowerCase()];
  if (Array.isArray(value)) return value[0];
  return typeof value === 'string' ? value : undefined;
}

function parseFilters(input: z.infer<typeof querySchema>): IncidentFilters {
  const minRisk = toNumber(input.minRisk);
  const limit = clampNumber(toNumber(input.limit) ?? 50, 1, 200);
  const offset = clampNumber(toNumber(input.offset) ?? 0, 0, 10_000);
  const from = parseDate(input.from);
  const to = parseDate(input.to);

  return {
    minRisk: minRisk === null ? undefined : minRisk,
    from: from || undefined,
    to: to || undefined,
    pageId: input.pageId || undefined,
    sessionId: input.sessionId || undefined,
    limit,
    offset
  };
}

function toNumber(value?: string): number | null {
  if (!value) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function clampNumber(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function parseDate(value?: string): Date | null {
  if (!value) return null;
  const numeric = Number(value);
  if (!Number.isNaN(numeric)) {
    return new Date(numeric);
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}
