import Fastify, { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { serverConfig } from './config';
import { pool, query } from './db';
import { renderDashboard } from './dashboard';
import { buildIncidentQuery, IncidentFilters } from './queries';
import { checkRateLimit } from './rateLimit';

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

export function buildServer(): FastifyInstance {
  const fastify = Fastify({ logger: false });

  fastify.addHook('onRequest', async (request, reply) => {
    reply.header('Access-Control-Allow-Origin', '*');
    reply.header('Access-Control-Allow-Headers', 'content-type, x-api-key');
    reply.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (request.method === 'OPTIONS') {
      reply.status(204).send();
      return;
    }
  });

  fastify.post('/api/v1/incidents', async (request, reply) => {
    const apiKey = request.headers['x-api-key'];
    if (!apiKey || apiKey !== serverConfig.apiKey) {
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
        payload.risk,
        JSON.stringify(payload.topSignals),
        JSON.stringify(payload.features),
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
    const rows = await query(sql, params);

    return reply.send({ items: rows });
  });

  fastify.get('/dashboard', async (request, reply) => {
    const parseResult = querySchema.safeParse(request.query);
    if (!parseResult.success) {
      return reply.status(400).send('Invalid query');
    }

    const filters = parseFilters(parseResult.data);
    const { sql, params } = buildIncidentQuery(filters);
    const rows = await query(sql, params);
    const html = renderDashboard(rows, filters);

    return reply.type('text/html').send(html);
  });

  fastify.addHook('onClose', async () => {
    await pool.end();
  });

  return fastify;
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
