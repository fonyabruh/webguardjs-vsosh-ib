import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';

const rangeSchema = z
  .object({
    a: z.number(),
    b: z.number()
  })
  .refine((value) => value.b > value.a, 'range.b must be greater than range.a');

const webguardConfigSchema = z
  .object({
    debug: z.object({
      enabled: z.boolean()
    }),
    analyzer: z
      .object({
        windowSeconds: z.number().int().min(10).max(300),
        maxSamples: z.number().int().min(20).max(500),
        maxPaths: z.number().int().min(10).max(500),
        profileTtlMs: z.number().int().min(60_000),
        pendingTtlMs: z.number().int().min(10_000),
        telemetryStaleSec: z.number().int().min(30),
        defaultTelemetryAgeSec: z.number().int().min(60),
        emaAlpha: z.number().gt(0).lte(1),
        ranges: z.object({
          rps: rangeSchema,
          burst5s: rangeSchema,
          cv: rangeSchema,
          uniquePathRatio: rangeSchema,
          errorRatio: rangeSchema,
          telemetryAgeSec: rangeSchema,
          browserHeadersScore: rangeSchema
        }),
        weights: z.object({
          highRps: z.number().min(0),
          burst: z.number().min(0),
          regularIntervals: z.number().min(0),
          lowDiversity: z.number().min(0),
          highErrorRatio: z.number().min(0),
          noTelemetry: z.number().min(0),
          suspiciousHeaders: z.number().min(0),
          sequentialEnum: z.number().min(0)
        }),
        sequentialEnum: z.object({
          enabled: z.boolean(),
          minPoints: z.number().int().min(3),
          maxErrors: z.number().int().min(0).max(5)
        }),
        decisions: z.object({
          allowMax: z.number().min(0).max(1),
          delayMax: z.number().min(0).max(1),
          challengeMax: z.number().min(0).max(1)
        }),
        ban: z.object({
          minMinutes: z.number().min(1),
          maxMinutes: z.number().min(1),
          adaptive: z.boolean()
        })
      })
      .superRefine((value, ctx) => {
        if (!(value.decisions.allowMax < value.decisions.delayMax)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'decisions.allowMax must be lower than decisions.delayMax'
          });
        }

        if (!(value.decisions.delayMax < value.decisions.challengeMax)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'decisions.delayMax must be lower than decisions.challengeMax'
          });
        }

        if (value.ban.maxMinutes < value.ban.minMinutes) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'ban.maxMinutes must be >= ban.minMinutes'
          });
        }
      }),
    enforcement: z
      .object({
        enabled: z.boolean(),
        apiPrefix: z.string().min(1),
        excludedPrefixes: z.array(z.string()),
        allowlistPrefixes: z.array(z.string()),
        denylistPrefixes: z.array(z.string()),
        delayMinMs: z.number().int().min(0),
        delayMaxMs: z.number().int().min(0)
      })
      .superRefine((value, ctx) => {
        if (value.delayMaxMs < value.delayMinMs) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'enforcement.delayMaxMs must be >= enforcement.delayMinMs'
          });
        }
      })
  })
  .strict();

export type WebguardConfig = z.infer<typeof webguardConfigSchema>;
export type AnalyzerConfig = WebguardConfig['analyzer'];

const DEFAULT_CONFIG: WebguardConfig = {
  debug: {
    enabled: true
  },
  analyzer: {
    windowSeconds: 60,
    maxSamples: 120,
    maxPaths: 50,
    profileTtlMs: 30 * 60_000,
    pendingTtlMs: 5 * 60_000,
    telemetryStaleSec: 120,
    defaultTelemetryAgeSec: 3600,
    emaAlpha: 0.35,
    ranges: {
      rps: { a: 0.2, b: 2.0 },
      burst5s: { a: 5, b: 20 },
      cv: { a: 0.15, b: 0.8 },
      uniquePathRatio: { a: 0.1, b: 0.6 },
      errorRatio: { a: 0.1, b: 0.6 },
      telemetryAgeSec: { a: 120, b: 600 },
      browserHeadersScore: { a: 0.3, b: 0.9 }
    },
    weights: {
      highRps: 0.2,
      burst: 0.15,
      regularIntervals: 0.15,
      lowDiversity: 0.1,
      highErrorRatio: 0.1,
      noTelemetry: 0.12,
      suspiciousHeaders: 0.08,
      sequentialEnum: 0.1
    },
    sequentialEnum: {
      enabled: true,
      minPoints: 5,
      maxErrors: 2
    },
    decisions: {
      allowMax: 0.55,
      delayMax: 0.7,
      challengeMax: 0.85
    },
    ban: {
      minMinutes: 5,
      maxMinutes: 30,
      adaptive: true
    }
  },
  enforcement: {
    enabled: false,
    apiPrefix: '/api/',
    excludedPrefixes: [
      '/api/v1/telemetry/heartbeat',
      '/api/v1/risk',
      '/dashboard',
      '/assets',
      '/static',
      '/demo',
      '/favicon.ico',
      '/robots.txt'
    ],
    allowlistPrefixes: [],
    denylistPrefixes: [],
    delayMinMs: 300,
    delayMaxMs: 800
  }
};

export function defaultWebguardConfig(): WebguardConfig {
  return clone(DEFAULT_CONFIG);
}

export function loadWebguardConfig(env: NodeJS.ProcessEnv = process.env): WebguardConfig {
  let merged = defaultWebguardConfig();

  const configPath = env.WEBGUARD_CONFIG_PATH;
  if (configPath) {
    const resolved = path.resolve(process.cwd(), configPath);
    const fileContent = fs.readFileSync(resolved, 'utf8');
    const parsed = JSON.parse(fileContent);
    if (!isRecord(parsed)) {
      throw new Error(`WEBGUARD_CONFIG_PATH must point to a JSON object: ${resolved}`);
    }
    merged = mergeConfig(merged, parsed);
  }

  merged = applyEnvOverrides(merged, env);
  return webguardConfigSchema.parse(merged);
}

export function shouldEnforceRequest(
  method: string,
  url: string,
  config: WebguardConfig,
): boolean {
  if (method.toUpperCase() === 'OPTIONS') return false;
  const pathName = stripQuery(url);

  if (matchesPrefix(pathName, config.enforcement.excludedPrefixes)) return false;
  if (matchesPrefix(pathName, config.enforcement.denylistPrefixes)) return false;

  if (config.enforcement.allowlistPrefixes.length > 0) {
    return matchesPrefix(pathName, config.enforcement.allowlistPrefixes);
  }

  return pathName.startsWith(config.enforcement.apiPrefix);
}

function applyEnvOverrides(config: WebguardConfig, env: NodeJS.ProcessEnv): WebguardConfig {
  const next = clone(config);

  const enforce = parseBooleanEnv(env.WEBGUARD_ENFORCE);
  if (enforce !== null) next.enforcement.enabled = enforce;

  const debug = parseBooleanEnv(env.WEBGUARD_DEBUG);
  if (debug !== null) next.debug.enabled = debug;

  const allowlist = parseListEnv(env.WEBGUARD_ENFORCE_ALLOWLIST);
  if (allowlist !== null) next.enforcement.allowlistPrefixes = allowlist;

  const denylist = parseListEnv(env.WEBGUARD_ENFORCE_DENYLIST);
  if (denylist !== null) next.enforcement.denylistPrefixes = denylist;

  const delayMinMs = parseNumberEnv(env.WEBGUARD_DELAY_MIN_MS);
  if (delayMinMs !== null) next.enforcement.delayMinMs = delayMinMs;

  const delayMaxMs = parseNumberEnv(env.WEBGUARD_DELAY_MAX_MS);
  if (delayMaxMs !== null) next.enforcement.delayMaxMs = delayMaxMs;

  const allowThreshold = parseNumberEnv(env.WEBGUARD_THRESHOLD_ALLOW);
  if (allowThreshold !== null) next.analyzer.decisions.allowMax = allowThreshold;

  const delayThreshold = parseNumberEnv(env.WEBGUARD_THRESHOLD_DELAY);
  if (delayThreshold !== null) next.analyzer.decisions.delayMax = delayThreshold;

  const challengeThreshold = parseNumberEnv(env.WEBGUARD_THRESHOLD_CHALLENGE);
  if (challengeThreshold !== null) next.analyzer.decisions.challengeMax = challengeThreshold;

  const emaAlpha = parseNumberEnv(env.WEBGUARD_EMA_ALPHA);
  if (emaAlpha !== null) next.analyzer.emaAlpha = emaAlpha;

  const banMinMinutes = parseNumberEnv(env.WEBGUARD_BAN_MIN_MINUTES);
  if (banMinMinutes !== null) next.analyzer.ban.minMinutes = banMinMinutes;

  const banMaxMinutes = parseNumberEnv(env.WEBGUARD_BAN_MAX_MINUTES);
  if (banMaxMinutes !== null) next.analyzer.ban.maxMinutes = banMaxMinutes;

  return next;
}

function parseNumberEnv(raw: string | undefined): number | null {
  if (raw === undefined || raw.trim() === '') return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseBooleanEnv(raw: string | undefined): boolean | null {
  if (raw === undefined) return null;
  const value = raw.trim().toLowerCase();
  if (value === '1' || value === 'true' || value === 'yes') return true;
  if (value === '0' || value === 'false' || value === 'no') return false;
  return null;
}

function parseListEnv(raw: string | undefined): string[] | null {
  if (raw === undefined) return null;
  return raw
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

function matchesPrefix(pathName: string, prefixes: string[]): boolean {
  return prefixes.some((prefix) => pathName.startsWith(prefix));
}

function stripQuery(url: string): string {
  const [pathName] = url.split('?');
  if (!pathName) return '/';
  return pathName.startsWith('/') ? pathName : `/${pathName}`;
}

function mergeConfig(base: WebguardConfig, patch: Record<string, unknown>): WebguardConfig {
  const merged = mergeUnknown(base as unknown as Record<string, unknown>, patch);
  return merged as unknown as WebguardConfig;
}

function mergeUnknown(
  base: Record<string, unknown>,
  patch: Record<string, unknown>,
): Record<string, unknown> {
  const next: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    const current = next[key];
    if (isRecord(current) && isRecord(value)) {
      next[key] = mergeUnknown(current, value);
      continue;
    }
    next[key] = value;
  }
  return next;
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
