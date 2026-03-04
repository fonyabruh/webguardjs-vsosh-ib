import { AnalyzerConfig, defaultWebguardConfig } from './webguardConfig';

export type Decision = 'allow' | 'delay' | 'challenge' | 'ban';

type StatusClass = '2xx' | '3xx' | '4xx' | '5xx';

type HeaderValue = string | string[] | undefined;

type HeadersLike = Record<string, HeaderValue>;

type RequestSample = {
  ts: number;
  path: string;
  requestUrl: string;
  statusClass: StatusClass;
};

type PendingRequest = {
  key: string;
  ts: number;
  path: string;
  requestUrl: string;
  method: string;
  userAgent: string;
  browserHeadersScore: number;
};

type WeightedSignalCode =
  | 'HIGH_RPS'
  | 'BURST'
  | 'REGULAR_INTERVALS'
  | 'LOW_DIVERSITY'
  | 'HIGH_ERROR_RATIO'
  | 'NO_TELEMETRY'
  | 'SUSPICIOUS_HEADERS'
  | 'SEQUENTIAL_ENUM';

type WeightedSignal = {
  code: WeightedSignalCode;
  metric: number;
  weight: number;
  contribution: number;
};

export type ServerRiskSnapshot = {
  total60: number;
  byPath: Record<string, number>;
  byStatus: Record<StatusClass, number>;
  rps60: number;
  burst5s: number;
  cvInterArrival: number;
  uniquePathRatio: number;
  errorRatio: number;
  telemetryAgeSec: number;
  hasTelemetryRecently: boolean;
  browserHeadersScore: number;
  sequentialEnumScore: number;
  scoreRaw: number;
  lastSeen: number;
  lastTelemetryAt: number | null;
  // TODO: uaRotation
  // TODO: cookieMissingRatio
  // TODO: nightActivity
};

export type ServerRiskResult = {
  key: string;
  riskServer: number;
  scoreRaw: number;
  decision: Decision;
  reasons: string[];
  snapshot: ServerRiskSnapshot;
  updatedAt: number;
};

type RequestProfile = {
  key: string;
  samples: RequestSample[];
  ema: number | null;
  lastSeen: number;
  lastTelemetryAt: number | null;
  hasTelemetryRecently: boolean;
  lastDecisionAt: number | null;
  lastBrowserHeadersScore: number;
  lastRisk: number;
  userAgent: string;
  ip: string;
};

export type BeginRequestInput = {
  requestId: string;
  ip: string;
  method: string;
  url: string;
  headers: HeadersLike;
  now?: number;
};

export type CompleteRequestInput = {
  requestId: string;
  statusCode: number;
  now?: number;
  activateBan?: boolean;
};

type AnalyzerWindowStats = {
  total: number;
  byPath: Record<string, number>;
  byStatus: Record<StatusClass, number>;
  timestamps: number[];
  requestUrls: string[];
  uniquePathCount: number;
};

const BOT_UA_PATTERN = /(undici|curl|wget|python-requests|httpclient|okhttp|^$)/i;

const DEFAULT_ANALYZER_CONFIG = defaultWebguardConfig().analyzer;

export function fuseRisk(riskClient: number, riskServer: number): number {
  const hi = Math.max(riskClient, riskServer);
  const lo = Math.min(riskClient, riskServer);
  return clamp01(hi + 0.15 * lo);
}

export class RequestAnalyzer {
  private readonly profiles = new Map<string, RequestProfile>();

  private readonly pendingByRequestId = new Map<string, PendingRequest>();

  private readonly banUntil = new Map<string, number>();

  private readonly config: AnalyzerConfig;

  constructor(config: AnalyzerConfig = DEFAULT_ANALYZER_CONFIG) {
    this.config = config;
  }

  beginRequest(input: BeginRequestInput): { key: string; sessionId?: string } {
    const now = input.now ?? Date.now();
    this.cleanup(now);

    const identity = resolveIdentity(input.headers, input.ip);
    const urlParts = normalizeRequestUrl(input.url);
    const profile = this.getOrCreateProfile(identity.key, input.ip, identity.userAgent, now);

    profile.lastSeen = now;
    profile.userAgent = identity.userAgent || profile.userAgent;
    profile.ip = input.ip;
    profile.lastBrowserHeadersScore = identity.browserHeadersScore;
    profile.hasTelemetryRecently =
      profile.lastTelemetryAt !== null &&
      (now - profile.lastTelemetryAt) / 1000 <= this.config.telemetryStaleSec;

    this.pendingByRequestId.set(input.requestId, {
      key: identity.key,
      ts: now,
      path: urlParts.path,
      requestUrl: urlParts.requestUrl,
      method: input.method,
      userAgent: identity.userAgent,
      browserHeadersScore: identity.browserHeadersScore
    });

    return { key: identity.key, sessionId: identity.sessionId };
  }

  completeRequest(input: CompleteRequestInput): ServerRiskResult | null {
    const now = input.now ?? Date.now();
    const pending = this.pendingByRequestId.get(input.requestId);
    if (!pending) return null;

    this.pendingByRequestId.delete(input.requestId);
    const profile = this.getOrCreateProfile(pending.key, '', pending.userAgent, now);
    profile.lastSeen = now;
    profile.lastBrowserHeadersScore = pending.browserHeadersScore;
    profile.userAgent = pending.userAgent || profile.userAgent;

    profile.samples.push({
      ts: pending.ts,
      path: pending.path,
      requestUrl: pending.requestUrl,
      statusClass: classifyStatus(input.statusCode)
    });
    trimSamples(profile.samples, this.config.maxSamples);

    const metrics = this.computeMetrics(profile, now);
    profile.ema = ema(profile.ema, metrics.scoreRaw, this.config.emaAlpha);
    profile.lastRisk = clamp01(profile.ema);
    profile.hasTelemetryRecently = metrics.hasTelemetryRecently;
    const decision = this.resolveDecision(profile.key, profile.lastRisk, now, input.activateBan ?? false);
    profile.lastDecisionAt = now;

    return this.buildResult(profile, metrics, decision, now);
  }

  getRiskByRequestId(
    requestId: string,
    now = Date.now(),
    activateBan = false,
  ): ServerRiskResult | null {
    const pending = this.pendingByRequestId.get(requestId);
    if (!pending) return null;
    return this.getRiskByKey(pending.key, now, activateBan);
  }

  getRiskByKey(key: string, now = Date.now(), activateBan = false): ServerRiskResult {
    const profile = this.getOrCreateProfile(key, '', '', now);
    const metrics = this.computeMetrics(profile, now);
    profile.hasTelemetryRecently = metrics.hasTelemetryRecently;

    const baselineRisk = profile.ema === null ? metrics.scoreRaw : profile.ema;
    const riskServer = clamp01(baselineRisk);
    const decision = this.resolveDecision(profile.key, riskServer, now, activateBan);
    profile.lastDecisionAt = now;
    profile.lastRisk = riskServer;

    return this.buildResult(profile, metrics, decision, now, riskServer);
  }

  markTelemetry(sessionId: string, now = Date.now()): void {
    if (!sessionId) return;
    const profile = this.getOrCreateProfile(sessionId, '', '', now);
    profile.lastTelemetryAt = now;
    profile.hasTelemetryRecently = true;
    profile.lastSeen = now;
  }

  getRetryAfterSec(key: string, now = Date.now()): number {
    const until = this.banUntil.get(key);
    if (!until || until <= now) return 0;
    return Math.ceil((until - now) / 1000);
  }

  resolveKey(headers: HeadersLike, ip: string): { key: string; sessionId?: string } {
    const identity = resolveIdentity(headers, ip);
    return { key: identity.key, sessionId: identity.sessionId };
  }

  private getOrCreateProfile(key: string, ip: string, userAgent: string, now: number): RequestProfile {
    const existing = this.profiles.get(key);
    if (existing) {
      if (ip) existing.ip = ip;
      if (userAgent) existing.userAgent = userAgent;
      return existing;
    }

    const profile: RequestProfile = {
      key,
      samples: [],
      ema: null,
      lastSeen: now,
      lastTelemetryAt: null,
      hasTelemetryRecently: false,
      lastDecisionAt: null,
      lastBrowserHeadersScore: 0,
      lastRisk: 0,
      userAgent,
      ip
    };
    this.profiles.set(key, profile);
    return profile;
  }

  private buildResult(
    profile: RequestProfile,
    metrics: ReturnType<RequestAnalyzer['computeMetrics']>,
    decision: Decision,
    now: number,
    riskOverride?: number,
  ): ServerRiskResult {
    const riskServer = riskOverride ?? clamp01(profile.ema === null ? metrics.scoreRaw : profile.ema);
    const reasons = metrics.signals
      .filter((signal) => signal.contribution > 0)
      .sort((a, b) => b.contribution - a.contribution)
      .slice(0, 3)
      .map((signal) => signal.code);

    const snapshot: ServerRiskSnapshot = {
      total60: metrics.stats.total,
      byPath: metrics.stats.byPath,
      byStatus: metrics.stats.byStatus,
      rps60: metrics.rps60,
      burst5s: metrics.burst5s,
      cvInterArrival: metrics.cvInterArrival,
      uniquePathRatio: metrics.uniquePathRatio,
      errorRatio: metrics.errorRatio,
      telemetryAgeSec: metrics.telemetryAgeSec,
      hasTelemetryRecently: metrics.hasTelemetryRecently,
      browserHeadersScore: metrics.browserHeadersScore,
      sequentialEnumScore: metrics.sequentialEnumScore,
      scoreRaw: metrics.scoreRaw,
      lastSeen: profile.lastSeen,
      lastTelemetryAt: profile.lastTelemetryAt
    };

    return {
      key: profile.key,
      riskServer,
      scoreRaw: metrics.scoreRaw,
      decision,
      reasons,
      snapshot,
      updatedAt: now
    };
  }

  private computeMetrics(profile: RequestProfile, now: number) {
    const stats = windowStats(profile.samples, now, this.config.windowSeconds, this.config.maxPaths);
    const rps60 = stats.total / Math.max(1, this.config.windowSeconds);
    const burst5s = maxRequestsInWindow(stats.timestamps, 5000);
    const cvInterArrival = coefficientOfVariation(interArrival(stats.timestamps));
    const uniquePathRatio = stats.total === 0 ? 1 : stats.uniquePathCount / stats.total;
    const errorCount = stats.byStatus['4xx'] + stats.byStatus['5xx'];
    const errorRatio = stats.total === 0 ? 0 : errorCount / stats.total;
    const telemetryAgeSec =
      profile.lastTelemetryAt === null
        ? this.config.defaultTelemetryAgeSec
        : Math.max(0, (now - profile.lastTelemetryAt) / 1000);
    const hasTelemetryRecently = telemetryAgeSec <= this.config.telemetryStaleSec;
    const browserHeadersScore = profile.lastBrowserHeadersScore;

    const sequentialPattern = detectSequentialEnum(
      stats.requestUrls,
      this.config.sequentialEnum.minPoints,
      this.config.sequentialEnum.maxErrors,
    );
    const suspiciousPacing = rps60 >= 0.8 || burst5s >= 8 || cvInterArrival <= 0.25;
    const sequentialEnumScore =
      this.config.sequentialEnum.enabled && suspiciousPacing && sequentialPattern ? 1 : 0;

    const ranges = this.config.ranges;
    const metrics: Record<WeightedSignalCode, number> = {
      HIGH_RPS: norm(rps60, ranges.rps.a, ranges.rps.b),
      BURST: norm(burst5s, ranges.burst5s.a, ranges.burst5s.b),
      REGULAR_INTERVALS: normInv(cvInterArrival, ranges.cv.a, ranges.cv.b),
      LOW_DIVERSITY: normInv(uniquePathRatio, ranges.uniquePathRatio.a, ranges.uniquePathRatio.b),
      HIGH_ERROR_RATIO: norm(errorRatio, ranges.errorRatio.a, ranges.errorRatio.b),
      NO_TELEMETRY:
        rps60 >= 0.8 && telemetryAgeSec > this.config.telemetryStaleSec
          ? norm(telemetryAgeSec, ranges.telemetryAgeSec.a, ranges.telemetryAgeSec.b)
          : 0,
      SUSPICIOUS_HEADERS: normInv(
        browserHeadersScore,
        ranges.browserHeadersScore.a,
        ranges.browserHeadersScore.b,
      ),
      SEQUENTIAL_ENUM: sequentialEnumScore
    };

    const weights = this.config.weights;
    const weightBySignal: Record<WeightedSignalCode, number> = {
      HIGH_RPS: weights.highRps,
      BURST: weights.burst,
      REGULAR_INTERVALS: weights.regularIntervals,
      LOW_DIVERSITY: weights.lowDiversity,
      HIGH_ERROR_RATIO: weights.highErrorRatio,
      NO_TELEMETRY: weights.noTelemetry,
      SUSPICIOUS_HEADERS: weights.suspiciousHeaders,
      SEQUENTIAL_ENUM: weights.sequentialEnum
    };

    const signals: WeightedSignal[] = (Object.keys(metrics) as WeightedSignalCode[]).map((code) => {
      const metric = clamp01(metrics[code]);
      const weight = weightBySignal[code] ?? 0;
      return {
        code,
        metric,
        weight,
        contribution: weight * metric
      };
    });

    const scoreRaw = clamp01(signals.reduce((sum, signal) => sum + signal.contribution, 0));

    return {
      stats,
      signals,
      scoreRaw,
      rps60,
      burst5s,
      cvInterArrival,
      uniquePathRatio,
      errorRatio,
      telemetryAgeSec,
      hasTelemetryRecently,
      browserHeadersScore,
      sequentialEnumScore
    };
  }

  private resolveDecision(key: string, riskServer: number, now: number, activateBan: boolean): Decision {
    const activeBanUntil = this.banUntil.get(key);
    if (activeBanUntil && activeBanUntil > now) {
      return 'ban';
    }

    const thresholds = this.config.decisions;
    let decision: Decision = 'allow';
    if (riskServer >= thresholds.challengeMax) {
      decision = 'ban';
      if (activateBan) {
        const ttlMs = computeBanTtlMs(riskServer, this.config);
        const currentBan = this.banUntil.get(key) ?? 0;
        const nextBan = now + ttlMs;
        if (nextBan > currentBan) {
          this.banUntil.set(key, nextBan);
        }
      }
    } else if (riskServer >= thresholds.delayMax) {
      decision = 'challenge';
    } else if (riskServer >= thresholds.allowMax) {
      decision = 'delay';
    }

    return decision;
  }

  private cleanup(now: number): void {
    for (const [key, profile] of this.profiles.entries()) {
      if (now - profile.lastSeen > this.config.profileTtlMs) {
        this.profiles.delete(key);
      }
    }

    for (const [key, until] of this.banUntil.entries()) {
      if (until <= now) this.banUntil.delete(key);
    }

    for (const [requestId, pending] of this.pendingByRequestId.entries()) {
      if (now - pending.ts > this.config.pendingTtlMs) {
        this.pendingByRequestId.delete(requestId);
      }
    }
  }
}

function resolveIdentity(headers: HeadersLike, ip: string): {
  key: string;
  sessionId?: string;
  userAgent: string;
  browserHeadersScore: number;
} {
  const session = resolveSessionIdFromHeaders(headers);
  const userAgent = readHeader(headers, 'user-agent') || '';
  const key = session.sessionId || `${ip}|${userAgent || 'unknown'}`;
  return {
    key,
    sessionId: session.sessionId,
    userAgent,
    browserHeadersScore: browserLikeHeadersScore(headers)
  };
}

export function resolveSessionIdFromHeaders(headers: HeadersLike): {
  sessionId?: string;
  source?: 'header' | 'cookie';
} {
  const headerSessionId = readHeader(headers, 'x-webguard-session');
  if (headerSessionId) {
    return { sessionId: headerSessionId.trim(), source: 'header' };
  }

  const cookieHeader = readHeader(headers, 'cookie');
  const cookieSession = extractCookieValue(cookieHeader, 'wg_sid');
  if (cookieSession) {
    return { sessionId: cookieSession, source: 'cookie' };
  }

  return {};
}

export function extractCookieValue(cookieHeader: string | undefined, name: string): string | undefined {
  if (!cookieHeader) return undefined;
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const [rawName, ...rest] = part.trim().split('=');
    if (rawName !== name) continue;
    const rawValue = rest.join('=').trim();
    if (!rawValue) return undefined;
    try {
      return decodeURIComponent(rawValue);
    } catch {
      return rawValue;
    }
  }
  return undefined;
}

function readHeader(headers: HeadersLike, name: string): string | undefined {
  const key = name.toLowerCase();
  const value = headers[key] ?? headers[name];
  if (Array.isArray(value)) return value[0];
  if (typeof value === 'string') return value;
  return undefined;
}

function browserLikeHeadersScore(headers: HeadersLike): number {
  const ua = (readHeader(headers, 'user-agent') || '').trim();
  const hasAcceptLanguage = Boolean(readHeader(headers, 'accept-language'));
  const hasSecChUa = Boolean(readHeader(headers, 'sec-ch-ua'));
  const hasSecFetchSite = Boolean(readHeader(headers, 'sec-fetch-site'));
  const hasReferer = Boolean(readHeader(headers, 'referer'));
  const uaLooksBrowser = ua.length > 0 && !BOT_UA_PATTERN.test(ua);

  let score = 0;
  if (uaLooksBrowser) score += 0.35;
  if (hasAcceptLanguage) score += 0.2;
  if (hasSecChUa) score += 0.2;
  if (hasSecFetchSite) score += 0.15;
  if (hasReferer) score += 0.1;

  return clamp01(score);
}

function windowStats(
  samples: RequestSample[],
  now: number,
  windowSeconds: number,
  maxPaths: number,
): AnalyzerWindowStats {
  const cutoff = now - windowSeconds * 1000;
  const recent = samples.filter((sample) => sample.ts >= cutoff);

  const byStatus: Record<StatusClass, number> = {
    '2xx': 0,
    '3xx': 0,
    '4xx': 0,
    '5xx': 0
  };

  const byPathMap = new Map<string, number>();
  const uniquePaths = new Set<string>();
  const timestamps: number[] = [];
  const requestUrls: string[] = [];

  for (const sample of recent) {
    byStatus[sample.statusClass] += 1;
    timestamps.push(sample.ts);
    requestUrls.push(sample.requestUrl);
    uniquePaths.add(sample.path);

    const key = byPathMap.has(sample.path)
      ? sample.path
      : byPathMap.size < maxPaths
        ? sample.path
        : '__other';
    byPathMap.set(key, (byPathMap.get(key) ?? 0) + 1);
  }

  timestamps.sort((a, b) => a - b);

  const byPath: Record<string, number> = {};
  for (const [path, count] of byPathMap.entries()) {
    byPath[path] = count;
  }

  return {
    total: recent.length,
    byPath,
    byStatus,
    timestamps,
    requestUrls,
    uniquePathCount: Math.min(uniquePaths.size, maxPaths)
  };
}

function classifyStatus(statusCode: number): StatusClass {
  if (statusCode >= 500) return '5xx';
  if (statusCode >= 400) return '4xx';
  if (statusCode >= 300) return '3xx';
  return '2xx';
}

function trimSamples(samples: RequestSample[], maxSamples: number): void {
  if (samples.length <= maxSamples) return;
  samples.splice(0, samples.length - maxSamples);
}

function normalizeRequestUrl(url: string): { path: string; requestUrl: string } {
  const [rawPath, rawQuery] = url.split('?');
  const path = rawPath.startsWith('/') ? rawPath : `/${rawPath}`;
  if (rawQuery === undefined) {
    return { path, requestUrl: path };
  }
  return { path, requestUrl: `${path}?${rawQuery}` };
}

function interArrival(timestamps: number[]): number[] {
  if (timestamps.length < 2) return [];
  const values: number[] = [];
  for (let i = 1; i < timestamps.length; i += 1) {
    values.push(Math.max(0, timestamps[i] - timestamps[i - 1]));
  }
  return values;
}

function maxRequestsInWindow(sortedTimestamps: number[], spanMs: number): number {
  if (sortedTimestamps.length === 0) return 0;

  let max = 1;
  let left = 0;
  for (let right = 0; right < sortedTimestamps.length; right += 1) {
    while (sortedTimestamps[right] - sortedTimestamps[left] > spanMs) {
      left += 1;
    }
    const count = right - left + 1;
    if (count > max) max = count;
  }
  return max;
}

function detectSequentialEnum(requestUrls: string[], minPoints: number, maxErrors: number): boolean {
  const numbers: number[] = [];
  for (const requestUrl of requestUrls) {
    const extracted = extractSequenceNumber(requestUrl);
    if (extracted !== null) numbers.push(extracted);
  }

  if (numbers.length < minPoints) return false;
  if (numbers[numbers.length - 1] <= numbers[0]) return false;

  let errors = 0;
  let goodTransitions = 0;

  for (let i = 1; i < numbers.length; i += 1) {
    const diff = numbers[i] - numbers[i - 1];
    if (diff === 1) {
      goodTransitions += 1;
      continue;
    }

    if (diff >= 0 && diff <= 2) {
      goodTransitions += 1;
      errors += 1;
      continue;
    }

    errors += 1;
  }

  if (errors > maxErrors) return false;
  const transitionRatio = goodTransitions / Math.max(1, numbers.length - 1);
  return transitionRatio >= 0.7;
}

function extractSequenceNumber(requestUrl: string): number | null {
  const [pathName, query = ''] = requestUrl.split('?');
  const searchParams = new URLSearchParams(query);
  const pageParam = searchParams.get('page');
  if (pageParam && /^\d+$/.test(pageParam)) {
    return Number(pageParam);
  }

  const segments = pathName.split('/').filter(Boolean);
  const tail = segments.length > 0 ? segments[segments.length - 1] : '';
  if (/^\d+$/.test(tail)) {
    return Number(tail);
  }

  return null;
}

function clamp01(value: number): number {
  if (value <= 0) return 0;
  if (value >= 1) return 1;
  return value;
}

function norm(value: number, a: number, b: number): number {
  if (value <= a) return 0;
  if (value >= b) return 1;
  return (value - a) / (b - a);
}

function normInv(value: number, a: number, b: number): number {
  return 1 - norm(value, a, b);
}

function ema(previous: number | null, value: number, alpha: number): number {
  if (previous === null) return value;
  return alpha * value + (1 - alpha) * previous;
}

function coefficientOfVariation(values: number[]): number {
  if (values.length < 2) return 1;
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  if (mean <= 0) return 1;

  const variance =
    values.reduce((sum, value) => sum + Math.pow(value - mean, 2), 0) / values.length;
  const std = Math.sqrt(variance);
  return std / mean;
}

function computeBanTtlMs(riskServer: number, config: AnalyzerConfig): number {
  const minMs = Math.round(config.ban.minMinutes * 60_000);
  const maxMs = Math.round(config.ban.maxMinutes * 60_000);

  if (!config.ban.adaptive || maxMs <= minMs) {
    return minMs;
  }

  const scaled = norm(riskServer, config.decisions.challengeMax, 1);
  return Math.round(minMs + scaled * (maxMs - minMs));
}
