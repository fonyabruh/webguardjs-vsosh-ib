import { serverConfig } from './config';

type RateLimitState = {
  count: number;
  resetAt: number;
};

const buckets = new Map<string, RateLimitState>();

export function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const state = buckets.get(ip);
  if (!state || now >= state.resetAt) {
    buckets.set(ip, { count: 1, resetAt: now + serverConfig.rateLimit.windowMs });
    return true;
  }

  if (state.count >= serverConfig.rateLimit.max) {
    return false;
  }

  state.count += 1;
  return true;
}
