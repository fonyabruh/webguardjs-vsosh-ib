import { describe, expect, it } from 'vitest';
import { defaultWebguardConfig, shouldEnforceRequest } from '../webguardConfig';

describe('webguardConfig enforcement matcher', () => {
  it('excludes protected and static routes', () => {
    const config = defaultWebguardConfig();
    config.enforcement.enabled = true;

    expect(shouldEnforceRequest('OPTIONS', '/api/v1/data', config)).toBe(false);
    expect(shouldEnforceRequest('GET', '/api/v1/telemetry/heartbeat', config)).toBe(false);
    expect(shouldEnforceRequest('GET', '/api/v1/risk', config)).toBe(false);
    expect(shouldEnforceRequest('GET', '/dashboard', config)).toBe(false);
    expect(shouldEnforceRequest('GET', '/assets/app.js', config)).toBe(false);
    expect(shouldEnforceRequest('GET', '/static/main.css', config)).toBe(false);
  });

  it('respects allowlist when provided', () => {
    const config = defaultWebguardConfig();
    config.enforcement.allowlistPrefixes = ['/api/v1/data', '/api/v1/export', '/api/v1/search'];

    expect(shouldEnforceRequest('GET', '/api/v1/data/list', config)).toBe(true);
    expect(shouldEnforceRequest('GET', '/api/v1/incidents', config)).toBe(false);
    expect(shouldEnforceRequest('GET', '/dashboard', config)).toBe(false);
  });

  it('respects denylist overrides', () => {
    const config = defaultWebguardConfig();
    config.enforcement.denylistPrefixes = ['/api/v1/incidents'];

    expect(shouldEnforceRequest('GET', '/api/v1/incidents', config)).toBe(false);
    expect(shouldEnforceRequest('GET', '/api/v1/unknown', config)).toBe(true);
  });
});
