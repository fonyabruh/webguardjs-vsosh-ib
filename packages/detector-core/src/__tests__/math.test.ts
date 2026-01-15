import { describe, expect, it } from 'vitest';
import { coefficientOfVariation, ema, normalize, normalizeInverse } from '../math';

describe('math helpers', () => {
  it('normalizes with piecewise linear function', () => {
    expect(normalize(0, { a: 1, b: 3 })).toBe(0);
    expect(normalize(1, { a: 1, b: 3 })).toBe(0);
    expect(normalize(2, { a: 1, b: 3 })).toBeCloseTo(0.5);
    expect(normalize(3, { a: 1, b: 3 })).toBe(1);
    expect(normalize(10, { a: 1, b: 3 })).toBe(1);
  });

  it('inverts normalization for low-variance detection', () => {
    expect(normalizeInverse(0, { a: 0.1, b: 0.5 })).toBe(1);
    expect(normalizeInverse(0.1, { a: 0.1, b: 0.5 })).toBe(1);
    expect(normalizeInverse(0.3, { a: 0.1, b: 0.5 })).toBeCloseTo(0.5);
    expect(normalizeInverse(0.5, { a: 0.1, b: 0.5 })).toBe(0);
  });

  it('computes coefficient of variation for intervals', () => {
    const uniform = coefficientOfVariation([1000, 1000, 1000]);
    expect(uniform).toBeCloseTo(0);

    const varied = coefficientOfVariation([1000, 2000, 3000]);
    expect(varied).toBeCloseTo(0.4082, 3);
  });

  it('calculates ema with alpha', () => {
    expect(ema(null, 0.8, 0.35)).toBe(0.8);
    expect(ema(0.5, 1, 0.35)).toBeCloseTo(0.675);
  });
});
