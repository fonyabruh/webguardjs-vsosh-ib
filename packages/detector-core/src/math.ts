import { NormalizationRange } from './types';

export function clamp01(value: number): number {
  if (value <= 0) return 0;
  if (value >= 1) return 1;
  return value;
}

export function normalize(value: number, range: NormalizationRange): number {
  if (value <= range.a) return 0;
  if (value >= range.b) return 1;
  return (value - range.a) / (range.b - range.a);
}

export function normalizeInverse(value: number, range: NormalizationRange): number {
  return 1 - normalize(value, range);
}

export function ema(previous: number | null, value: number, alpha: number): number {
  if (previous === null) return value;
  return alpha * value + (1 - alpha) * previous;
}

export function coefficientOfVariation(values: number[]): number {
  if (values.length < 2) return 1;
  const mean = values.reduce((sum, v) => sum + v, 0) / values.length;
  if (mean === 0) return 1;
  const variance =
    values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
  const std = Math.sqrt(variance);
  return std / mean;
}
