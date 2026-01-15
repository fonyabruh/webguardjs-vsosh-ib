import { describe, expect, it } from 'vitest';
import { defaultDetectorConfig } from '../config';
import { normalizeFeatures, computeScore, evaluateEvents, reasonCodes, topSignals } from '../score';
import { DetectorConfig, DetectorEvent, FeatureValues } from '../types';

const baseTs = 2_000_000;

function event(offsetMs: number, type: DetectorEvent['type']): DetectorEvent {
  return { ts: baseTs + offsetMs, type };
}

describe('scoring and explainability', () => {
  it('sums weighted normalized features into a raw score', () => {
    const features: FeatureValues = {
      eventRate: 999,
      intervalCv: 0,
      repetitionRatio: 1,
      copyCutPerMin: 999,
      pastePerMin: 999,
      scrollEventsPerMin: 999,
      scrollDistancePerMin: 99999,
      navigationPerMin: 999,
      exportPerMin: 999,
      mouseMoves: 1,
      keyboardAndClicks: 100,
      mouseAbsenceRatio: 100
    };

    const normalized = normalizeFeatures(features, defaultDetectorConfig);
    const { scoreRaw } = computeScore(normalized, defaultDetectorConfig.weights);

    expect(scoreRaw).toBeCloseTo(1);
  });

  it('calculates EMA-based risk in evaluation', () => {
    const config: DetectorConfig = {
      windowSeconds: 60,
      emaAlpha: 0.5,
      topSignalCount: 3,
      thresholds: { warn: 0.7, incident: 0.85, reason: 0.5 },
      weights: {
        event_rate: 0.5,
        interval_regularity: 0.5,
        repetition_ratio: 0,
        copy_activity: 0,
        paste_activity: 0,
        scroll_velocity: 0,
        navigation_burst: 0,
        export_intent: 0,
        mouse_absence_factor: 0
      },
      normalization: {
        event_rate: { a: 0, b: 10 },
        interval_regularity: { a: 0, b: 1 },
        repetition_ratio: { a: 0, b: 1 },
        copy_activity: { a: 0, b: 1 },
        paste_activity: { a: 0, b: 1 },
        scroll_events_per_min: { a: 0, b: 1 },
        scroll_distance_per_min: { a: 0, b: 1 },
        navigation_burst: { a: 0, b: 1 },
        export_intent: { a: 0, b: 1 },
        mouse_absence_factor: { a: 0, b: 1 }
      }
    };

    const events = Array.from({ length: 10 }, (_, i) => event(i * 1000, 'click'));
    const result = evaluateEvents(events, baseTs + 10_000, 0.5, config);

    expect(result.scoreRaw).toBeCloseTo(1);
    expect(result.ema).toBeCloseTo(0.75);
    expect(result.risk).toBeCloseTo(0.75);
  });

  it('returns top signals and reason codes', () => {
    const features: FeatureValues = {
      eventRate: 20,
      intervalCv: 0.01,
      repetitionRatio: 0.2,
      copyCutPerMin: 10,
      pastePerMin: 0,
      scrollEventsPerMin: 0,
      scrollDistancePerMin: 0,
      navigationPerMin: 0,
      exportPerMin: 0,
      mouseMoves: 10,
      keyboardAndClicks: 20,
      mouseAbsenceRatio: 2
    };

    const normalized = normalizeFeatures(features, defaultDetectorConfig);
    const signals = topSignals(features, normalized, defaultDetectorConfig.weights, 3);
    const codes = reasonCodes(normalized, 0.7, defaultDetectorConfig.weights);

    const signalFeatures = signals.map((signal) => signal.feature);
    expect(signalFeatures).toContain('copy_activity');
    expect(signalFeatures).toContain('interval_regularity');
    expect(codes).toContain('HIGH_COPY_RATE');
    expect(codes).toContain('LOW_INTERVAL_VARIANCE');
  });
});
