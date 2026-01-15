import { clamp01, ema, normalize, normalizeInverse } from './math';
import {
  DetectorConfig,
  DetectorEvent,
  DetectorWeights,
  DetectionResult,
  FeatureId,
  FeatureValues,
  NormalizedFeatures,
  TopSignal
} from './types';
import { buildCounters, computeFeatureValues, filterEventsByWindow } from './features';

const FEATURE_ORDER: FeatureId[] = [
  'event_rate',
  'interval_regularity',
  'repetition_ratio',
  'copy_activity',
  'paste_activity',
  'scroll_velocity',
  'navigation_burst',
  'export_intent',
  'mouse_absence_factor'
];

const REASON_CODES: Record<FeatureId, string> = {
  event_rate: 'HIGH_EVENT_RATE',
  interval_regularity: 'LOW_INTERVAL_VARIANCE',
  repetition_ratio: 'HIGH_REPETITION',
  copy_activity: 'HIGH_COPY_RATE',
  paste_activity: 'HIGH_PASTE_RATE',
  scroll_velocity: 'FAST_SCROLL',
  navigation_burst: 'NAV_BURST',
  export_intent: 'EXPORT_INTENT',
  mouse_absence_factor: 'LOW_MOUSE_ACTIVITY'
};

export function normalizeFeatures(
  values: FeatureValues,
  config: DetectorConfig,
): NormalizedFeatures {
  const scrollEventsNorm = normalize(
    values.scrollEventsPerMin,
    config.normalization.scroll_events_per_min,
  );
  const scrollDistanceNorm = normalize(
    values.scrollDistancePerMin,
    config.normalization.scroll_distance_per_min,
  );
  const scrollVelocity = clamp01((scrollEventsNorm + scrollDistanceNorm) / 2);

  return {
    event_rate: normalize(values.eventRate, config.normalization.event_rate),
    interval_regularity: normalizeInverse(
      values.intervalCv,
      config.normalization.interval_regularity,
    ),
    repetition_ratio: normalize(values.repetitionRatio, config.normalization.repetition_ratio),
    copy_activity: normalize(values.copyCutPerMin, config.normalization.copy_activity),
    paste_activity: normalize(values.pastePerMin, config.normalization.paste_activity),
    scroll_velocity: scrollVelocity,
    navigation_burst: normalize(values.navigationPerMin, config.normalization.navigation_burst),
    export_intent: normalize(values.exportPerMin, config.normalization.export_intent),
    mouse_absence_factor: normalize(
      values.mouseAbsenceRatio,
      config.normalization.mouse_absence_factor,
    )
  };
}

export function computeScore(
  normalized: NormalizedFeatures,
  weights: DetectorWeights,
): { scoreRaw: number; contributions: Record<FeatureId, number> } {
  const weight = (feature: FeatureId): number => weights[feature] || 0;
  const contributions = FEATURE_ORDER.reduce<Record<FeatureId, number>>((acc, feature) => {
    const value = normalized[feature] || 0;
    acc[feature] = weight(feature) * value;
    return acc;
  }, {} as Record<FeatureId, number>);

  const scoreRaw = FEATURE_ORDER.reduce((sum, feature) => sum + contributions[feature], 0);
  return { scoreRaw, contributions };
}

export function topSignals(
  values: FeatureValues,
  normalized: NormalizedFeatures,
  weights: DetectorWeights,
  count: number,
): TopSignal[] {
  const weight = (feature: FeatureId): number => weights[feature] || 0;
  const rawValue = (feature: FeatureId): number => {
    switch (feature) {
      case 'event_rate':
        return values.eventRate;
      case 'interval_regularity':
        return values.intervalCv;
      case 'repetition_ratio':
        return values.repetitionRatio;
      case 'copy_activity':
        return values.copyCutPerMin;
      case 'paste_activity':
        return values.pastePerMin;
      case 'scroll_velocity':
        return values.scrollEventsPerMin;
      case 'navigation_burst':
        return values.navigationPerMin;
      case 'export_intent':
        return values.exportPerMin;
      case 'mouse_absence_factor':
        return values.mouseAbsenceRatio;
      default:
        return 0;
    }
  };

  const signals = FEATURE_ORDER.map((feature) => {
    const normalizedValue = normalized[feature] || 0;
    return {
      feature,
      contribution: weight(feature) * normalizedValue,
      weight: weight(feature),
      value: rawValue(feature),
      normalized: normalizedValue
    };
  });

  return signals.sort((a, b) => b.contribution - a.contribution).slice(0, count);
}

export function reasonCodes(
  normalized: NormalizedFeatures,
  threshold: number,
  weights: DetectorWeights,
): string[] {
  const codes: string[] = [];
  for (const feature of FEATURE_ORDER) {
    const value = normalized[feature] || 0;
    if ((weights[feature] || 0) <= 0) continue;
    if (value >= threshold) {
      codes.push(REASON_CODES[feature]);
    }
  }
  return codes;
}

export function evaluateEvents(
  events: DetectorEvent[],
  nowMs: number,
  previousEma: number | null,
  config: DetectorConfig,
): DetectionResult {
  const windowed = filterEventsByWindow(events, nowMs, config.windowSeconds);
  const features = computeFeatureValues(windowed, config.windowSeconds);
  const normalized = normalizeFeatures(features, config);
  const { scoreRaw } = computeScore(normalized, config.weights);
  const emaValue = ema(previousEma, scoreRaw, config.emaAlpha);
  const counters = buildCounters(windowed, config.windowSeconds);

  return {
    ts: nowMs,
    risk: clamp01(emaValue),
    scoreRaw,
    ema: emaValue,
    features,
    normalized,
    topSignals: topSignals(features, normalized, config.weights, config.topSignalCount),
    reasonCodes: reasonCodes(normalized, config.thresholds.reason, config.weights),
    counters
  };
}
