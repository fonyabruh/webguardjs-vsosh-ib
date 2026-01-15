export type EventType =
  | 'click'
  | 'keydown'
  | 'input'
  | 'scroll'
  | 'copy'
  | 'cut'
  | 'paste'
  | 'mousemove'
  | 'navigation'
  | 'export';

export type ElementType = 'input' | 'textarea' | 'button' | 'div' | 'a' | 'other';

export type NavigationKind = 'pushState' | 'replaceState' | 'popstate';

export type ExportKind = 'print' | 'data-export' | 'download';

export interface DetectorEvent {
  ts: number;
  type: EventType;
  elementType?: ElementType;
  selectionLength?: number;
  scrollDeltaY?: number;
  navigationKind?: NavigationKind;
  exportKind?: ExportKind;
}

export type FeatureId =
  | 'event_rate'
  | 'interval_regularity'
  | 'repetition_ratio'
  | 'copy_activity'
  | 'paste_activity'
  | 'scroll_velocity'
  | 'navigation_burst'
  | 'export_intent'
  | 'mouse_absence_factor';

export interface FeatureValues {
  eventRate: number;
  intervalCv: number;
  repetitionRatio: number;
  copyCutPerMin: number;
  pastePerMin: number;
  scrollEventsPerMin: number;
  scrollDistancePerMin: number;
  navigationPerMin: number;
  exportPerMin: number;
  mouseMoves: number;
  keyboardAndClicks: number;
  mouseAbsenceRatio: number;
}

export interface NormalizedFeatures {
  event_rate: number;
  interval_regularity: number;
  repetition_ratio: number;
  copy_activity: number;
  paste_activity: number;
  scroll_velocity: number;
  navigation_burst: number;
  export_intent: number;
  mouse_absence_factor?: number;
}

export interface NormalizationRange {
  a: number;
  b: number;
}

export interface NormalizationConfig {
  event_rate: NormalizationRange;
  interval_regularity: NormalizationRange;
  repetition_ratio: NormalizationRange;
  copy_activity: NormalizationRange;
  paste_activity: NormalizationRange;
  scroll_events_per_min: NormalizationRange;
  scroll_distance_per_min: NormalizationRange;
  navigation_burst: NormalizationRange;
  export_intent: NormalizationRange;
  mouse_absence_factor: NormalizationRange;
}

export interface DetectorWeights {
  event_rate: number;
  interval_regularity: number;
  repetition_ratio: number;
  copy_activity: number;
  paste_activity: number;
  scroll_velocity: number;
  navigation_burst: number;
  export_intent: number;
  mouse_absence_factor?: number;
}

export interface DetectorThresholds {
  warn: number;
  incident: number;
  reason: number;
}

export interface DetectorConfig {
  windowSeconds: number;
  emaAlpha: number;
  weights: DetectorWeights;
  normalization: NormalizationConfig;
  thresholds: DetectorThresholds;
  topSignalCount: number;
}

export interface Counters {
  totalEvents: number;
  byType: Record<EventType, number>;
  windowSeconds: number;
}

export interface TopSignal {
  feature: FeatureId;
  contribution: number;
  weight: number;
  value: number;
  normalized: number;
}

export interface DetectionResult {
  ts: number;
  risk: number;
  scoreRaw: number;
  ema: number;
  features: FeatureValues;
  normalized: NormalizedFeatures;
  topSignals: TopSignal[];
  reasonCodes: string[];
  counters: Counters;
}
