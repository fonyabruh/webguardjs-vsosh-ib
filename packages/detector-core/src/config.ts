import { DetectorConfig } from './types';

export const defaultDetectorConfig: DetectorConfig = {
  windowSeconds: 60,
  emaAlpha: 0.35,
  topSignalCount: 3,
  thresholds: {
    warn: 0.7,
    incident: 0.85,
    reason: 0.7
  },
  weights: {
    event_rate: 0.14,
    interval_regularity: 0.18,
    repetition_ratio: 0.1,
    copy_activity: 0.2,
    navigation_burst: 0.12,
    export_intent: 0.12,
    scroll_velocity: 0.07,
    paste_activity: 0.07,
    mouse_absence_factor: 0
  },
  normalization: {
    event_rate: { a: 20, b: 120 },
    interval_regularity: { a: 0.05, b: 0.4 },
    repetition_ratio: { a: 0.3, b: 0.8 },
    copy_activity: { a: 1, b: 6 },
    paste_activity: { a: 1, b: 6 },
    scroll_events_per_min: { a: 5, b: 40 },
    scroll_distance_per_min: { a: 300, b: 4000 },
    navigation_burst: { a: 1, b: 10 },
    export_intent: { a: 1, b: 4 },
    mouse_absence_factor: { a: 3, b: 12 }
  }
};
