import { describe, expect, it } from 'vitest';
import { computeFeatureValues } from '../features';
import { DetectorEvent } from '../types';

const baseTs = 1_000_000;

function event(
  offsetMs: number,
  type: DetectorEvent['type'],
  data: Partial<DetectorEvent> = {},
): DetectorEvent {
  return {
    ts: baseTs + offsetMs,
    type,
    ...data
  };
}

describe('feature extraction', () => {
  it('computes event rate, repetition ratio, and interval regularity', () => {
    const events = Array.from({ length: 60 }, (_, i) => event(i * 1000, 'click'));
    const features = computeFeatureValues(events, 60);

    expect(features.eventRate).toBe(60);
    expect(features.repetitionRatio).toBe(1);
    expect(features.intervalCv).toBeCloseTo(0);
  });

  it('computes copy and paste activity per minute', () => {
    const events = [
      event(0, 'copy'),
      event(1000, 'copy'),
      event(2000, 'copy'),
      event(3000, 'cut'),
      event(4000, 'paste'),
      event(5000, 'paste'),
      event(6000, 'paste'),
      event(7000, 'paste'),
      event(8000, 'paste')
    ];
    const features = computeFeatureValues(events, 60);

    expect(features.copyCutPerMin).toBe(4);
    expect(features.pastePerMin).toBe(5);
  });

  it('computes scroll velocity metrics', () => {
    const events = [
      event(0, 'scroll', { scrollDeltaY: 100 }),
      event(1000, 'scroll', { scrollDeltaY: -50 }),
      event(2000, 'scroll', { scrollDeltaY: 150 })
    ];
    const features = computeFeatureValues(events, 60);

    expect(features.scrollEventsPerMin).toBe(3);
    expect(features.scrollDistancePerMin).toBe(300);
  });

  it('computes navigation, export, and mouse absence factor', () => {
    const events = [
      event(0, 'navigation'),
      event(1000, 'navigation'),
      event(2000, 'export'),
      event(3000, 'click'),
      event(4000, 'click'),
      event(5000, 'keydown'),
      event(6000, 'input'),
      event(7000, 'mousemove')
    ];
    const features = computeFeatureValues(events, 60);

    expect(features.navigationPerMin).toBe(2);
    expect(features.exportPerMin).toBe(1);
    expect(features.mouseMoves).toBe(1);
    expect(features.keyboardAndClicks).toBe(4);
    expect(features.mouseAbsenceRatio).toBe(4);
  });
});
