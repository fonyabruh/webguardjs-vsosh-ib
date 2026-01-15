import { coefficientOfVariation } from './math';
import { Counters, DetectorEvent, EventType, FeatureValues } from './types';

const EVENT_TYPES: EventType[] = [
  'click',
  'keydown',
  'input',
  'scroll',
  'copy',
  'cut',
  'paste',
  'mousemove',
  'navigation',
  'export'
];

const REGULARITY_TYPES: EventType[] = ['click', 'keydown'];

export function filterEventsByWindow(
  events: DetectorEvent[],
  nowMs: number,
  windowSeconds: number,
): DetectorEvent[] {
  const minTs = nowMs - windowSeconds * 1000;
  return events.filter((event) => event.ts >= minTs && event.ts <= nowMs);
}

export function buildCounters(events: DetectorEvent[], windowSeconds: number): Counters {
  const byType = EVENT_TYPES.reduce<Record<EventType, number>>((acc, type) => {
    acc[type] = 0;
    return acc;
  }, {} as Record<EventType, number>);

  for (const event of events) {
    byType[event.type] = (byType[event.type] || 0) + 1;
  }

  return {
    totalEvents: events.length,
    byType,
    windowSeconds
  };
}

export function computeFeatureValues(
  events: DetectorEvent[],
  windowSeconds: number,
): FeatureValues {
  const windowMinutes = windowSeconds / 60;
  const counters = buildCounters(events, windowSeconds);
  const totalEvents = counters.totalEvents;

  const regularityTimes = events
    .filter((event) => REGULARITY_TYPES.includes(event.type))
    .map((event) => event.ts)
    .sort((a, b) => a - b);

  const intervals: number[] = [];
  for (let i = 1; i < regularityTimes.length; i += 1) {
    intervals.push(regularityTimes[i] - regularityTimes[i - 1]);
  }

  const scrollDistance = events.reduce((sum, event) => {
    if (event.type !== 'scroll') return sum;
    return sum + Math.abs(event.scrollDeltaY || 0);
  }, 0);

  const keyboardAndClicks =
    counters.byType.click + counters.byType.keydown + counters.byType.input;

  return {
    eventRate: windowMinutes > 0 ? totalEvents / windowMinutes : 0,
    intervalCv: coefficientOfVariation(intervals),
    repetitionRatio: totalEvents === 0 ? 0 : maxCount(counters) / totalEvents,
    copyCutPerMin:
      windowMinutes > 0
        ? (counters.byType.copy + counters.byType.cut) / windowMinutes
        : 0,
    pastePerMin: windowMinutes > 0 ? counters.byType.paste / windowMinutes : 0,
    scrollEventsPerMin: windowMinutes > 0 ? counters.byType.scroll / windowMinutes : 0,
    scrollDistancePerMin: windowMinutes > 0 ? scrollDistance / windowMinutes : 0,
    navigationPerMin:
      windowMinutes > 0 ? counters.byType.navigation / windowMinutes : 0,
    exportPerMin: windowMinutes > 0 ? counters.byType.export / windowMinutes : 0,
    mouseMoves: counters.byType.mousemove,
    keyboardAndClicks,
    mouseAbsenceRatio: keyboardAndClicks / Math.max(1, counters.byType.mousemove)
  };
}

function maxCount(counters: Counters): number {
  let max = 0;
  for (const type of EVENT_TYPES) {
    const count = counters.byType[type] || 0;
    if (count > max) max = count;
  }
  return max;
}
