import {
  DetectorConfig,
  DetectorEvent,
  DetectionResult,
  defaultDetectorConfig,
  evaluateEvents,
  filterEventsByWindow
} from '@webguard/detector-core';

export interface IncidentPayload {
  ts: number;
  sessionId: string;
  pageId: string;
  risk: number;
  topSignals: DetectionResult['topSignals'];
  features: {
    values: DetectionResult['features'];
    normalized: DetectionResult['normalized'];
    reasonCodes: DetectionResult['reasonCodes'];
    scoreRaw: number;
    ema: number;
  };
  counters: DetectionResult['counters'];
  userAgent: string;
}

export interface WebDetectorConfig {
  endpoint: string;
  apiKey: string;
  pageId?: string;
  sessionId?: string;
  cooldownMs?: number;
  tickMs?: number;
  detectorConfig?: DetectorConfig;
}

export interface WebDetectorCallbacks {
  onUpdate?: (result: DetectionResult) => void;
  onIncidentSent?: (payload: IncidentPayload) => void;
  onIncidentQueued?: (payload: IncidentPayload) => void;
}

const QUEUE_KEY = 'webguardjs:incidentQueue';
const RETRY_DELAYS = [1000, 3000, 10000];

export function createWebDetector(config: WebDetectorConfig, callbacks: WebDetectorCallbacks = {}) {
  const detectorConfig = config.detectorConfig || defaultDetectorConfig;
  const tickMs = config.tickMs ?? 1000;
  const cooldownMs = config.cooldownMs ?? 30_000;
  const events: DetectorEvent[] = [];
  let emaValue: number | null = null;
  let lastIncidentAt = 0;
  let lastSignature = '';
  let timer: number | null = null;
  let stopped = false;

  const sessionId = config.sessionId || getSessionId();
  const pageId = config.pageId || hashString(window.location.pathname || '/');

  function capture(event: DetectorEvent): void {
    events.push(event);
  }

  function tick(): void {
    const now = Date.now();
    const windowed = filterEventsByWindow(events, now, detectorConfig.windowSeconds);
    events.length = 0;
    events.push(...windowed);

    const result = evaluateEvents(events, now, emaValue, detectorConfig);
    emaValue = result.ema;
    callbacks.onUpdate?.(result);

    if (result.risk >= detectorConfig.thresholds.incident) {
      const signature = buildSignature(result);
      if (now - lastIncidentAt >= cooldownMs || signature !== lastSignature) {
        lastIncidentAt = now;
        lastSignature = signature;
        void sendIncident(result);
      }
    }
  }

  async function sendIncident(result: DetectionResult): Promise<void> {
    const payload: IncidentPayload = {
      ts: result.ts,
      sessionId,
      pageId,
      risk: result.risk,
      topSignals: result.topSignals,
      features: {
        values: result.features,
        normalized: result.normalized,
        reasonCodes: result.reasonCodes,
        scoreRaw: result.scoreRaw,
        ema: result.ema
      },
      counters: result.counters,
      userAgent: navigator.userAgent
    };

    if (!navigator.onLine) {
      enqueue(payload);
      callbacks.onIncidentQueued?.(payload);
      return;
    }

    try {
      await postWithRetry(payload, config.endpoint, config.apiKey);
      callbacks.onIncidentSent?.(payload);
    } catch {
      enqueue(payload);
      callbacks.onIncidentQueued?.(payload);
    }
  }

  function start(): void {
    if (timer !== null) return;
    stopped = false;
    timer = window.setInterval(tick, tickMs);
    attachListeners(capture);
    void flushQueue(config.endpoint, config.apiKey, callbacks.onIncidentSent);
    window.addEventListener('online', handleOnline);
  }

  function stop(): void {
    stopped = true;
    if (timer !== null) {
      window.clearInterval(timer);
      timer = null;
    }
    detachListeners();
    window.removeEventListener('online', handleOnline);
  }

  async function handleOnline(): Promise<void> {
    if (stopped) return;
    await flushQueue(config.endpoint, config.apiKey, callbacks.onIncidentSent);
  }

  return {
    start,
    stop,
    getState: () => ({
      sessionId,
      pageId,
      emaValue
    })
  };
}

async function postWithRetry(
  payload: IncidentPayload,
  endpoint: string,
  apiKey: string,
): Promise<void> {
  let attempt = 0;
  let lastError: unknown;

  while (attempt <= RETRY_DELAYS.length) {
    if (attempt > 0) {
      const delayMs = RETRY_DELAYS[attempt - 1];
      await delay(delayMs);
    }

    try {
      await postIncident(payload, endpoint, apiKey);
      return;
    } catch (error) {
      lastError = error;
    }

    attempt += 1;
  }

  throw lastError;
}

async function postIncident(
  payload: IncidentPayload,
  endpoint: string,
  apiKey: string,
): Promise<void> {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'X-API-Key': apiKey
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(`Incident post failed: ${response.status}`);
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function enqueue(payload: IncidentPayload): void {
  const queue = loadQueue();
  queue.push(payload);
  saveQueue(queue);
}

async function flushQueue(
  endpoint: string,
  apiKey: string,
  onSent?: (payload: IncidentPayload) => void,
): Promise<void> {
  if (!navigator.onLine) return;
  const queue = loadQueue();
  if (queue.length === 0) return;

  const remaining: IncidentPayload[] = [];
  for (const payload of queue) {
    try {
      await postIncident(payload, endpoint, apiKey);
      onSent?.(payload);
    } catch {
      remaining.push(payload);
    }
  }

  saveQueue(remaining);
}

function loadQueue(): IncidentPayload[] {
  const raw = localStorage.getItem(QUEUE_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as IncidentPayload[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveQueue(queue: IncidentPayload[]): void {
  localStorage.setItem(QUEUE_KEY, JSON.stringify(queue));
}

type Cleanup = () => void;

let detachListeners: Cleanup = () => {};

function attachListeners(capture: (event: DetectorEvent) => void): void {
  const cleanups: Cleanup[] = [];
  let lastScrollY = window.scrollY;
  let lastMouseMoveAt = 0;

  const onClick = (event: MouseEvent) => {
    const element = event.target instanceof Element ? event.target : null;
    const elementType = getElementType(element);
    capture({ ts: Date.now(), type: 'click', elementType });

    if (element && element.closest('[data-export]')) {
      capture({ ts: Date.now(), type: 'export', elementType, exportKind: 'data-export' });
    }
    if (element && isDownloadLink(element)) {
      capture({ ts: Date.now(), type: 'export', elementType, exportKind: 'download' });
    }
  };

  const onKeydown = (event: KeyboardEvent) => {
    const element = event.target instanceof Element ? event.target : null;
    capture({ ts: Date.now(), type: 'keydown', elementType: getElementType(element) });
  };

  const onInput = (event: Event) => {
    const element = event.target instanceof Element ? event.target : null;
    capture({ ts: Date.now(), type: 'input', elementType: getElementType(element) });
  };

  const onScroll = () => {
    const currentY = window.scrollY;
    const delta = currentY - lastScrollY;
    lastScrollY = currentY;
    capture({ ts: Date.now(), type: 'scroll', scrollDeltaY: delta });
  };

  const onCopy = (event: ClipboardEvent) => {
    capture({
      ts: Date.now(),
      type: 'copy',
      selectionLength: selectionLength(),
      elementType: getElementType(event.target instanceof Element ? event.target : null)
    });
  };

  const onCut = (event: ClipboardEvent) => {
    capture({
      ts: Date.now(),
      type: 'cut',
      selectionLength: selectionLength(),
      elementType: getElementType(event.target instanceof Element ? event.target : null)
    });
  };

  const onPaste = (event: ClipboardEvent) => {
    capture({
      ts: Date.now(),
      type: 'paste',
      selectionLength: selectionLength(),
      elementType: getElementType(event.target instanceof Element ? event.target : null)
    });
  };

  const onMousemove = () => {
    const now = Date.now();
    if (now - lastMouseMoveAt < 500) return;
    lastMouseMoveAt = now;
    capture({ ts: now, type: 'mousemove' });
  };

  const onPopstate = () => {
    capture({ ts: Date.now(), type: 'navigation', navigationKind: 'popstate' });
  };

  const restoreHistory = patchHistory((kind) => {
    capture({ ts: Date.now(), type: 'navigation', navigationKind: kind });
  });

  const restorePrint = patchPrint(() => {
    capture({ ts: Date.now(), type: 'export', exportKind: 'print' });
  });

  window.addEventListener('click', onClick, true);
  window.addEventListener('keydown', onKeydown, true);
  window.addEventListener('input', onInput, true);
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('copy', onCopy, true);
  window.addEventListener('cut', onCut, true);
  window.addEventListener('paste', onPaste, true);
  window.addEventListener('mousemove', onMousemove, true);
  window.addEventListener('popstate', onPopstate, true);

  cleanups.push(() => window.removeEventListener('click', onClick, true));
  cleanups.push(() => window.removeEventListener('keydown', onKeydown, true));
  cleanups.push(() => window.removeEventListener('input', onInput, true));
  cleanups.push(() => window.removeEventListener('scroll', onScroll));
  cleanups.push(() => window.removeEventListener('copy', onCopy, true));
  cleanups.push(() => window.removeEventListener('cut', onCut, true));
  cleanups.push(() => window.removeEventListener('paste', onPaste, true));
  cleanups.push(() => window.removeEventListener('mousemove', onMousemove, true));
  cleanups.push(() => window.removeEventListener('popstate', onPopstate, true));
  cleanups.push(restoreHistory);
  cleanups.push(restorePrint);

  detachListeners = () => {
    for (const cleanup of cleanups) cleanup();
    detachListeners = () => {};
  };
}

function patchHistory(onNavigate: (kind: 'pushState' | 'replaceState') => void): Cleanup {
  const originalPush = history.pushState;
  const originalReplace = history.replaceState;

  history.pushState = function (...args): void {
    onNavigate('pushState');
    return originalPush.apply(this, args as unknown as [unknown, string, string | URL | null]);
  };

  history.replaceState = function (...args): void {
    onNavigate('replaceState');
    return originalReplace.apply(this, args as unknown as [unknown, string, string | URL | null]);
  };

  return () => {
    history.pushState = originalPush;
    history.replaceState = originalReplace;
  };
}

function patchPrint(onPrint: () => void): Cleanup {
  const originalPrint = window.print?.bind(window);
  window.print = () => {
    onPrint();
    if (originalPrint) {
      originalPrint();
    }
  };

  return () => {
    if (originalPrint) {
      window.print = originalPrint;
    }
  };
}

function selectionLength(): number {
  const selection = document.getSelection();
  return selection ? selection.toString().length : 0;
}

function getElementType(element: Element | null): DetectorEvent['elementType'] {
  if (!element) return 'other';
  const tag = element.tagName.toLowerCase();
  if (tag === 'input') return 'input';
  if (tag === 'textarea') return 'textarea';
  if (tag === 'button') return 'button';
  if (tag === 'a') return 'a';
  if (tag === 'div') return 'div';
  return 'other';
}

function isDownloadLink(element: Element): boolean {
  const link = element.closest('a');
  if (!link) return false;
  return link instanceof HTMLAnchorElement && link.hasAttribute('download');
}

function getSessionId(): string {
  const existing = sessionStorage.getItem('webguardjs:sessionId');
  if (existing) return existing;
  const id = crypto.randomUUID();
  sessionStorage.setItem('webguardjs:sessionId', id);
  return id;
}

function hashString(value: string): string {
  let hash = 2166136261;
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return `p_${(hash >>> 0).toString(16)}`;
}

function buildSignature(result: DetectionResult): string {
  const codes = [...result.reasonCodes].sort().join('|');
  const signals = result.topSignals.map((signal) => signal.feature).join(',');
  return `${codes}:${signals}`;
}
