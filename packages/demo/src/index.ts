import { createWebDetector, defaultDetectorConfig } from '@webguard/detector-web';

const runtime = window as Window & {
  WEBGUARD_ENDPOINT?: string;
  WEBGUARD_API_KEY?: string;
};

const endpoint = runtime.WEBGUARD_ENDPOINT || 'http://localhost:3000/api/v1/incidents';
const apiKey = runtime.WEBGUARD_API_KEY || 'changeme';

const riskValue = document.getElementById('risk-value') as HTMLDivElement;
const riskStatus = document.getElementById('risk-status') as HTMLDivElement;
const topSignals = document.getElementById('top-signals') as HTMLDivElement;
const normalInput = document.getElementById('normal-input') as HTMLInputElement;
const normalTextarea = document.getElementById('normal-textarea') as HTMLTextAreaElement;

const BURST = {
  clickCount: 140,
  clickIntervalMs: 60,
  keydownCount: 90,
  keydownIntervalMs: 60,
  inputCount: 90,
  inputIntervalMs: 60,
  copyCount: 50,
  cutCount: 20,
  pasteCount: 35,
  clipboardIntervalMs: 50,
  navCount: 50,
  navIntervalMs: 80,
  exportCount: 6,
  exportIntervalMs: 120,
  downloadCount: 4,
  downloadIntervalMs: 150
};

let lastIncidentSentAt = 0;

const demoDetectorConfig = {
  ...defaultDetectorConfig,
  thresholds: {
    ...defaultDetectorConfig.thresholds,
    warn: 0.55,
    incident: 0.62,
    reason: 0.6
  }
};

const detector = createWebDetector(
  {
    endpoint,
    apiKey,
    detectorConfig: demoDetectorConfig
  },
  {
    onUpdate: (result) => {
      riskValue.textContent = result.risk.toFixed(2);
      const now = Date.now();
      const incidentRecentlySent = now - lastIncidentSentAt < 10_000;

      if (incidentRecentlySent) {
        riskStatus.textContent = 'INCIDENT_SENT';
        riskStatus.className = 'status incident';
      } else if (result.risk >= demoDetectorConfig.thresholds.incident) {
        riskStatus.textContent = 'INCIDENT';
        riskStatus.className = 'status incident';
      } else if (result.risk >= demoDetectorConfig.thresholds.warn) {
        riskStatus.textContent = 'WARN';
        riskStatus.className = 'status warn';
      } else {
        riskStatus.textContent = 'OK';
        riskStatus.className = 'status';
      }

      topSignals.innerHTML = '';
      result.topSignals.forEach((signal) => {
        const item = document.createElement('span');
        item.textContent = `${signal.feature}: ${signal.normalized.toFixed(2)}`;
        topSignals.appendChild(item);
      });
    },
    onIncidentSent: () => {
      lastIncidentSentAt = Date.now();
    }
  },
);

detector.start();

const simulateCopy = document.getElementById('simulate-copy') as HTMLButtonElement;
const simulateClicks = document.getElementById('simulate-clicks') as HTMLButtonElement;
const simulateNav = document.getElementById('simulate-nav') as HTMLButtonElement;
const simulateExport = document.getElementById('simulate-export') as HTMLButtonElement;
const simulateDownload = document.getElementById('simulate-download') as HTMLAnchorElement;

simulateCopy.addEventListener('click', () => {
  const selectionTarget = ensureSelectionTarget();
  selectAll(selectionTarget);

  runBurst(BURST.copyCount, BURST.clipboardIntervalMs, () => {
    emitClipboard(selectionTarget, 'copy');
  });
  runBurst(
    BURST.cutCount,
    BURST.clipboardIntervalMs,
    () => emitClipboard(selectionTarget, 'cut'),
    20,
  );
  runBurst(
    BURST.pasteCount,
    BURST.clipboardIntervalMs,
    () => emitClipboard(selectionTarget, 'paste'),
    40,
  );

  runBurst(BURST.keydownCount, BURST.keydownIntervalMs, () => emitKeydown(normalInput), 10);
  runBurst(BURST.inputCount, BURST.inputIntervalMs, () => emitInput(normalInput), 35);
  runBurst(BURST.clickCount / 2, BURST.clickIntervalMs, () => emitClick(normalInput), 20);
});

simulateClicks.addEventListener('click', () => {
  const button = document.getElementById('normal-button') as HTMLButtonElement;
  runBurst(BURST.clickCount, BURST.clickIntervalMs, () => emitClick(button));
  runBurst(
    BURST.keydownCount,
    BURST.keydownIntervalMs,
    () => emitKeydown(normalTextarea),
    BURST.clickIntervalMs / 2,
  );
  runBurst(
    BURST.inputCount,
    BURST.inputIntervalMs,
    () => emitInput(normalTextarea),
    BURST.clickIntervalMs / 2 + 10,
  );
});

simulateNav.addEventListener('click', () => {
  runBurst(BURST.navCount, BURST.navIntervalMs, (index) => {
    history.pushState({}, '', `#nav-${Date.now()}-${index}`);
  });
  runBurst(BURST.clickCount / 2, BURST.clickIntervalMs, () => emitClick(normalInput), 30);
});

simulateExport.addEventListener('click', () => {
  if (window.print) {
    window.print();
  }
  const exportProxy = ensureExportProxy();
  runBurst(BURST.exportCount, BURST.exportIntervalMs, () => emitClick(exportProxy), 60);
});

simulateDownload.addEventListener('click', (event) => {
  event.preventDefault();
  runBurst(BURST.downloadCount, BURST.downloadIntervalMs, () => triggerDownload(), 40);
});

function ensureSelectionTarget(): HTMLDivElement {
  let target = document.getElementById('selection-buffer') as HTMLDivElement | null;
  if (!target) {
    target = document.createElement('div');
    target.id = 'selection-buffer';
    target.textContent = 'webguardjs-selection-buffer-webguardjs-selection-buffer';
    target.style.position = 'absolute';
    target.style.left = '-9999px';
    document.body.appendChild(target);
  }
  return target;
}

function selectAll(element: HTMLElement): void {
  const selection = window.getSelection();
  if (!selection) return;
  selection.removeAllRanges();
  const range = document.createRange();
  range.selectNodeContents(element);
  selection.addRange(range);
}

function runBurst(
  count: number,
  intervalMs: number,
  action: (index: number) => void,
  offsetMs = 0,
): void {
  const start = () => {
    let index = 0;
    const interval = window.setInterval(() => {
      action(index);
      index += 1;
      if (index >= count) {
        window.clearInterval(interval);
      }
    }, intervalMs);
  };

  if (offsetMs > 0) {
    window.setTimeout(start, offsetMs);
  } else {
    start();
  }
}

function emitClick(target: Element): void {
  target.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
}

function emitKeydown(target: Element): void {
  target.dispatchEvent(
    new KeyboardEvent('keydown', { bubbles: true, cancelable: true, key: 'A' }),
  );
}

function emitInput(target: Element): void {
  target.dispatchEvent(new Event('input', { bubbles: true, cancelable: true }));
}

function emitClipboard(
  target: Element,
  type: 'copy' | 'cut' | 'paste',
): void {
  target.dispatchEvent(new Event(type, { bubbles: true, cancelable: true }));
}

let exportProxy: HTMLButtonElement | null = null;
let downloadProxy: HTMLAnchorElement | null = null;

function ensureExportProxy(): HTMLButtonElement {
  if (exportProxy) return exportProxy;
  exportProxy = document.createElement('button');
  exportProxy.type = 'button';
  exportProxy.dataset.export = 'true';
  exportProxy.style.position = 'absolute';
  exportProxy.style.left = '-9999px';
  document.body.appendChild(exportProxy);
  return exportProxy;
}

function ensureDownloadProxy(): HTMLAnchorElement {
  if (downloadProxy) return downloadProxy;
  downloadProxy = document.createElement('a');
  downloadProxy.download = 'export.txt';
  downloadProxy.style.position = 'absolute';
  downloadProxy.style.left = '-9999px';
  document.body.appendChild(downloadProxy);
  return downloadProxy;
}

function triggerDownload(): void {
  const link = ensureDownloadProxy();
  link.href = `data:text/plain,export-${Date.now()}`;
  emitClick(link);
}
