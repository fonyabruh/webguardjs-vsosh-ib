import { createWebDetector } from '@webguard/detector-web';

const runtime = window as Window & {
  WEBGUARD_ENDPOINT?: string;
  WEBGUARD_API_KEY?: string;
};

const endpoint = runtime.WEBGUARD_ENDPOINT || 'http://localhost:3000/api/v1/incidents';
const apiKey = runtime.WEBGUARD_API_KEY || 'changeme';

const riskValue = document.getElementById('risk-value') as HTMLDivElement;
const riskStatus = document.getElementById('risk-status') as HTMLDivElement;
const topSignals = document.getElementById('top-signals') as HTMLDivElement;

let lastIncidentSentAt = 0;

const detector = createWebDetector(
  {
    endpoint,
    apiKey
  },
  {
    onUpdate: (result) => {
      riskValue.textContent = result.risk.toFixed(2);
      const now = Date.now();
      const incidentRecentlySent = now - lastIncidentSentAt < 10_000;

      if (incidentRecentlySent) {
        riskStatus.textContent = 'INCIDENT_SENT';
        riskStatus.className = 'status incident';
      } else if (result.risk >= 0.85) {
        riskStatus.textContent = 'INCIDENT';
        riskStatus.className = 'status incident';
      } else if (result.risk >= 0.7) {
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
  for (let i = 0; i < 12; i += 1) {
    const event = new Event('copy', { bubbles: true, cancelable: true });
    selectionTarget.dispatchEvent(event);
  }
});

simulateClicks.addEventListener('click', () => {
  const button = document.getElementById('normal-button') as HTMLButtonElement;
  let count = 0;
  const interval = window.setInterval(() => {
    button.click();
    count += 1;
    if (count >= 20) window.clearInterval(interval);
  }, 150);
});

simulateNav.addEventListener('click', () => {
  for (let i = 0; i < 12; i += 1) {
    history.pushState({}, '', `#nav-${Date.now()}-${i}`);
  }
});

simulateExport.addEventListener('click', () => {
  if (window.print) {
    window.print();
  }
});

simulateDownload.addEventListener('click', (event) => {
  event.preventDefault();
  const link = document.createElement('a');
  link.download = 'export.txt';
  link.href = `data:text/plain,export-${Date.now()}`;
  link.style.position = 'absolute';
  link.style.left = '-9999px';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
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
