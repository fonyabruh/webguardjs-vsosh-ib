import { IncidentFilters } from './queries';

export type IncidentRow = {
  id: string;
  ts: string;
  session_id: string;
  page_id: string;
  risk: number;
  top_signals: unknown;
  features: unknown;
  counters: unknown;
  user_agent: string;
  created_at: string;
};

export function renderDashboard(incidents: IncidentRow[], filters: IncidentFilters): string {
  const rows = incidents
    .map((row) => {
      return `
        <tr class="incident-row">
          <td>${escapeHtml(String(row.ts))}</td>
          <td>${escapeHtml(String(row.session_id))}</td>
          <td>${escapeHtml(String(row.page_id))}</td>
          <td>${row.risk.toFixed(3)}</td>
          <td>${escapeHtml(String(row.user_agent))}</td>
        </tr>
        <tr class="detail-row">
          <td colspan="5">
            ${renderDetails(row)}
          </td>
        </tr>
      `;
    })
    .join('');

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>WebGuard Incidents</title>
        <style>
          @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;600&display=swap');

          body {
            font-family: "IBM Plex Sans", system-ui, -apple-system, sans-serif;
            margin: 24px;
            color: #1f2933;
            background: #f5f7fa;
          }
          h1 {
            margin-bottom: 16px;
          }
          form {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
            padding: 16px;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 6px 20px rgba(31, 41, 51, 0.08);
          }
          label {
            display: flex;
            flex-direction: column;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            gap: 6px;
            color: #52606d;
          }
          input {
            padding: 8px 10px;
            border-radius: 8px;
            border: 1px solid #cbd2d9;
            font-size: 14px;
          }
          button {
            padding: 10px 12px;
            border: none;
            border-radius: 10px;
            background: #2563eb;
            color: #ffffff;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 6px 20px rgba(31, 41, 51, 0.08);
          }
          th, td {
            padding: 12px 14px;
            border-bottom: 1px solid #e4e7eb;
            text-align: left;
            vertical-align: top;
            font-size: 13px;
          }
          th {
            background: #f0f4f8;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
          }
          pre {
            white-space: pre-wrap;
            word-break: break-word;
            background: #f8f9fb;
            padding: 10px;
            border-radius: 8px;
            font-size: 12px;
          }
          .detail-row td {
            padding: 0 14px 18px;
            background: #f7f9fb;
          }
          details {
            width: 100%;
          }
          details summary {
            cursor: pointer;
            font-weight: 600;
            padding: 12px 14px;
            background: #ffffff;
            border: 1px solid #e4e7eb;
            border-radius: 10px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            width: 100%;
          }
          details[open] summary {
            margin-bottom: 10px;
          }
          .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
          }
          .detail-card {
            background: #f8f9fb;
            border: 1px solid #e4e7eb;
            border-radius: 10px;
            padding: 10px;
          }
          .detail-card h4 {
            margin: 0 0 8px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #52606d;
          }
          .detail-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
          }
          .detail-table td {
            padding: 4px 0;
            border-bottom: 1px dashed #d6dde3;
          }
          .detail-table tr:last-child td {
            border-bottom: none;
          }
          .detail-list {
            margin: 0;
            padding-left: 16px;
          }
          .detail-list li {
            margin-bottom: 6px;
            font-size: 12px;
          }
          .detail-chip {
            display: inline-flex;
            align-items: center;
            padding: 4px 8px;
            margin: 0 6px 6px 0;
            border-radius: 999px;
            background: #e6f0ff;
            color: #1d4ed8;
            font-size: 11px;
            font-weight: 600;
          }
          .detail-empty {
            font-size: 12px;
            color: #9aa5b1;
          }
        </style>
      </head>
      <body>
        <h1>WebGuard Incidents</h1>
        <form method="get" action="/dashboard">
          <label>
            Min Risk
            <input name="minRisk" type="number" step="0.01" value="${filters.minRisk ?? ''}" />
          </label>
          <label>
            From (ISO or ms)
            <input name="from" type="text" value="${filters.from?.toISOString() ?? ''}" />
          </label>
          <label>
            To (ISO or ms)
            <input name="to" type="text" value="${filters.to?.toISOString() ?? ''}" />
          </label>
          <label>
            Page ID
            <input name="pageId" type="text" value="${filters.pageId ?? ''}" />
          </label>
          <label>
            Session ID
            <input name="sessionId" type="text" value="${filters.sessionId ?? ''}" />
          </label>
          <label>
            Limit
            <input name="limit" type="number" value="${filters.limit}" />
          </label>
          <label>
            Offset
            <input name="offset" type="number" value="${filters.offset}" />
          </label>
          <button type="submit">Apply Filters</button>
        </form>
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Session</th>
              <th>Page</th>
              <th>Risk</th>
              <th>User Agent</th>
            </tr>
          </thead>
          <tbody>
            ${rows || '<tr><td colspan="5">No incidents yet.</td></tr>'}
          </tbody>
        </table>
      </body>
    </html>
  `;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderDetails(row: IncidentRow): string {
  const topSignals = asArray(parseJson(row.top_signals));
  const features = asRecord(parseJson(row.features));
  const counters = asRecord(parseJson(row.counters));
  const serverFeatures = asRecord(features.server);
  const serverSnapshot = asRecord(serverFeatures.snapshot);
  const serverReasons = asArray(serverFeatures.reasons);
  const featureValues = asRecord(features.values);
  const featureNormalized = asRecord(features.normalized);
  const reasonCodes = asArray(features.reasonCodes);
  const countersSummary: Record<string, unknown> = {
    totalEvents: counters.totalEvents,
    windowSeconds: counters.windowSeconds
  };
  const countersByType = asRecord(counters.byType);
  const riskClient = asFiniteNumber(serverFeatures.riskClient);
  const riskServer = asFiniteNumber(serverFeatures.riskServer);
  const scoreSummary: Record<string, unknown> = {
    riskTotal: row.risk,
    riskClient: riskClient ?? row.risk,
    riskServer,
    scoreRaw: features.scoreRaw,
    ema: features.ema
  };

  const detailGrid = `
    <div class="detail-grid">
      ${renderCard('Summary', renderKeyValueTable(scoreSummary))}
      ${renderCard('Top signals', renderTopSignals(topSignals))}
      ${renderCard('Reason codes', renderReasonCodes(reasonCodes))}
      ${renderCard('Feature values', renderKeyValueTable(featureValues))}
      ${renderCard('Normalized', renderKeyValueTable(featureNormalized))}
      ${renderCard('Counters', renderKeyValueTable(countersSummary))}
      ${renderCard('Events by type', renderKeyValueTable(countersByType))}
      ${renderCard('Server signals', renderServerSignals(serverSnapshot, serverReasons))}
    </div>
  `;

  return `
    <details class="detail-block">
      <summary>Details</summary>
      ${detailGrid}
    </details>
  `;
}

function renderCard(title: string, content: string): string {
  return `
    <div class="detail-card">
      <h4>${escapeHtml(title)}</h4>
      ${content}
    </div>
  `;
}

function renderTopSignals(signals: unknown[]): string {
  if (signals.length === 0) return '<div class="detail-empty">No data</div>';
  const items = signals
    .map((signal) => {
      const signalObj = asRecord(signal);
      const feature = escapeHtml(String(signalObj.feature ?? 'unknown'));
      const normalized = formatValue(signalObj.normalized);
      const weight = formatValue(signalObj.weight);
      const contribution = formatValue(signalObj.contribution);
      return `<li><strong>${feature}</strong> · n=${normalized} · w=${weight} · c=${contribution}</li>`;
    })
    .join('');
  return `<ol class="detail-list">${items}</ol>`;
}

function renderReasonCodes(codes: unknown[]): string {
  if (codes.length === 0) return '<div class="detail-empty">No data</div>';
  const items = codes
    .map((code) => `<span class="detail-chip">${escapeHtml(String(code))}</span>`)
    .join('');
  return items;
}

function renderKeyValueTable(data: Record<string, unknown>): string {
  const entries = Object.entries(data).filter(([, value]) => value !== undefined);
  if (entries.length === 0) return '<div class="detail-empty">No data</div>';
  const rows = entries
    .map(([key, value]) => {
      return `
        <tr>
          <td>${escapeHtml(key)}</td>
          <td>${escapeHtml(formatValue(value))}</td>
        </tr>
      `;
    })
    .join('');
  return `<table class="detail-table">${rows}</table>`;
}

function parseJson(value: unknown): unknown {
  if (typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }
  return value;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '-';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return '-';
    return Number.isInteger(value) ? value.toString() : value.toFixed(3);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  return String(value);
}

function renderServerSignals(snapshot: Record<string, unknown>, reasons: unknown[]): string {
  const fields: Record<string, unknown> = {
    rps60: snapshot.rps60,
    burst5s: snapshot.burst5s,
    cvInterArrival: snapshot.cvInterArrival,
    uniquePathRatio: snapshot.uniquePathRatio,
    errorRatio: snapshot.errorRatio,
    telemetryAgeSec: snapshot.telemetryAgeSec,
    browserHeadersScore: snapshot.browserHeadersScore
  };

  return `
    ${renderKeyValueTable(fields)}
    <div style="margin-top:8px">${renderReasonCodes(reasons)}</div>
  `;
}

function asFiniteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}
