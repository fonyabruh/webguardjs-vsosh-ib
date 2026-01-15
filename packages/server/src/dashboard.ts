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
      const details = escapeHtml(
        JSON.stringify(
          {
            topSignals: row.top_signals,
            features: row.features,
            counters: row.counters
          },
          null,
          2,
        ),
      );

      return `
        <tr>
          <td>${escapeHtml(String(row.ts))}</td>
          <td>${escapeHtml(String(row.session_id))}</td>
          <td>${escapeHtml(String(row.page_id))}</td>
          <td>${row.risk.toFixed(3)}</td>
          <td>${escapeHtml(String(row.user_agent))}</td>
          <td>
            <details>
              <summary>Details</summary>
              <pre>${details}</pre>
            </details>
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
          details summary {
            cursor: pointer;
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
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            ${rows || '<tr><td colspan="6">No incidents yet.</td></tr>'}
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
