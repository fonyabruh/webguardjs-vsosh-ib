export interface IncidentFilters {
  minRisk?: number;
  from?: Date;
  to?: Date;
  pageId?: string;
  sessionId?: string;
  limit: number;
  offset: number;
}

export function buildIncidentQuery(filters: IncidentFilters): { sql: string; params: unknown[] } {
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (filters.minRisk !== undefined) {
    params.push(filters.minRisk);
    conditions.push(`risk >= $${params.length}`);
  }

  if (filters.from) {
    params.push(filters.from);
    conditions.push(`ts >= $${params.length}`);
  }

  if (filters.to) {
    params.push(filters.to);
    conditions.push(`ts <= $${params.length}`);
  }

  if (filters.pageId) {
    params.push(filters.pageId);
    conditions.push(`page_id = $${params.length}`);
  }

  if (filters.sessionId) {
    params.push(filters.sessionId);
    conditions.push(`session_id = $${params.length}`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  params.push(filters.limit);
  params.push(filters.offset);

  const sql = `
    SELECT id, ts, session_id, page_id, risk, top_signals, features, counters, user_agent, created_at
    FROM incidents
    ${where}
    ORDER BY ts DESC
    LIMIT $${params.length - 1}
    OFFSET $${params.length}
  `;

  return { sql, params };
}
