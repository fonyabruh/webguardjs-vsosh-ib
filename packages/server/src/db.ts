import { Pool } from 'pg';
import { serverConfig } from './config';

export const pool = new Pool(
  serverConfig.databaseUrl
    ? { connectionString: serverConfig.databaseUrl }
    : {
        host: serverConfig.pg.host,
        user: serverConfig.pg.user,
        password: serverConfig.pg.password,
        database: serverConfig.pg.database,
        port: serverConfig.pg.port
      },
);

export async function query<T = unknown>(text: string, params: unknown[] = []): Promise<T[]> {
  const result = await pool.query(text, params);
  return result.rows as T[];
}
