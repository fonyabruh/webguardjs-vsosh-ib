export const serverConfig = {
  port: Number(process.env.PORT || 3000),
  apiKey: process.env.API_KEY || 'changeme',
  databaseUrl: process.env.DATABASE_URL || '',
  pg: {
    host: process.env.PGHOST || 'localhost',
    user: process.env.PGUSER || 'webguard',
    password: process.env.PGPASSWORD || 'webguard',
    database: process.env.PGDATABASE || 'webguard',
    port: Number(process.env.PGPORT || 5432)
  },
  rateLimit: {
    windowMs: 60_000,
    max: 120
  }
};
