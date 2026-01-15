import { buildServer } from './server';
import { serverConfig } from './config';

const app = buildServer();

app
  .listen({ port: serverConfig.port, host: '0.0.0.0' })
  .then(() => {
    // eslint-disable-next-line no-console
    console.log(`WebGuard server listening on ${serverConfig.port}`);
  })
  .catch((error) => {
    // eslint-disable-next-line no-console
    console.error('Failed to start server', error);
    process.exit(1);
  });

const shutdown = async () => {
  await app.close();
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
