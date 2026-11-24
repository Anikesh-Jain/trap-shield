/**
 * TRAPSHIELD Server Entry Point
 */

import http from 'node:http';
import { app } from './app.js';
import { env } from './config/env.js';
import { connectDatabase, disconnectDatabase } from './config/db.js';
import { logger } from './utils/logger.js';

async function startServer() {
  logger.info('Starting TRAPSHIELD backend server...', {
    env: env.NODE_ENV,
    port: env.PORT,
    clientOrigin: env.CLIENT_ORIGIN,
    allowedOrigins: env.CLIENT_ORIGINS,
  });

  // Attempt database connection (gracefully degrades to stateless mode on failure)
  await connectDatabase();

  const server = http.createServer(app);

  server.listen(env.PORT, () => {
    logger.info(`TRAPSHIELD API server listening on http://localhost:${env.PORT}`);
    logger.info(`Health check available at http://localhost:${env.PORT}/api/v1/health`);
  });

  // Graceful shutdown handlers
  async function gracefulShutdown(signal) {
    logger.info(`Received ${signal}. Shutting down gracefully...`);
    server.close(async () => {
      logger.info('HTTP server closed.');
      await disconnectDatabase();
      process.exit(0);
    });

    // Force shutdown if cleanup hangs
    setTimeout(() => {
      logger.error('Graceful shutdown timed out. Forcing process termination.');
      process.exit(1);
    }, 10000).unref();
  }

  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

  return server;
}

// Only start when invoked directly as the main process
startServer().catch((err) => {
  logger.error('Failed to initialize TRAPSHIELD backend', err);
  process.exit(1);
});

