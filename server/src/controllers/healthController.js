/**
 * TRAPSHIELD Health Controller
 * 
 * Reports server uptime, service health, and accurate database connectivity.
 * ACCURACY MANDATE: Never claims database is connected unless physically verified.
 */

import { getDatabaseState } from '../config/db.js';
import { env } from '../config/env.js';
import { successResponse } from '../utils/apiResponse.js';

export function getHealth(req, res) {
  const dbState = getDatabaseState();
  const overallStatus = dbState.isConnected ? 'healthy' : 'degraded';

  const healthData = {
    status: overallStatus,
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    environment: env.NODE_ENV,
    version: '0.1.0',
    database: {
      connected: dbState.isConnected,
      state: dbState.state,
      ...(dbState.lastError ? { error: dbState.lastError.message } : {}),
      note: dbState.isConnected
        ? 'MongoDB operational'
        : 'MongoDB unreachable; operating in stateless/in-memory mode',
    },
  };

  const statusCode = dbState.isConnected ? 200 : 200; // Still 200 so monitoring sees the health status payload
  return successResponse(res, healthData, `TRAPSHIELD API is operational (${overallStatus})`, statusCode);
}

