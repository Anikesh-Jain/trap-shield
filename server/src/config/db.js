/**
 * TRAPSHIELD Database Connection Manager
 * 
 * Manages Mongoose connection lifecycle with graceful degradation,
 * timeout controls, and state reporting.
 */

import mongoose from 'mongoose';
import { env } from './env.js';
import { configureDevelopmentDns } from './dns.js';
import { logger } from '../utils/logger.js';

// Configure development DNS resolver immediately upon module load before any SRV lookups occur
configureDevelopmentDns();

export const DB_STATES = Object.freeze({
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  DEGRADED: 'degraded',
  DISCONNECTING: 'disconnecting',
});

let currentState = DB_STATES.DISCONNECTED;
let lastError = null;

// Map Mongoose readyState numbers to our state string
function mapReadyState(readyState) {
  switch (readyState) {
    case 0: return DB_STATES.DISCONNECTED;
    case 1: return DB_STATES.CONNECTED;
    case 2: return DB_STATES.CONNECTING;
    case 3: return DB_STATES.DISCONNECTING;
    default: return DB_STATES.DISCONNECTED;
  }
}

export function getDatabaseState() {
  const ready = mapReadyState(mongoose.connection.readyState);
  return {
    state: currentState === DB_STATES.DEGRADED && ready !== DB_STATES.CONNECTED ? DB_STATES.DEGRADED : ready,
    isConnected: ready === DB_STATES.CONNECTED,
    lastError: lastError ? { message: lastError.message, timestamp: lastError.timestamp } : null,
  };
}

export function isDatabaseConnected() {
  return mongoose.connection.readyState === 1;
}

export async function connectDatabase() {
  // Ensure DNS resolver is configured in development prior to any Mongoose SRV lookups
  configureDevelopmentDns();

  if (mongoose.connection.readyState === 1) {
    currentState = DB_STATES.CONNECTED;
    return true;
  }

  currentState = DB_STATES.CONNECTING;
  logger.info('Initiating MongoDB connection...', { uri: env.MONGODB_URI.replace(/\/\/([^:]+):([^@]+)@/, '//$1:****@') });

  // Attach event handlers only once
  if (!mongoose.connection._hasTrapshieldListeners) {
    mongoose.connection._hasTrapshieldListeners = true;

    mongoose.connection.on('connected', () => {
      currentState = DB_STATES.CONNECTED;
      lastError = null;
      logger.info('MongoDB connection established successfully');
    });

    mongoose.connection.on('error', (err) => {
      currentState = DB_STATES.DEGRADED;
      lastError = { message: err.message, timestamp: new Date().toISOString() };
      logger.error('MongoDB runtime error encountered', err);
    });

    mongoose.connection.on('disconnected', () => {
      if (currentState !== DB_STATES.DISCONNECTING) {
        currentState = DB_STATES.DEGRADED;
        logger.warn('MongoDB disconnected. Application running in degraded (in-memory/stateless) mode');
      }
    });

    mongoose.connection.on('reconnected', () => {
      currentState = DB_STATES.CONNECTED;
      lastError = null;
      logger.info('MongoDB reconnected successfully');
    });
  }

  try {
    await mongoose.connect(env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 5000,
      autoIndex: !env.IS_PRODUCTION,
    });
    currentState = DB_STATES.CONNECTED;
    lastError = null;
    return true;
  } catch (err) {
    currentState = DB_STATES.DEGRADED;
    lastError = { message: err.message, timestamp: new Date().toISOString() };
    logger.warn('Could not connect to MongoDB. Server will operate in stateless/degraded mode', {
      reason: err.message,
    });
    return false;
  }
}

export async function disconnectDatabase() {
  currentState = DB_STATES.DISCONNECTING;
  try {
    await mongoose.disconnect();
    currentState = DB_STATES.DISCONNECTED;
    logger.info('MongoDB disconnected cleanly');
  } catch (err) {
    logger.error('Error during MongoDB disconnect', err);
  }
}

