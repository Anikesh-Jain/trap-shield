/**
 * TRAPSHIELD Development DNS Resolver Configuration
 *
 * PROBLEM STATEMENT:
 * On certain institutional, campus, or college LAN networks, default local DNS
 * resolvers drop UDP packets or fail recursive DNS SRV record queries, causing
 * Node.js MongoDB Atlas connections (mongodb+srv://) to fail with querySrv ETIMEOUT.
 *
 * SOLUTION:
 * Safely configures Node.js process-level DNS resolver to use Google's Public DNS
 * (8.8.8.8, 8.8.4.4) in development environments prior to Mongoose initiating
 * any MongoDB SRV lookups.
 *
 * SAFETY MANDATES:
 * 1. Development/Non-Production Only: In production (NODE_ENV=production), system
 *    DNS settings are strictly preserved untouched.
 * 2. No OS-level network changes: Configures only the Node.js process via `dns.setServers()`.
 *    Does not touch Windows network adapters or registry.
 * 3. No IPv6 disabling: Leaves system IPv6 and IPv4 stacks fully intact.
 * 4. No URI modifications: Leaves the MongoDB connection URI completely unchanged.
 * 5. No hardcoded credentials: Pure network resolver utility.
 */

import dns from 'node:dns';
import { env } from './env.js';
import { logger } from '../utils/logger.js';

export const GOOGLE_DNS_SERVERS = Object.freeze(['8.8.8.8', '8.8.4.4']);

// Capture initial system DNS servers upon module initialization
let initialSystemServers = null;
try {
  initialSystemServers = dns.getServers();
} catch {
  initialSystemServers = [];
}

let isDnsConfigured = false;

/**
 * Configures Google Public DNS for Node.js in development environments.
 * Strictly no-op in production.
 *
 * @param {object} [options]
 * @param {boolean} [options.force] - Force execution (for testing)
 * @param {string[]} [options.servers] - Custom DNS servers to use
 * @returns {{ applied: boolean, servers: string[], reason?: string }}
 */
export function configureDevelopmentDns(options = {}) {
  const isProd = options.force ? false : env.IS_PRODUCTION;

  // 1. Production Safety Guard: Keep production DNS behavior completely unchanged
  if (isProd) {
    logger.debug('Production environment detected: retaining default system DNS servers');
    return {
      applied: false,
      reason: 'production',
      servers: dns.getServers(),
    };
  }

  // 2. Explicit Opt-out Guard: Allow disabling via environment variable if desired
  if (env.DEV_CUSTOM_DNS === false && !options.force) {
    logger.debug('Development custom DNS disabled via configuration');
    return {
      applied: false,
      reason: 'disabled_by_config',
      servers: dns.getServers(),
    };
  }

  const targetServers = options.servers || env.DEV_DNS_SERVERS || GOOGLE_DNS_SERVERS;

  try {
    dns.setServers(targetServers);
    isDnsConfigured = true;
    logger.info('Development DNS resolver configured with Google Public DNS for MongoDB Atlas SRV resolution', {
      dnsServers: targetServers,
    });

    return {
      applied: true,
      servers: dns.getServers(),
    };
  } catch (err) {
    logger.warn('Failed to configure development DNS servers. Falling back to system default resolver', {
      error: err.message,
    });

    return {
      applied: false,
      reason: 'error',
      error: err.message,
      servers: dns.getServers(),
    };
  }
}

/**
 * Restores initial system DNS servers (primarily for test cleanup)
 */
export function restoreSystemDns() {
  if (initialSystemServers && initialSystemServers.length > 0) {
    try {
      dns.setServers(initialSystemServers);
      isDnsConfigured = false;
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Returns current active DNS servers in the Node.js runtime
 */
export function getActiveDnsServers() {
  return dns.getServers();
}

/**
 * Returns whether development DNS has been configured
 */
export function isDevelopmentDnsActive() {
  return isDnsConfigured;
}
