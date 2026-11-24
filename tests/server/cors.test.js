/**
 * TRAPSHIELD Production CORS Configuration Tests
 *
 * Verifies:
 * 1. Exact environment variable parsing (CLIENT_ORIGIN).
 * 2. Allowing exact production origins:
 *    - https://trap-shield.vercel.app
 *    - https://trap-shield-r0gpwye6f-anixora-tech.vercel.app
 * 3. Preserving localhost:3000 for development only (rejected in production).
 * 4. Correct OPTIONS preflight responses with credentials/cookies support.
 * 5. Strict rejection of wildcards ('*') when credentials are used.
 * 6. Explicit 403 rejection for unauthorized/unrelated origins.
 */

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import { app } from '../../server/src/app.js';
import {
  parseOrigins,
  resolveAllowedOrigins,
  DEFAULT_PRODUCTION_ORIGINS,
} from '../../server/src/config/env.js';
import { getAuthCookieOptions } from '../../server/src/utils/token.js';
import { configureCors } from '../../server/src/middleware/security.js';
import { errorHandler } from '../../server/src/middleware/errorHandler.js';

let server;
let baseUrl;

const PROD_ORIGIN_MAIN = 'https://trap-shield.vercel.app';
const PROD_ORIGIN_PREVIEW = 'https://trap-shield-r0gpwye6f-anixora-tech.vercel.app';
const UNRELATED_ORIGIN = 'https://malicious-attacker.com';

before(async () => {
  await new Promise((resolve) => {
    server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      baseUrl = `http://127.0.0.1:${address.port}`;
      resolve();
    });
  });
});

after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
});

// ----------------------------------------------------
// 1. CONFIGURATION & PARSING UNIT TESTS
// ----------------------------------------------------
test('CORS Config - parseOrigins strips whitespace and trailing slashes', () => {
  const input = ' https://trap-shield.vercel.app/ , https://other-domain.com/// ';
  const result = parseOrigins(input);

  assert.deepEqual(result, [
    'https://trap-shield.vercel.app',
    'https://other-domain.com',
  ]);
});

test('CORS Config - resolveAllowedOrigins in production includes both verified Vercel deployments', () => {
  const prodOrigins = resolveAllowedOrigins('', true);

  assert.ok(prodOrigins.includes(PROD_ORIGIN_MAIN));
  assert.ok(prodOrigins.includes(PROD_ORIGIN_PREVIEW));
  assert.equal(prodOrigins.includes('http://localhost:3000'), false);
});

test('CORS Config - resolveAllowedOrigins in development includes localhost:3000', () => {
  const devOrigins = resolveAllowedOrigins('', false);

  assert.ok(devOrigins.includes('http://localhost:3000'));
});

test('CORS Config - resolveAllowedOrigins merges custom environment origins with production defaults', () => {
  const customInput = 'https://custom-portal.org, https://trap-shield.vercel.app';
  const prodOrigins = resolveAllowedOrigins(customInput, true);

  assert.ok(prodOrigins.includes('https://custom-portal.org'));
  assert.ok(prodOrigins.includes(PROD_ORIGIN_MAIN));
  assert.ok(prodOrigins.includes(PROD_ORIGIN_PREVIEW));
});

// ----------------------------------------------------
// 2. PRODUCTION ORIGIN INTEGRATION TESTS (APP)
// ----------------------------------------------------
test('CORS Preflight - Main production origin (trap-shield.vercel.app) receives valid preflight headers', async () => {
  const res = await fetch(`${baseUrl}/api/v1/health`, {
    method: 'OPTIONS',
    headers: {
      Origin: PROD_ORIGIN_MAIN,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'Content-Type, Authorization',
    },
  });

  assert.equal(res.status, 204);
  assert.equal(res.headers.get('access-control-allow-origin'), PROD_ORIGIN_MAIN);
  assert.equal(res.headers.get('access-control-allow-credentials'), 'true');
  assert.notEqual(res.headers.get('access-control-allow-origin'), '*');

  const allowedMethods = res.headers.get('access-control-allow-methods') || '';
  assert.ok(allowedMethods.includes('GET'));
  assert.ok(allowedMethods.includes('POST'));
  assert.ok(allowedMethods.includes('OPTIONS'));
  assert.ok(allowedMethods.includes('DELETE'));
  assert.ok(allowedMethods.includes('PATCH'));
});

test('CORS Request - Main production origin receives matching allow-origin and credentials', async () => {
  const res = await fetch(`${baseUrl}/api/v1/health`, {
    method: 'GET',
    headers: {
      Origin: PROD_ORIGIN_MAIN,
    },
  });

  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), PROD_ORIGIN_MAIN);
  assert.equal(res.headers.get('access-control-allow-credentials'), 'true');
  assert.notEqual(res.headers.get('access-control-allow-origin'), '*');
});

test('CORS Preflight - Preview production origin receives valid preflight headers', async () => {
  const res = await fetch(`${baseUrl}/api/v1/health`, {
    method: 'OPTIONS',
    headers: {
      Origin: PROD_ORIGIN_PREVIEW,
      'Access-Control-Request-Method': 'GET',
    },
  });

  assert.equal(res.status, 204);
  assert.equal(res.headers.get('access-control-allow-origin'), PROD_ORIGIN_PREVIEW);
  assert.equal(res.headers.get('access-control-allow-credentials'), 'true');
  assert.notEqual(res.headers.get('access-control-allow-origin'), '*');
});

test('CORS Request - Preview production origin receives matching allow-origin and credentials', async () => {
  const res = await fetch(`${baseUrl}/api/v1/health`, {
    method: 'GET',
    headers: {
      Origin: PROD_ORIGIN_PREVIEW,
    },
  });

  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), PROD_ORIGIN_PREVIEW);
  assert.equal(res.headers.get('access-control-allow-credentials'), 'true');
});

test('CORS Security - Unrelated origin is rejected with 403 CORS_FORBIDDEN and no allow-origin', async () => {
  const res = await fetch(`${baseUrl}/api/v1/health`, {
    method: 'GET',
    headers: {
      Origin: UNRELATED_ORIGIN,
    },
  });

  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.success, false);
  assert.equal(body.errorCode, 'CORS_FORBIDDEN');
  assert.equal(res.headers.get('access-control-allow-origin'), null);
});

test('CORS Security - Server-to-server or non-browser requests (no Origin header) succeed', async () => {
  const res = await fetch(`${baseUrl}/api/v1/health`, {
    method: 'GET',
  });

  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.success, true);
});

// ----------------------------------------------------
// 3. PRODUCTION VS DEVELOPMENT ISOLATION TESTS
// ----------------------------------------------------
test('CORS Isolation - Production mode strictly rejects http://localhost:3000', async () => {
  // Test isolated production instance
  const prodApp = express();
  prodApp.use(configureCors({ isProduction: true, allowedOrigins: [...DEFAULT_PRODUCTION_ORIGINS] }));
  prodApp.get('/test', (req, res) => res.json({ ok: true }));
  prodApp.use(errorHandler);

  const prodServer = http.createServer(prodApp);
  await new Promise((resolve) => prodServer.listen(0, '127.0.0.1', resolve));
  const testBaseUrl = `http://127.0.0.1:${prodServer.address().port}`;

  try {
    const res = await fetch(`${testBaseUrl}/test`, {
      method: 'GET',
      headers: { Origin: 'http://localhost:3000' },
    });

    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.errorCode, 'CORS_FORBIDDEN');
    assert.equal(res.headers.get('access-control-allow-origin'), null);
  } finally {
    await new Promise((resolve) => prodServer.close(resolve));
  }
});

test('CORS Isolation - Development mode allows http://localhost:3000', async () => {
  // Test isolated development instance
  const devApp = express();
  devApp.use(configureCors({ isProduction: false, allowedOrigins: ['http://localhost:3000'] }));
  devApp.get('/test', (req, res) => res.json({ ok: true }));
  devApp.use(errorHandler);

  const devServer = http.createServer(devApp);
  await new Promise((resolve) => devServer.listen(0, '127.0.0.1', resolve));
  const testBaseUrl = `http://127.0.0.1:${devServer.address().port}`;

  try {
    const res = await fetch(`${testBaseUrl}/test`, {
      method: 'GET',
      headers: { Origin: 'http://localhost:3000' },
    });

    assert.equal(res.status, 200);
    assert.equal(res.headers.get('access-control-allow-origin'), 'http://localhost:3000');
    assert.equal(res.headers.get('access-control-allow-credentials'), 'true');
  } finally {
    await new Promise((resolve) => devServer.close(resolve));
  }
});

// ----------------------------------------------------
// 4. CROSS-SITE HTTP-ONLY COOKIE ATTRIBUTE TESTS
// ----------------------------------------------------
test('Cookie Security - Production cookie enforces SameSite=None, Secure=true, and Partitioned=true for cross-site auth', () => {
  const options = getAuthCookieOptions({ isProduction: true });

  assert.equal(options.httpOnly, true, 'Auth cookie must be httpOnly');
  assert.equal(options.secure, true, 'Cross-site production cookie requires Secure');
  assert.equal(options.sameSite, 'none', 'Cross-site production cookie requires SameSite=None');
  assert.equal(options.partitioned, true, 'Cross-site production cookie requires Partitioned (CHIPS)');
  assert.equal(options.path, '/', 'Auth cookie must be available across entire application');
});

test('Cookie Security - Development cookie preserves SameSite=Lax and Secure=false for local HTTP', () => {
  const options = getAuthCookieOptions({ isProduction: false });

  assert.equal(options.httpOnly, true);
  assert.equal(options.secure, false, 'Local development does not require HTTPS/Secure');
  assert.equal(options.sameSite, 'lax', 'Local development uses SameSite=Lax');
  assert.equal(options.partitioned, false);
});
