/**
 * TRAPSHIELD Backend API Integration Tests
 * 
 * Verifies health endpoints, database status reporting,
 * request validation, security boundaries, and scan processing.
 */

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { app } from '../../server/src/app.js';
import { disconnectDatabase } from '../../server/src/config/db.js';

let server;
let baseUrl;

before(async () => {
  // Bind to an ephemeral port (0) for reliable parallel testing
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
  await new Promise((resolve) => server.close(resolve));
  await disconnectDatabase();
});

test('Backend Foundation - Root Service Ping', async () => {
  const res = await fetch(`${baseUrl}/`);
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.status, 'operational');
  assert.equal(body.name, 'TRAPSHIELD Detection API');
});

test('Backend Foundation - Health Check Endpoint returns accurate DB status', async () => {
  const res = await fetch(`${baseUrl}/api/v1/health`);
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.success, true);
  assert.ok(typeof body.data.uptimeSeconds === 'number');
  assert.ok(body.data.environment);

  // ACCURACY CHECK: MongoDB is not running on this host, so it MUST NOT report connected
  assert.equal(body.data.database.connected, false);
  assert.match(body.data.database.state, /disconnected|degraded|connecting/);
  assert.equal(body.data.status, 'degraded');
});

test('Backend Foundation - 404 Handler on undefined route', async () => {
  const res = await fetch(`${baseUrl}/api/v1/nonexistent-route`);
  const body = await res.json();

  assert.equal(res.status, 404);
  assert.equal(body.success, false);
  assert.equal(body.errorCode, 'ROUTE_NOT_FOUND');
  // No stack trace in response
  assert.equal(body.stack, undefined);
});

test('Backend Foundation - Scan validation rejects missing analysis type', async () => {
  const res = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input: 'Suspicious text here' }),
  });
  const body = await res.json();

  assert.equal(res.status, 400);
  assert.equal(body.success, false);
  assert.equal(body.errorCode, 'INVALID_ANALYSIS_TYPE');
});

test('Backend Foundation - Scan validation rejects invalid analysis type', async () => {
  const res = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'INVALID_TYPE', input: 'Suspicious text here' }),
  });
  const body = await res.json();

  assert.equal(res.status, 400);
  assert.equal(body.success, false);
  assert.equal(body.errorCode, 'INVALID_ANALYSIS_TYPE');
});

test('Backend Foundation - Scan validation rejects empty input', async () => {
  const res = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'MESSAGE', input: '   ' }),
  });
  const body = await res.json();

  assert.equal(res.status, 400);
  assert.equal(body.success, false);
  assert.equal(body.errorCode, 'EMPTY_INPUT');
});

test('Backend Foundation - Scan validation rejects oversized payload (>50KB)', async () => {
  const hugeString = 'A'.repeat(55000);
  const res = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'MESSAGE', input: hugeString }),
  });
  const body = await res.json();

  assert.equal(res.status, 413);
  assert.equal(body.success, false);
  assert.equal(body.errorCode, 'PAYLOAD_TOO_LARGE');
});

test('Backend Foundation - POST /api/v1/scan successfully analyzes suspicious message', async () => {
  const phishingMessage = 'URGENT: Your bank account will be blocked today due to KYC verification. Contact officer on WhatsApp.';
  const res = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'MESSAGE', input: phishingMessage }),
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.success, true);
  assert.ok(body.data);
  assert.ok(typeof body.data.riskScore === 'number');
  assert.ok(body.data.riskScore > 0);
  assert.ok(body.data.riskClassification);
  assert.ok(Array.isArray(body.data.detectedIndicators));
  assert.ok(body.data.detectedIndicators.length > 0);
  assert.equal(body.meta.analysisType, 'MESSAGE');
});

test('Backend Foundation - POST /api/v1/scan successfully analyzes suspicious URL', async () => {
  const suspiciousUrl = 'http://192.168.1.105/login-portal';
  const res = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'URL', input: suspiciousUrl }),
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.success, true);
  assert.ok(body.data.riskScore >= 40);
  assert.ok(body.data.detectedIndicators.some(i => i.id === 'URL_IP_ADDRESS_HOST'));
});

test('Backend Foundation - POST /api/v1/scan successfully analyzes fraudulent job offer', async () => {
  const jobScam = 'Congratulations! You are selected for Data Entry Specialist. Please pay a refundable security deposit of ₹2,500 to initiate laptop dispatch.';
  const res = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'JOB_OFFER', input: jobScam }),
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.success, true);
  assert.ok(body.data.riskScore >= 40);
  assert.ok(body.data.detectedIndicators.some(i => i.id === 'JOB_UPFRONT_FEE_OR_SECURITY_DEPOSIT'));
});
