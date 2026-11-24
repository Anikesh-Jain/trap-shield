/**
 * TRAPSHIELD End-to-End Frontend API Integration Flow Tests
 * 
 * Verifies that the client API methods and contracts invoked by the React frontend:
 * 1. Guest scanning flow: operates without cookies, gets structured result, does not persist in Scan model.
 * 2. User registration & login: sets HTTP-only session cookie and returns user profile.
 * 3. Authenticated scanning flow: attaches cookie, saves to personal history, returns savedScanId.
 * 4. History retrieval & deletion: lists scans, opens single scan, deletes scan.
 * 5. Normal user denial from admin: ensures 403 on all admin routes.
 * 6. Admin oversight: allows viewing user scans, audit logging, and platform stats.
 * 7. Privacy policy retrieval: returns complete transparency disclosures.
 */

process.env.NODE_ENV = 'test';
process.env.AUTH_RATE_LIMIT_MAX = '1000';
process.env.RATE_LIMIT_MAX = '1000';
process.env.SCAN_RATE_LIMIT_MAX = '1000';

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { app } from '../../server/src/app.js';
import { connectDatabase, disconnectDatabase } from '../../server/src/config/db.js';
import { User } from '../../server/src/models/User.js';
import { Scan } from '../../server/src/models/Scan.js';
import { AdminAuditLog } from '../../server/src/models/AdminAuditLog.js';

let server;
let baseUrl;

function getCookie(res) {
  const setCookie = res.headers.get('set-cookie');
  if (!setCookie) return '';
  return setCookie.split(';')[0];
}

const FLOW_USER = {
  email: `flow_user_${Date.now()}@trapshield.test`,
  password: 'FlowPassword123!',
};

const FLOW_ADMIN = {
  email: `flow_admin_${Date.now()}@trapshield.test`,
  password: 'FlowAdminPassword2026!',
};

let userCookie = '';
let adminCookie = '';
let savedScanId = '';
let flowUserId = '';

before(async () => {
  await connectDatabase();

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
  try {
    const emails = [FLOW_USER.email, FLOW_ADMIN.email];
    const users = await User.find({ email: { $in: emails } });
    const userIds = users.map(u => u._id);
    await Scan.deleteMany({ userId: { $in: userIds } });
    await AdminAuditLog.deleteMany({ adminEmail: FLOW_ADMIN.email });
    await User.deleteMany({ email: { $in: emails } });
  } catch {
    // Ignore cleanup errors
  }
  await disconnectDatabase();
});

test('E2E Flow 1: Guest Scan without registration or cookies', async () => {
  const guestPayload = {
    type: 'MESSAGE',
    input: 'URGENT: Your SBI account is blocked. Verify KYC on WhatsApp immediately.',
  };

  const res = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(guestPayload),
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.success, true);
  assert.ok(body.data.riskScore > 0);
  assert.equal(body.data.savedScanId, undefined, 'Guest scan must not return a savedScanId');

  // Verify that nothing was stored in Scan collection for guest
  const stored = await Scan.findOne({ submittedContent: guestPayload.input });
  assert.equal(stored, null, 'Guest scan payload must not be stored in Scan collection');
});

test('E2E Flow 2: User Registration and Session Cookie Acquisition', async () => {
  const res = await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(FLOW_USER),
  });
  const body = await res.json();

  assert.equal(res.status, 201);
  assert.equal(body.success, true);
  assert.equal(body.data.user.email, FLOW_USER.email);
  assert.equal(body.data.user.role, 'user');
  flowUserId = body.data.user.id;

  userCookie = getCookie(res);
  assert.ok(userCookie.includes('trapshield_token='));
});

test('E2E Flow 3: Current User Session Restoration (GET /api/v1/auth/me)', async () => {
  const res = await fetch(`${baseUrl}/api/v1/auth/me`, {
    headers: { Cookie: userCookie },
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.data.user.email, FLOW_USER.email);
});

test('E2E Flow 4: Authenticated Scan Execution with Automatic Archive Persistence', async () => {
  const userPayload = {
    type: 'JOB_OFFER',
    input: 'Congratulations! You are selected. Pay ₹2,500 registration deposit for laptop delivery.',
  };

  const res = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: userCookie,
    },
    body: JSON.stringify(userPayload),
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.success, true);
  assert.ok(body.data.savedScanId, 'Authenticated scan must produce a savedScanId');
  savedScanId = body.data.savedScanId;

  // Confirm saved in Scan collection under this user's ID
  const savedDoc = await Scan.findById(savedScanId);
  assert.ok(savedDoc);
  assert.equal(savedDoc.userId.toString(), flowUserId);
  assert.equal(savedDoc.submittedContent, userPayload.input);
});

test('E2E Flow 5: Scan History Listing and Individual Deletion', async () => {
  // 1. List History
  const historyRes = await fetch(`${baseUrl}/api/v1/scan/history?page=1&limit=10`, {
    headers: { Cookie: userCookie },
  });
  const historyBody = await historyRes.json();

  assert.equal(historyRes.status, 200);
  assert.ok(Array.isArray(historyBody.data.scans));
  assert.ok(historyBody.data.scans.some(s => s.id === savedScanId));

  // 2. Open Single Scan
  const singleRes = await fetch(`${baseUrl}/api/v1/scan/history/${savedScanId}`, {
    headers: { Cookie: userCookie },
  });
  const singleBody = await singleRes.json();

  assert.equal(singleRes.status, 200);
  assert.equal(singleBody.data.id, savedScanId);

  // 3. Delete Scan
  const deleteRes = await fetch(`${baseUrl}/api/v1/scan/history/${savedScanId}`, {
    method: 'DELETE',
    headers: { Cookie: userCookie },
  });
  assert.equal(deleteRes.status, 200);

  // 4. Verify scan is no longer in database
  const deletedDoc = await Scan.findById(savedScanId);
  assert.equal(deletedDoc, null);
});

test('E2E Flow 6: Normal User Access Denied to Admin APIs (403)', async () => {
  const routes = [
    `${baseUrl}/api/v1/admin/users`,
    `${baseUrl}/api/v1/admin/stats`,
    `${baseUrl}/api/v1/admin/audit-logs`,
  ];

  for (const url of routes) {
    const res = await fetch(url, {
      headers: { Cookie: userCookie },
    });
    assert.equal(res.status, 403, `Expected 403 on ${url} for regular user`);
  }
});

test('E2E Flow 7: Administrator Access and Oversight Workflow', async () => {
  // Create admin user
  const passwordHash = await User.hashPassword(FLOW_ADMIN.password);
  await User.create({
    email: FLOW_ADMIN.email,
    passwordHash,
    role: 'admin',
    isActive: true,
  });

  // Log in as Admin
  const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(FLOW_ADMIN),
  });
  adminCookie = getCookie(loginRes);

  // 1. Fetch Stats
  const statsRes = await fetch(`${baseUrl}/api/v1/admin/stats`, {
    headers: { Cookie: adminCookie },
  });
  assert.equal(statsRes.status, 200);

  // 2. Fetch Users
  const usersRes = await fetch(`${baseUrl}/api/v1/admin/users`, {
    headers: { Cookie: adminCookie },
  });
  const usersBody = await usersRes.json();
  assert.equal(usersRes.status, 200);
  assert.ok(usersBody.data.users.some(u => u.email === FLOW_USER.email));

  // 3. Fetch Audit Logs
  const auditRes = await fetch(`${baseUrl}/api/v1/admin/audit-logs`, {
    headers: { Cookie: adminCookie },
  });
  assert.equal(auditRes.status, 200);
});

test('E2E Flow 8: Privacy Policy & Data Retention Transparency API', async () => {
  const res = await fetch(`${baseUrl}/api/v1/privacy`);
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.success, true);
  assert.ok(Array.isArray(body.data.guarantees));
  assert.ok(body.data.guarantees.some(g => g.scope === 'GUEST_SCANS'));
  assert.ok(body.data.guarantees.some(g => g.scope === 'REGISTERED_USER_SCANS'));
  assert.ok(body.data.guarantees.some(g => g.scope === 'ADMINISTRATIVE_ACCESS_DISCLOSURE'));
  assert.ok(body.data.guarantees.some(g => g.scope === 'OFFLINE_ANALYSIS_INTEGRITY'));
});

