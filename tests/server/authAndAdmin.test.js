/**
 * TRAPSHIELD Authentication, Ownership Isolation & Admin Authorization Tests
 * 
 * Tests:
 * 1. User registration, password criteria, bcrypt hashing, role restriction
 * 2. Login, HTTP-only cookie setting, credential verification
 * 3. Logout & cookie clearance
 * 4. Guest scans: zero raw text retention, no Scan documents
 * 5. Registered user scans: saved with submitted content for history
 * 6. 90-day retention TTL index verification
 * 7. Strict Ownership Isolation / IDOR prevention: User A cannot read or delete User B's scan
 * 8. Suspended user rejection and immediate session invalidation
 * 9. Admin role protection: regular users rejected from admin routes
 * 10. Admin user inspection, scan review, suspension/reactivation, self-suspension block
 * 11. Admin audit logging verification
 * 12. Privacy policy endpoint
 */

process.env.NODE_ENV = 'test';
process.env.AUTH_RATE_LIMIT_MAX = '1000';
process.env.RATE_LIMIT_MAX = '1000';
process.env.SCAN_RATE_LIMIT_MAX = '1000';

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import mongoose from 'mongoose';
import { app } from '../../server/src/app.js';
import { connectDatabase, disconnectDatabase } from '../../server/src/config/db.js';
import { User } from '../../server/src/models/User.js';
import { Scan } from '../../server/src/models/Scan.js';
import { ScanAudit } from '../../server/src/models/ScanAudit.js';
import { AdminAuditLog } from '../../server/src/models/AdminAuditLog.js';

let server;
let baseUrl;

function getCookie(res) {
  const setCookie = res.headers.get('set-cookie');
  if (!setCookie) return '';
  return setCookie.split(';')[0];
}

const TEST_USER_A = {
  email: `test_user_a_${Date.now()}@trapshield.test`,
  password: 'Password123!',
};

const TEST_USER_B = {
  email: `test_user_b_${Date.now()}@trapshield.test`,
  password: 'Password456!',
};

const TEST_ADMIN = {
  email: `admin_${Date.now()}@trapshield.test`,
  password: 'AdminSuperPassword2026!',
};

let userACookie = '';
let userBCookie = '';
let adminCookie = '';
let userAScanId = '';
let userBScanId = '';
let userBId = '';

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
  // Clean up test data created during test run
  try {
    const testEmails = [TEST_USER_A.email, TEST_USER_B.email, TEST_ADMIN.email];
    const users = await User.find({ email: { $in: testEmails } });
    const userIds = users.map(u => u._id);
    await Scan.deleteMany({ userId: { $in: userIds } });
    await AdminAuditLog.deleteMany({ adminEmail: TEST_ADMIN.email });
    await User.deleteMany({ email: { $in: testEmails } });
  } catch (err) {
    // Ignore cleanup error
  }
  await disconnectDatabase();
});

// ----------------------------------------------------
// 1. PRIVACY DISCLOSURE TESTS
// ----------------------------------------------------
test('Privacy Policy - Discloses zero guest retention and 90-day registered TTL', async () => {
  const res = await fetch(`${baseUrl}/api/v1/privacy`);
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.success, true);
  assert.ok(body.data.guarantees.some(g => g.scope === 'GUEST_SCANS' && /zero/i.test(g.policy)));
  assert.ok(body.data.guarantees.some(g => g.scope === 'REGISTERED_USER_SCANS' && /90-day/i.test(g.policy)));
  assert.ok(body.data.guarantees.some(g => g.scope === 'ADMINISTRATIVE_ACCESS_DISCLOSURE'));
});

// ----------------------------------------------------
// 2. AUTHENTICATION & REGISTRATION TESTS
// ----------------------------------------------------
test('Auth - Rejects invalid email and weak passwords', async () => {
  // Invalid email
  const res1 = await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'not-an-email', password: 'Password123' }),
  });
  assert.equal(res1.status, 400);

  // Weak password (< 8 chars)
  const res2 = await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'valid@test.com', password: 'short' }),
  });
  assert.equal(res2.status, 400);

  // No numbers
  const res3 = await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'valid@test.com', password: 'OnlyLettersHere' }),
  });
  assert.equal(res3.status, 400);
});

test('Auth - Successfully registers User A and sets HTTP-only cookie', async () => {
  const res = await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: TEST_USER_A.email,
      password: TEST_USER_A.password,
      role: 'admin', // PRIVILEGE ESCALATION ATTEMPT: must be ignored and forced to 'user'
    }),
  });
  const body = await res.json();

  assert.equal(res.status, 201);
  assert.equal(body.success, true);
  assert.equal(body.data.user.email, TEST_USER_A.email);
  assert.equal(body.data.user.role, 'user'); // Strict escalation prevention
  assert.equal(body.data.user.passwordHash, undefined); // Never exposed

  // Check HTTP-only cookie
  userACookie = getCookie(res);
  assert.ok(userACookie.includes('trapshield_token='));
  const rawSetCookie = res.headers.get('set-cookie');
  assert.match(rawSetCookie, /HttpOnly/i);
});

test('Auth - Registers User B successfully', async () => {
  const res = await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(TEST_USER_B),
  });
  const body = await res.json();

  assert.equal(res.status, 201);
  userBCookie = getCookie(res);
  userBId = body.data.user.id;
});

test('Auth - Rejects duplicate email registration', async () => {
  const res = await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(TEST_USER_A),
  });
  const body = await res.json();

  assert.equal(res.status, 409);
  assert.equal(body.errorCode, 'EMAIL_ALREADY_EXISTS');
});

test('Auth - Rejects invalid login credentials', async () => {
  const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: TEST_USER_A.email, password: 'WrongPassword999!' }),
  });
  const body = await res.json();

  assert.equal(res.status, 401);
  assert.equal(body.errorCode, 'INVALID_CREDENTIALS');
});

test('Auth - Successfully logs in User A and returns safe user profile', async () => {
  const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(TEST_USER_A),
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.data.user.email, TEST_USER_A.email);
  assert.equal(body.data.user.passwordHash, undefined);
  userACookie = getCookie(res);
});

test('Auth - GET /api/v1/auth/me returns authenticated user details', async () => {
  const res = await fetch(`${baseUrl}/api/v1/auth/me`, {
    headers: { Cookie: userACookie },
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.data.user.email, TEST_USER_A.email);
  assert.equal(body.data.user.role, 'user');
});

test('Auth - GET /api/v1/auth/me rejects unauthenticated request', async () => {
  const res = await fetch(`${baseUrl}/api/v1/auth/me`);
  assert.equal(res.status, 401);
});

test('Auth - Logout clears session cookie', async () => {
  const res = await fetch(`${baseUrl}/api/v1/auth/logout`, {
    method: 'POST',
    headers: { Cookie: userACookie },
  });
  assert.equal(res.status, 200);
  const rawSetCookie = res.headers.get('set-cookie');
  // Cleared cookie should either have empty value or expire in the past
  assert.ok(rawSetCookie.includes('trapshield_token=;') || rawSetCookie.includes('Expires=Thu, 01 Jan 1970'));
});

// ----------------------------------------------------
// 3. GUEST PRIVACY & ZERO RETENTION TESTS
// ----------------------------------------------------
test('Guest Privacy - Scan without authentication succeeds and NEVER persists submitted content in Scan collection', async () => {
  const secretGuestContent = 'CONFIDENTIAL_GUEST_TEXT_DO_NOT_STORE_12345';
  const initialScanCount = await Scan.countDocuments();

  const res = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'MESSAGE', input: secretGuestContent }),
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.data.savedScanId, undefined); // No saved scan ID returned for guests

  // Verify that Scan collection did NOT increase
  const postScanCount = await Scan.countDocuments();
  assert.equal(postScanCount, initialScanCount, 'Guest scan must not create a document in Scan model');

  // Verify that submitted text was NEVER stored in Scan
  const storedContent = await Scan.findOne({ submittedContent: secretGuestContent });
  assert.equal(storedContent, null, 'Submitted guest text must never be saved in Scan model');
});

// ----------------------------------------------------
// 4. REGISTERED USER SCAN HISTORY & 90-DAY RETENTION
// ----------------------------------------------------
test('Registered User - Scan with auth cookie saves submitted content and analysis to Scan history', async () => {
  // Re-login User A
  const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(TEST_USER_A),
  });
  userACookie = getCookie(loginRes);

  const submittedMessage = 'URGENT: Your bank account is suspended. Verify KYC immediately on WhatsApp.';

  const scanRes = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: userACookie,
    },
    body: JSON.stringify({ type: 'MESSAGE', input: submittedMessage }),
  });
  const body = await scanRes.json();

  assert.equal(scanRes.status, 200);
  assert.ok(body.data.savedScanId, 'Expected savedScanId for registered user');
  userAScanId = body.data.savedScanId;

  // Verify in MongoDB that Scan was created with the submitted content
  const dbScan = await Scan.findById(userAScanId);
  assert.ok(dbScan);
  assert.equal(dbScan.submittedContent, submittedMessage);
  assert.equal(dbScan.riskScore, body.data.riskScore);
});

test('Registered User - User B saves a scan to their history', async () => {
  const submittedUrl = 'http://192.168.1.50/login';

  const scanRes = await fetch(`${baseUrl}/api/v1/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: userBCookie,
    },
    body: JSON.stringify({ type: 'URL', input: submittedUrl }),
  });
  const body = await scanRes.json();

  assert.equal(scanRes.status, 200);
  assert.ok(body.data.savedScanId);
  userBScanId = body.data.savedScanId;
});

test('Retention Policy - Scan model has 90-day TTL index configured', async () => {
  const indexes = await Scan.collection.indexes();
  const ttlIndex = indexes.find(idx => idx.key && idx.key.createdAt === 1 && idx.expireAfterSeconds !== undefined);

  assert.ok(ttlIndex, 'Scan collection must have a TTL index on createdAt');
  // 90 days = 90 * 24 * 60 * 60 = 7,776,000 seconds
  assert.equal(ttlIndex.expireAfterSeconds, 90 * 24 * 60 * 60);
});

test('Registered User - Lists their own scan history', async () => {
  const res = await fetch(`${baseUrl}/api/v1/scan/history`, {
    headers: { Cookie: userACookie },
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.ok(Array.isArray(body.data.scans));
  assert.ok(body.data.scans.length >= 1);
  assert.equal(body.data.scans[0].id, userAScanId);
});

test('Registered User - Retrieves single scan by ID', async () => {
  const res = await fetch(`${baseUrl}/api/v1/scan/history/${userAScanId}`, {
    headers: { Cookie: userACookie },
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.data.id, userAScanId);
  assert.ok(body.data.submittedContent);
});

// ----------------------------------------------------
// 5. STRICT OWNERSHIP ISOLATION (IDOR PROTECTION)
// ----------------------------------------------------
test('Ownership Isolation - User A CANNOT view User B scan record (returns 404)', async () => {
  const res = await fetch(`${baseUrl}/api/v1/scan/history/${userBScanId}`, {
    headers: { Cookie: userACookie }, // User A tries to view User B's scan
  });
  assert.equal(res.status, 404);
});

test('Ownership Isolation - User A CANNOT delete User B scan record (returns 404)', async () => {
  const res = await fetch(`${baseUrl}/api/v1/scan/history/${userBScanId}`, {
    method: 'DELETE',
    headers: { Cookie: userACookie }, // User A tries to delete User B's scan
  });
  assert.equal(res.status, 404);

  // Verify User B's scan is still intact
  const stillExists = await Scan.findById(userBScanId);
  assert.ok(stillExists, 'Scan must not be deleted by unauthorized user');
});

test('Registered User - Deletes own scan record', async () => {
  const res = await fetch(`${baseUrl}/api/v1/scan/history/${userAScanId}`, {
    method: 'DELETE',
    headers: { Cookie: userACookie },
  });
  assert.equal(res.status, 200);

  // Verify deletion from DB
  const deleted = await Scan.findById(userAScanId);
  assert.equal(deleted, null);
});

// ----------------------------------------------------
// 6. ADMIN AUTHORIZATION & CONTROLS
// ----------------------------------------------------
test('Admin - Bootstraps admin account and rejects non-admin access', async () => {
  // Create admin user directly in DB (simulating seed command)
  const passwordHash = await User.hashPassword(TEST_ADMIN.password);
  await User.create({
    email: TEST_ADMIN.email,
    passwordHash,
    role: 'admin',
    isActive: true,
  });

  // Regular user (User A) attempting admin endpoint is rejected with 403
  const forbiddenRes = await fetch(`${baseUrl}/api/v1/admin/users`, {
    headers: { Cookie: userACookie },
  });
  assert.equal(forbiddenRes.status, 403);

  // Unauthenticated user attempting admin endpoint is rejected with 401
  const unauthRes = await fetch(`${baseUrl}/api/v1/admin/users`);
  assert.equal(unauthRes.status, 401);

  // Log in as Admin
  const adminLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(TEST_ADMIN),
  });
  assert.equal(adminLoginRes.status, 200);
  adminCookie = getCookie(adminLoginRes);
});

test('Admin - Can view registered users list with metadata', async () => {
  const res = await fetch(`${baseUrl}/api/v1/admin/users`, {
    headers: { Cookie: adminCookie },
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.ok(Array.isArray(body.data.users));
  assert.ok(body.data.users.some(u => u.email === TEST_USER_B.email));
});

test('Admin - Can view a registered user saved scan contents', async () => {
  const res = await fetch(`${baseUrl}/api/v1/admin/users/${userBId}/scans`, {
    headers: { Cookie: adminCookie },
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.ok(Array.isArray(body.data.scans));
  assert.ok(body.data.scans.some(s => s.id === userBScanId));
  assert.ok(body.data.scans[0].submittedContent);

  // Verify that an AdminAuditLog entry was recorded
  const auditLog = await AdminAuditLog.findOne({
    action: 'VIEW_USER_SCANS',
    targetUserId: userBId,
  });
  assert.ok(auditLog, 'Admin viewing user scans must be audited');
});

test('Admin - Can suspend a user account and suspend immediate access', async () => {
  const res = await fetch(`${baseUrl}/api/v1/admin/users/${userBId}/status`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Cookie: adminCookie,
    },
    body: JSON.stringify({ isActive: false }),
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.data.user.isActive, false);

  // User B's session should now be rejected with 403 on protected endpoints
  const blockedRes = await fetch(`${baseUrl}/api/v1/scan/history`, {
    headers: { Cookie: userBCookie },
  });
  assert.equal(blockedRes.status, 403);

  // User B cannot log in while suspended
  const loginAttemptRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(TEST_USER_B),
  });
  assert.equal(loginAttemptRes.status, 403);
});

test('Admin - Cannot suspend their own account', async () => {
  const adminDoc = await User.findOne({ email: TEST_ADMIN.email });
  const res = await fetch(`${baseUrl}/api/v1/admin/users/${adminDoc._id}/status`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Cookie: adminCookie,
    },
    body: JSON.stringify({ isActive: false }),
  });
  const body = await res.json();

  assert.equal(res.status, 400);
  assert.equal(body.errorCode, 'CANNOT_SUSPEND_SELF');
});

test('Admin - Can reactivate a suspended user account', async () => {
  const res = await fetch(`${baseUrl}/api/v1/admin/users/${userBId}/status`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Cookie: adminCookie,
    },
    body: JSON.stringify({ isActive: true }),
  });
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.data.user.isActive, true);

  // User B can now log in again
  const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(TEST_USER_B),
  });
  assert.equal(loginRes.status, 200);
});

test('Admin - Retrieves platform statistics and audit logs', async () => {
  const statsRes = await fetch(`${baseUrl}/api/v1/admin/stats`, {
    headers: { Cookie: adminCookie },
  });
  const statsBody = await statsRes.json();
  assert.equal(statsRes.status, 200);
  assert.ok(statsBody.data.users.total >= 2);
  assert.ok(statsBody.data.scans.totalSavedRegisteredScans >= 1);

  const logsRes = await fetch(`${baseUrl}/api/v1/admin/audit-logs`, {
    headers: { Cookie: adminCookie },
  });
  const logsBody = await logsRes.json();
  assert.equal(logsRes.status, 200);
  assert.ok(Array.isArray(logsBody.data.logs));
  assert.ok(logsBody.data.logs.length >= 1);
});
