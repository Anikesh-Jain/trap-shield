/**
 * TRAPSHIELD Administrator Bootstrap Script
 * 
 * SECURITY MANDATE:
 * - Bootstraps the single platform administrator securely using environment variables.
 * - Enforces exactly ONE administrator account.
 * - Does NOT hardcode passwords or secrets.
 * - Records bootstrapping in AdminAuditLog.
 */

import { connectDatabase, disconnectDatabase } from '../config/db.js';
import { env } from '../config/env.js';
import { User } from '../models/User.js';
import { AdminAuditLog } from '../models/AdminAuditLog.js';
import { logger } from '../utils/logger.js';

async function seedAdmin() {
  const adminEmail = (env.ADMIN_EMAIL || process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const adminPassword = (env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD || '').trim();

  if (!adminEmail || !adminEmail.includes('@')) {
    logger.error('ADMIN_EMAIL environment variable is required and must be a valid email address.');
    process.exit(1);
  }

  if (!adminPassword || adminPassword.length < 12) {
    logger.error('ADMIN_PASSWORD environment variable is required and must be at least 12 characters.');
    logger.info('Usage: ADMIN_PASSWORD="your-secure-password" npm run seed:admin');
    process.exit(1);
  }

  const connected = await connectDatabase();
  if (!connected) {
    logger.error('Cannot connect to MongoDB. Ensure MongoDB is running before bootstrapping admin.');
    process.exit(1);
  }

  try {
    const existingAdmin = await User.findOne({ role: 'admin' });

    if (existingAdmin) {
      if (existingAdmin.email === adminEmail) {
        logger.info(`Administrator account with email "${adminEmail}" already exists. Updating password...`);
        const passwordHash = await User.hashPassword(adminPassword);
        existingAdmin.passwordHash = passwordHash;
        existingAdmin.isActive = true;
        await existingAdmin.save();

        await AdminAuditLog.create({
          adminId: existingAdmin._id,
          adminEmail: existingAdmin.email,
          action: 'SYSTEM_SEED_ADMIN',
          details: { message: 'Existing administrator password rotated via seed command' },
        });

        logger.info('Administrator password updated successfully.');
      } else {
        logger.warn(
          `Security policy violation: An administrator account already exists with email "${existingAdmin.email}". TRAPSHIELD policy allows exactly one administrator.`
        );
        process.exit(1);
      }
    } else {
      const passwordHash = await User.hashPassword(adminPassword);
      const newAdmin = await User.create({
        email: adminEmail,
        passwordHash,
        role: 'admin',
        isActive: true,
      });

      await AdminAuditLog.create({
        adminId: newAdmin._id,
        adminEmail: newAdmin.email,
        action: 'SYSTEM_SEED_ADMIN',
        details: { message: 'Initial administrator account bootstrapped via seed command' },
      });

      logger.info(`Platform administrator account bootstrapped successfully: ${adminEmail}`);
    }
  } catch (err) {
    logger.error('Failed to seed administrator account', err);
    process.exit(1);
  } finally {
    await disconnectDatabase();
  }
}

seedAdmin().then(() => {
  process.exit(0);
});

