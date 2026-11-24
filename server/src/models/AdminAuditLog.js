/**
 * TRAPSHIELD Admin Audit Log Model
 * 
 * Immutable record of sensitive administrator operations:
 * - User account suspension / reactivation
 * - Inspecting registered users' scan history
 * - System admin bootstrapping
 */

import mongoose from 'mongoose';

const adminAuditLogSchema = new mongoose.Schema(
  {
    adminId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    adminEmail: {
      type: String,
      required: true,
    },
    action: {
      type: String,
      required: true,
      enum: [
        'SUSPEND_USER',
        'REACTIVATE_USER',
        'VIEW_USER_SCANS',
        'VIEW_USERS_LIST',
        'SYSTEM_SEED_ADMIN',
      ],
      index: true,
    },
    targetUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
      index: true,
    },
    targetUserEmail: {
      type: String,
      default: null,
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    ipAddress: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
  }
);

adminAuditLogSchema.index({ createdAt: -1 });

export const AdminAuditLog = mongoose.model('AdminAuditLog', adminAuditLogSchema);

