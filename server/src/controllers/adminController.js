/**
 * TRAPSHIELD Admin Controller
 * 
 * SERVER-SIDE AUTHORIZATION:
 * Accessible ONLY by users with role: 'admin'.
 * All sensitive administrative operations are recorded in AdminAuditLog.
 */

import { User } from '../models/User.js';
import { Scan } from '../models/Scan.js';
import { ScanAudit } from '../models/ScanAudit.js';
import { AdminAuditLog } from '../models/AdminAuditLog.js';
import { successResponse, errorResponse } from '../utils/apiResponse.js';
import mongoose from 'mongoose';

export async function listUsers(req, res, next) {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const skip = (page - 1) * limit;

    const [users, totalCount] = await Promise.all([
      User.find()
        .select('-passwordHash')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      User.countDocuments(),
    ]);

    // Aggregate scan counts per user
    const userIds = users.map(u => u._id);
    const scanCounts = await Scan.aggregate([
      { $match: { userId: { $in: userIds } } },
      { $group: { _id: '$userId', count: { $sum: 1 } } },
    ]);

    const countMap = new Map(scanCounts.map(item => [item._id.toString(), item.count]));

    const formattedUsers = users.map(u => ({
      id: u._id.toString(),
      email: u.email,
      role: u.role,
      isActive: u.isActive,
      lastLoginAt: u.lastLoginAt,
      createdAt: u.createdAt,
      totalScans: countMap.get(u._id.toString()) || 0,
    }));

    // Record admin viewing the users list
    await AdminAuditLog.create({
      adminId: req.user._id,
      adminEmail: req.user.email,
      action: 'VIEW_USERS_LIST',
      details: { page, limit, totalUsersFound: totalCount },
      ipAddress: req.ip,
    });

    return successResponse(
      res,
      {
        users: formattedUsers,
        pagination: {
          page,
          limit,
          total: totalCount,
          totalPages: Math.ceil(totalCount / limit) || 1,
        },
      },
      'User accounts retrieved successfully'
    );
  } catch (err) {
    return next(err);
  }
}

export async function getUserScans(req, res, next) {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return errorResponse(res, 'User not found', 404, 'USER_NOT_FOUND');
    }

    const targetUser = await User.findById(id).select('-passwordHash').lean();
    if (!targetUser) {
      return errorResponse(res, 'User not found', 404, 'USER_NOT_FOUND');
    }

    const scans = await Scan.find({ userId: targetUser._id })
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    const formattedScans = scans.map(s => ({
      id: s._id.toString(),
      analysisType: s.analysisType,
      submittedContent: s.submittedContent,
      riskScore: s.riskScore,
      riskClassification: s.riskClassification,
      detectedIndicators: s.detectedIndicators,
      evidence: s.evidence,
      explanations: s.explanations,
      recommendedActions: s.recommendedActions,
      createdAt: s.createdAt,
    }));

    // Audit logging for inspecting registered user scan contents
    await AdminAuditLog.create({
      adminId: req.user._id,
      adminEmail: req.user.email,
      action: 'VIEW_USER_SCANS',
      targetUserId: targetUser._id,
      targetUserEmail: targetUser.email,
      details: { scansRetrieved: scans.length },
      ipAddress: req.ip,
    });

    return successResponse(
      res,
      {
        user: {
          id: targetUser._id.toString(),
          email: targetUser.email,
          role: targetUser.role,
          isActive: targetUser.isActive,
          createdAt: targetUser.createdAt,
        },
        scans: formattedScans,
      },
      'User scans retrieved successfully'
    );
  } catch (err) {
    return next(err);
  }
}

export async function updateUserStatus(req, res, next) {
  try {
    const { id } = req.params;
    const { isActive } = req.body || {};

    if (typeof isActive !== 'boolean') {
      return errorResponse(res, 'Field "isActive" must be a boolean', 400, 'INVALID_STATUS');
    }

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return errorResponse(res, 'User not found', 404, 'USER_NOT_FOUND');
    }

    // SELF-SUSPENSION PREVENTION: Admin cannot suspend their own account
    if (id === req.user._id.toString()) {
      return errorResponse(res, 'Administrators cannot modify their own active status', 400, 'CANNOT_SUSPEND_SELF');
    }

    const targetUser = await User.findById(id);
    if (!targetUser) {
      return errorResponse(res, 'User not found', 404, 'USER_NOT_FOUND');
    }

    targetUser.isActive = isActive;
    if (!isActive) {
      // Invalidate existing sessions immediately by bumping token version
      targetUser.tokenVersion = (targetUser.tokenVersion || 0) + 1;
    }

    await targetUser.save();

    const action = isActive ? 'REACTIVATE_USER' : 'SUSPEND_USER';

    await AdminAuditLog.create({
      adminId: req.user._id,
      adminEmail: req.user.email,
      action,
      targetUserId: targetUser._id,
      targetUserEmail: targetUser.email,
      details: { previousStatus: !isActive, newStatus: isActive },
      ipAddress: req.ip,
    });

    return successResponse(
      res,
      { user: targetUser.toSafeJSON() },
      `User account ${isActive ? 'reactivated' : 'suspended'} successfully`
    );
  } catch (err) {
    return next(err);
  }
}

export async function getPlatformStats(req, res, next) {
  try {
    const [
      totalUsers,
      activeUsers,
      suspendedUsers,
      totalRegisteredScans,
      guestScanAudits,
      riskDistribution,
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isActive: true }),
      User.countDocuments({ isActive: false }),
      Scan.countDocuments(),
      ScanAudit.countDocuments({ isGuest: true }),
      Scan.aggregate([
        { $group: { _id: '$riskClassification.level', count: { $sum: 1 } } },
      ]),
    ]);

    const riskLevels = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };

    riskDistribution.forEach(item => {
      if (item._id && riskLevels[item._id] !== undefined) {
        riskLevels[item._id] = item.count;
      }
    });

    return successResponse(
      res,
      {
        users: {
          total: totalUsers,
          active: activeUsers,
          suspended: suspendedUsers,
        },
        scans: {
          totalSavedRegisteredScans: totalRegisteredScans,
          totalGuestScansLogged: guestScanAudits,
          riskDistribution: riskLevels,
        },
      },
      'Platform statistics retrieved successfully'
    );
  } catch (err) {
    return next(err);
  }
}

export async function getAuditLogs(req, res, next) {
  try {
    const logs = await AdminAuditLog.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    return successResponse(res, { logs }, 'Admin audit logs retrieved successfully');
  } catch (err) {
    return next(err);
  }
}

