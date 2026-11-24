/**
 * TRAPSHIELD Scan History Controller
 * 
 * STRICT TENANT & OWNERSHIP ISOLATION:
 * Every query rigorously matches `userId: req.user._id`.
 * Insecure Direct Object References (IDOR) are strictly prevented:
 * attempting to access or delete another user's scan returns a 404.
 */

import { Scan } from '../models/Scan.js';
import { successResponse, errorResponse } from '../utils/apiResponse.js';
import mongoose from 'mongoose';

export async function getScanHistory(req, res, next) {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const skip = (page - 1) * limit;

    const filter = { userId: req.user._id };

    const [scans, totalCount] = await Promise.all([
      Scan.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Scan.countDocuments(filter),
    ]);

    const formattedScans = scans.map(scan => ({
      id: scan._id.toString(),
      analysisType: scan.analysisType,
      submittedContent: scan.submittedContent,
      riskScore: scan.riskScore,
      riskClassification: scan.riskClassification,
      detectedIndicators: scan.detectedIndicators,
      evidence: scan.evidence,
      explanations: scan.explanations,
      recommendedActions: scan.recommendedActions,
      createdAt: scan.createdAt,
    }));

    return successResponse(
      res,
      {
        scans: formattedScans,
        pagination: {
          page,
          limit,
          total: totalCount,
          totalPages: Math.ceil(totalCount / limit) || 1,
        },
      },
      'Scan history retrieved successfully'
    );
  } catch (err) {
    return next(err);
  }
}

export async function getScanById(req, res, next) {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return errorResponse(res, 'Scan record not found', 404, 'SCAN_NOT_FOUND');
    }

    // STRICT OWNERSHIP ISOLATION: user can only fetch their own scan
    const scan = await Scan.findOne({ _id: id, userId: req.user._id }).lean();

    if (!scan) {
      return errorResponse(res, 'Scan record not found', 404, 'SCAN_NOT_FOUND');
    }

    return successResponse(
      res,
      {
        id: scan._id.toString(),
        analysisType: scan.analysisType,
        submittedContent: scan.submittedContent,
        riskScore: scan.riskScore,
        riskClassification: scan.riskClassification,
        scoringMetadata: scan.scoringMetadata,
        detectedIndicators: scan.detectedIndicators,
        evidence: scan.evidence,
        explanations: scan.explanations,
        recommendedActions: scan.recommendedActions,
        createdAt: scan.createdAt,
      },
      'Scan record retrieved successfully'
    );
  } catch (err) {
    return next(err);
  }
}

export async function deleteScanById(req, res, next) {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return errorResponse(res, 'Scan record not found', 404, 'SCAN_NOT_FOUND');
    }

    // STRICT OWNERSHIP ISOLATION: user can only delete their own scan
    const deleted = await Scan.findOneAndDelete({ _id: id, userId: req.user._id });

    if (!deleted) {
      return errorResponse(res, 'Scan record not found', 404, 'SCAN_NOT_FOUND');
    }

    return successResponse(res, { id }, 'Scan record deleted successfully');
  } catch (err) {
    return next(err);
  }
}

