/**
 * TRAPSHIELD Scan Audit Model
 * 
 * STRICT PRIVACY & ZERO DATA-RETENTION POLICY:
 * This model deliberately NEVER stores submitted message texts, URLs, or payloads.
 * Only non-sensitive statistical metadata (score, category, indicator IDs, timestamp)
 * is recorded for security monitoring and aggregate metrics.
 */

import mongoose from 'mongoose';

const scanAuditSchema = new mongoose.Schema(
  {
    analysisType: {
      type: String,
      required: true,
      enum: ['MESSAGE', 'URL', 'JOB_OFFER'],
      index: true,
    },
    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
      index: true,
    },
    riskLevel: {
      type: String,
      required: true,
      enum: ['CRITICAL', 'HIGH', 'ELEVATED', 'LOW_INCONCLUSIVE', 'LOW', 'MEDIUM'],
      index: true,
    },
    indicatorCount: {
      type: Number,
      default: 0,
    },
    detectedIndicatorIds: {
      type: [String],
      default: [],
    },
    isGuest: {
      type: Boolean,
      default: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
      index: true,
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
  }
);

// TTL index to automatically purge guest scan audit records after 30 days
scanAuditSchema.index({ createdAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });

export const ScanAudit = mongoose.model('ScanAudit', scanAuditSchema);

