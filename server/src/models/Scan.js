/**
 * TRAPSHIELD Scan Model (Registered Users Only)
 * 
 * CRITICAL DATA RETENTION POLICY:
 * 1. Saved ONLY for authenticated registered users to access their scan history.
 * 2. GUEST USERS ARE NEVER STORED IN THIS COLLECTION.
 * 3. 90-DAY RETENTION POLICY: A MongoDB TTL index automatically deletes
 *    records 90 days after creation.
 * 4. STRICT OWNERSHIP: Every document is indexed and scoped by `userId`.
 */

import mongoose from 'mongoose';

const scanSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    analysisType: {
      type: String,
      required: true,
      enum: ['MESSAGE', 'URL', 'JOB_OFFER'],
      index: true,
    },
    submittedContent: {
      type: String,
      required: true,
    },
    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
      index: true,
    },
    riskClassification: {
      level: {
        type: String,
        required: true,
        enum: ['CRITICAL', 'HIGH', 'ELEVATED', 'LOW_INCONCLUSIVE', 'LOW', 'MEDIUM'],
      },
      label: { type: String, required: true },
      badgeColor: { type: String, default: null },
      description: { type: String, default: null },
    },
    scoringMetadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    detectedIndicators: {
      type: [mongoose.Schema.Types.Mixed],
      default: [],
    },
    evidence: {
      type: [String],
      default: [],
    },
    explanations: {
      type: [String],
      default: [],
    },
    recommendedActions: {
      type: [String],
      default: [],
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
  }
);

// 90-DAY TTL INDEX: Automatically purges records 90 days after creation
// 90 days * 24 hours * 60 minutes * 60 seconds = 7,776,000 seconds
scanSchema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });

// Compound index for fast user history queries sorted by newest first
scanSchema.index({ userId: 1, createdAt: -1 });

export const Scan = mongoose.model('Scan', scanSchema);
