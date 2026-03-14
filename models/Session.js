const mongoose = require('mongoose');
const RETENTION_DAYS = parseInt(process.env.DATA_RETENTION_DAYS || 90);

const sessionSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, unique: true, index: true },

  // Participants
  user1: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  user2: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  user1Username: String,
  user2Username: String,

  // Compliance: IP logs per session (encrypted)
  user1IpEncrypted: String,
  user2IpEncrypted: String,

  // Session info
  status: { type: String, enum: ['active', 'ended'], default: 'active' },
  endReason: { type: String, enum: ['user_left', 'user1_left', 'user2_left', 'disconnected', 'reported', 'admin_ended'], default: 'disconnected' },
  messageCount: { type: Number, default: 0 },
  durationSeconds: { type: Number, default: 0 }, // Gap 2: wall-clock seconds from match → disconnect
  isBotSession: { type: Boolean, default: false }, // Gap 3: true = matched a demo bot, no real partner
  isFlagged: { type: Boolean, default: false },   // If reported → retain messages
  flagReason: { type: String, default: '' },

  // Legal hold
  legalHold: { type: Boolean, default: false },

  startedAt: { type: Date, default: Date.now },
  endedAt: { type: Date },

  // TTL - auto delete after retention period
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + RETENTION_DAYS * 24 * 60 * 60 * 1000),
  },

  // ═══════════════════════════════════════════════════════════════════
  // NEW: ANONYMOUS SESSION FIELDS (Device-based matching)
  // ═══════════════════════════════════════════════════════════════════
  
  deviceId: { type: String },
  displayName: { type: String },
  gender: { type: String, enum: ['male', 'female', 'other'] },
  
  // Device info intentionally omitted from Session — stored on User only.
  // Per DPDP Act 2023 data minimisation: storing device model on every session
  // record has no additional compliance or safety value beyond the User record.
  
  // Location data intentionally removed — not required for core service
  // (data minimisation, DPDP Act 2023). Re-add only with encryption + purpose documentation.

  isAnonymous: { type: Boolean, default: false }
});

sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, partialFilterExpression: { legalHold: false, isFlagged: false } });
sessionSchema.index({ user1: 1, user2: 1 });
sessionSchema.index({ startedAt: -1 });
sessionSchema.index({ isFlagged: 1 });
sessionSchema.index({ deviceId: 1 });
sessionSchema.index({ status: 1 });
sessionSchema.index({ isBotSession: 1 }); // Gap 3: admin can filter real vs bot sessions

module.exports = mongoose.model('Session', sessionSchema);
