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
    index: true
  },

  // ═══════════════════════════════════════════════════════════════════
  // NEW: ANONYMOUS SESSION FIELDS (Device-based matching)
  // ═══════════════════════════════════════════════════════════════════
  
  deviceId: { type: String },
  displayName: { type: String },
  gender: { type: String, enum: ['male', 'female', 'other'] },
  
  // Device information
  deviceInfo: {
    model: String,
    manufacturer: String
  },
  
  // Location data
  location: {
    latitude: Number,
    longitude: Number,
    accuracy: Number,
    timestamp: Date
  },
  
  isAnonymous: { type: Boolean, default: false }
});

sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, partialFilterExpression: { legalHold: false, isFlagged: false } });
sessionSchema.index({ user1: 1, user2: 1 });
sessionSchema.index({ startedAt: -1 });
sessionSchema.index({ isFlagged: 1 });
sessionSchema.index({ deviceId: 1 });
sessionSchema.index({ status: 1 });

module.exports = mongoose.model('Session', sessionSchema);
