const mongoose = require('mongoose');

// TTL: Auto-delete inactive users after 90 days (IT Act compliance)
const RETENTION_DAYS = parseInt(process.env.DATA_RETENTION_DAYS || 90);

const userSchema = new mongoose.Schema({
  // Identity
  username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 20 },
  email: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  isAnonymous: { type: Boolean, default: false },

  // Profile
  avatar: { type: String, default: '' },
  displayName: { type: String, default: '' },
  bio: { type: String, maxlength: 200, default: '' },
  gender: { type: String, enum: ['male', 'female', 'other', 'prefer_not_to_say'], default: 'prefer_not_to_say' },
  interests: [{ type: String }],

  // Compliance & Law Enforcement (IT Act 2000, Section 79)
  registrationIpEncrypted: { type: String },        // AES-256 encrypted
  lastLoginIpEncrypted: { type: String },            // AES-256 encrypted
  deviceIds: [{ type: String }],                     // Device fingerprints
  registrationCountry: { type: String, default: 'IN' },
  userAgent: { type: String },

  // Status
  isOnline: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  banReason: { type: String, default: '' },
  bannedAt: { type: Date },
  bannedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  isVerified: { type: Boolean, default: false },
  role: { type: String, enum: ['user', 'moderator'], default: 'user' },

  // Legal hold - prevent auto-deletion if under LE investigation
  legalHold: { type: Boolean, default: false },
  legalHoldReason: { type: String, default: '' },

  // Stats
  totalChats: { type: Number, default: 0 },
  totalMessages: { type: Number, default: 0 },
  reportCount: { type: Number, default: 0 },
  reportedCount: { type: Number, default: 0 },

  // Settings
  settings: {
    notifications: { type: Boolean, default: true },
    sound: { type: Boolean, default: true },
    theme: { type: String, default: 'dark' },
    language: { type: String, default: 'en' },
  },

  lastSeen: { type: Date, default: Date.now },
  lastActiveAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },

  // TTL index - auto delete after retention period if no legal hold
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + RETENTION_DAYS * 24 * 60 * 60 * 1000)
  }
});

// TTL index - MongoDB auto-deletes documents when expiresAt is reached
// Only applies when legalHold is false
userSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, partialFilterExpression: { legalHold: false } });
userSchema.index({ isOnline: 1 });
userSchema.index({ isBanned: 1 });
userSchema.index({ createdAt: -1 });

// Update lastActiveAt and refresh TTL on activity
userSchema.methods.recordActivity = async function (ipEncrypted) {
  this.lastActiveAt = new Date();
  this.lastSeen = new Date();
  if (ipEncrypted) this.lastLoginIpEncrypted = ipEncrypted;
  // Refresh retention window
  if (!this.legalHold) {
    this.expiresAt = new Date(Date.now() + RETENTION_DAYS * 24 * 60 * 60 * 1000);
  }
  await this.save();
};

module.exports = mongoose.model('User', userSchema);
