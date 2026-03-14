const mongoose = require('mongoose');

// ── BannedIp — IP-level ban registry (Gap 3 fix) ─────────────────────────────
// When a user is banned for severe violations their encrypted IPs (from User and
// Session records) are added here. On every new session creation the incoming IP
// is checked against this list BEFORE any data is stored, supporting the IT Act
// Sec. 79 safe harbour requirement to act on knowledge of abuse.

const bannedIpSchema = new mongoose.Schema({
  // We store a SHA-256 hash of the IP (not the raw IP, not the AES cipher) so
  // the check is fast (hash comparison) and irreversible (no decryption path).
  ipHash:     { type: String, required: true, unique: true, index: true },

  reason:     { type: String, default: '' },
  bannedBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  relatedUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },

  // Optional expiry — null means permanent
  expiresAt:  { type: Date, default: null },

  createdAt:  { type: Date, default: Date.now },
});

// Auto-remove expired entries
bannedIpSchema.index({ expiresAt: 1 }, {
  expireAfterSeconds: 0,
  partialFilterExpression: { expiresAt: { $type: 'date' } },
});

module.exports = mongoose.model('BannedIp', bannedIpSchema);
