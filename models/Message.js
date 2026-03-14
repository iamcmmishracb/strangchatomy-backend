const mongoose = require('mongoose');
const RETENTION_DAYS = parseInt(process.env.DATA_RETENTION_DAYS || 90);

// All messages are stored encrypted (AES-256-CBC, same key as IP encryption).
// Plain-text content is NEVER stored. Decryption is only performed:
//   1. By admin during a flagged-session review
//   2. In a law-enforcement data export (IT Act 2000, Sec. 69)
// TTL auto-deletes non-compliance messages after the retention window.

const messageSchema = new mongoose.Schema({
  sessionId:  { type: String, required: true, index: true },

  // Sender — stored as ObjectId when available, falls back to deviceSessionId string
  senderId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  senderUsername: { type: String },

  // Content — encrypted at rest (AES-256-CBC). Plain text is NEVER persisted.
  // Format: "<16-byte IV hex>:<ciphertext hex>"  (same format as IP encryption)
  contentEncrypted: { type: String, required: true },

  type:     { type: String, enum: ['text', 'image', 'file', 'emoji'], default: 'text' },
  mediaUrl: { type: String },

  isDeleted:             { type: Boolean, default: false },
  isFlagged:             { type: Boolean, default: false },
  retainedForCompliance: { type: Boolean, default: false },

  createdAt: { type: Date, default: Date.now },

  // TTL — auto-delete after retention window unless retained for compliance
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + RETENTION_DAYS * 24 * 60 * 60 * 1000),
  },
});

// Only auto-delete messages NOT retained for compliance (flagged sessions)
messageSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0, partialFilterExpression: { retainedForCompliance: false } }
);
messageSchema.index({ sessionId: 1, createdAt: 1 });
messageSchema.index({ isFlagged: 1 });
messageSchema.index({ senderId: 1 });

module.exports = mongoose.model('Message', messageSchema);
