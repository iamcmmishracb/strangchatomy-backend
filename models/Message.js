const mongoose = require('mongoose');
const RETENTION_DAYS = parseInt(process.env.DATA_RETENTION_DAYS || 90);

// IMPORTANT: Messages are NOT stored by default (privacy compliance)
// Messages are ONLY stored when a session is flagged/reported
// This complies with DPDP Act 2023 and IT Act 2000

const messageSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, index: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  senderUsername: { type: String },
  content: { type: String, maxlength: 5000 },
  type: { type: String, enum: ['text', 'image', 'file', 'emoji'], default: 'text' },
  mediaUrl: { type: String },
  isDeleted: { type: Boolean, default: false },
  isFlagged: { type: Boolean, default: false },  // Specifically flagged message
  retainedForCompliance: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },

  // TTL
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + RETENTION_DAYS * 24 * 60 * 60 * 1000)
  }
});

// Only auto-delete messages NOT retained for compliance
messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, partialFilterExpression: { retainedForCompliance: false } });
messageSchema.index({ sessionId: 1, createdAt: 1 });
messageSchema.index({ isFlagged: 1 });

module.exports = mongoose.model('Message', messageSchema);
