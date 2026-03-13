const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  reportedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  reportedUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  reportedUsername: String,
  sessionId: String,
  reason: { type: String, required: true, enum: ['spam', 'harassment', 'inappropriate_content', 'hate_speech', 'underage', 'threat', 'other'] },
  description: { type: String, maxlength: 1000 },
  evidence: [{ type: String }],  // message IDs or media URLs
  status: { type: String, enum: ['pending', 'under_review', 'resolved_ban', 'resolved_warn', 'resolved_dismissed'], default: 'pending' },
  adminNote: { type: String, default: '' },
  resolvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  resolvedAt: { type: Date },
  // When a report is filed, the session messages are flagged for retention
  sessionFlagged: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

reportSchema.index({ status: 1 });
reportSchema.index({ reportedUser: 1 });
reportSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Report', reportSchema);
