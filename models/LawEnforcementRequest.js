const mongoose = require('mongoose');

// IT Act 2000 Section 69 - Mandatory logging of all LE requests
// Every request from law enforcement MUST be logged here

const lawEnforcementRequestSchema = new mongoose.Schema({
  requestId: { type: String, required: true, unique: true },

  // Agency details
  agencyName: { type: String, required: true },
  agencyCountry: { type: String, required: true, default: 'IN' },
  officerName: { type: String, required: true },
  officerBadge: { type: String },
  officerEmail: { type: String },
  officerPhone: { type: String },

  // Legal basis
  legalBasis: { type: String, required: true, enum: [
    'court_order',           // Court issued order
    'mlat',                  // Mutual Legal Assistance Treaty
    'emergency_disclosure',  // Imminent threat to life
    'national_security',     // National security request
    'it_act_section_69',     // IT Act Section 69
    'crpc_section_91',       // CrPC Section 91
    'other'
  ]},
  caseReference: { type: String, required: true },
  courtOrderNumber: { type: String },
  documentUrl: { type: String },  // Upload of legal document

  // Target user
  targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  targetUsername: { type: String },
  targetEmail: { type: String },

  // Request details
  requestType: { type: String, enum: ['user_info', 'session_logs', 'messages', 'full_package'], required: true },
  dateRangeFrom: { type: Date },
  dateRangeTo: { type: Date },
  description: { type: String, required: true },

  // Processing
  status: { type: String, enum: ['received', 'under_review', 'approved', 'rejected', 'exported', 'completed'], default: 'received' },
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  processedAt: { type: Date },
  rejectionReason: { type: String },
  exportedAt: { type: Date },
  exportedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  exportPackageId: { type: String },

  // Legal hold placed on user data
  legalHoldPlaced: { type: Boolean, default: false },

  // Audit trail
  notes: [{ text: String, addedBy: String, addedAt: { type: Date, default: Date.now } }],

  receivedAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

lawEnforcementRequestSchema.index({ status: 1 });
lawEnforcementRequestSchema.index({ targetUserId: 1 });
lawEnforcementRequestSchema.index({ createdAt: -1 });

module.exports = mongoose.model('LawEnforcementRequest', lawEnforcementRequestSchema);
