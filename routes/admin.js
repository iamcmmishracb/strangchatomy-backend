const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const Message = require('../models/Message');
const Report = require('../models/Report');
const Session = require('../models/Session');
const Admin = require('../models/Admin');
const LawEnforcementRequest = require('../models/LawEnforcementRequest');
const { adminProtect, superAdminOnly } = require('../middleware/auth');
const { decrypt } = require('../utils/encryption');
const router = express.Router();

// POST /api/admin/login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username });
    if (!admin || !(await admin.comparePassword(password))) {
      return res.status(401).json({ success: false, message: 'Invalid admin credentials' });
    }
    admin.lastLogin = new Date();
    await admin.save();
    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '8h' });
    res.json({ success: true, data: { token, admin: { id: admin._id, username: admin.username, role: admin.role } } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/admin/stats
router.get('/stats', adminProtect, async (req, res) => {
  try {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const [totalUsers, onlineUsers, totalMessages, totalReports, pendingReports,
      totalSessions, activeSessions, pendingLERequests, newUsersToday, messagesToday] =
      await Promise.all([
        User.countDocuments(),
        User.countDocuments({ isOnline: true }),
        Message.countDocuments(),
        Report.countDocuments(),
        Report.countDocuments({ status: 'pending' }),
        Session.countDocuments(),
        Session.countDocuments({ status: 'active' }),
        LawEnforcementRequest.countDocuments({ status: { $in: ['received', 'under_review'] } }),
        User.countDocuments({ createdAt: { $gte: today } }),
        Message.countDocuments({ createdAt: { $gte: today } }),
      ]);

    res.json({
      success: true, data: {
        stats: {
          totalUsers, onlineUsers, totalMessages, totalReports, pendingReports,
          totalSessions, activeSessions, pendingLERequests,
          newUsersToday, messagesToday
        }
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/admin/users
router.get('/users', adminProtect, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', banned = '', legalHold = '' } = req.query;
    const query = {};
    if (search) query.$or = [{ username: new RegExp(search, 'i') }, { email: new RegExp(search, 'i') }];
    if (banned === 'true') query.isBanned = true;
    if (banned === 'false') query.isBanned = false;
    if (legalHold === 'true') query.legalHold = true;

    const users = await User.find(query).select('-password')
      .sort({ createdAt: -1 }).skip((page - 1) * limit).limit(Number(limit));
    const total = await User.countDocuments(query);

    res.json({ success: true, data: { users, total, pages: Math.ceil(total / limit) } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/admin/users/:id/ban
router.post('/users/:id/ban', adminProtect, async (req, res) => {
  try {
    const { reason } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id,
      { isBanned: true, banReason: reason || 'Violated terms of service', bannedAt: new Date(), bannedBy: req.admin._id },
      { new: true }).select('-password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, message: 'User banned', data: { user } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/admin/users/:id/unban
router.post('/users/:id/unban', adminProtect, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id,
      { isBanned: false, banReason: '', bannedAt: null },
      { new: true }).select('-password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, message: 'User unbanned', data: { user } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/admin/users/:id/legal-hold
router.post('/users/:id/legal-hold', adminProtect, async (req, res) => {
  try {
    const { reason, place } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id,
      { legalHold: place !== false, legalHoldReason: reason || '' },
      { new: true }).select('-password');
    res.json({ success: true, message: `Legal hold ${place !== false ? 'placed' : 'removed'}`, data: { user } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/admin/reports
router.get('/reports', adminProtect, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = '' } = req.query;
    const query = status ? { status } : {};
    const reports = await Report.find(query)
      .populate('reportedBy', 'username email')
      .populate('reportedUser', 'username email isBanned')
      .sort({ createdAt: -1 }).skip((page - 1) * limit).limit(Number(limit));
    const total = await Report.countDocuments(query);
    res.json({ success: true, data: { reports, total, pages: Math.ceil(total / limit) } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PATCH /api/admin/reports/:id
router.patch('/reports/:id', adminProtect, async (req, res) => {
  try {
    const { status, adminNote } = req.body;
    const report = await Report.findByIdAndUpdate(req.params.id,
      { status, adminNote, resolvedBy: req.admin._id, resolvedAt: new Date() },
      { new: true });
    res.json({ success: true, data: { report } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── LAW ENFORCEMENT SECTION ────────────────────────────────────────────

// GET /api/admin/le-requests
router.get('/le-requests', adminProtect, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = '' } = req.query;
    const query = status ? { status } : {};
    const requests = await LawEnforcementRequest.find(query)
      .sort({ createdAt: -1 }).skip((page - 1) * limit).limit(Number(limit));
    const total = await LawEnforcementRequest.countDocuments(query);
    res.json({ success: true, data: { requests, total, pages: Math.ceil(total / limit) } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/admin/le-requests
router.post('/le-requests', adminProtect, async (req, res) => {
  try {
    const { agencyName, agencyCountry, officerName, officerBadge, officerEmail,
      legalBasis, caseReference, targetUserId, requestType, description,
      dateRangeFrom, dateRangeTo } = req.body;

    const request = await LawEnforcementRequest.create({
      requestId: `LE-${Date.now()}-${uuidv4().slice(0, 8).toUpperCase()}`,
      agencyName, agencyCountry, officerName, officerBadge, officerEmail,
      legalBasis, caseReference, targetUserId, requestType, description,
      dateRangeFrom, dateRangeTo,
      processedBy: req.admin._id
    });

    // Place legal hold on target user
    if (targetUserId) {
      await User.findByIdAndUpdate(targetUserId, {
        legalHold: true,
        legalHoldReason: `LE Request: ${request.requestId} - ${agencyName}`
      });
    }

    res.status(201).json({ success: true, data: { request } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/admin/le-requests/:id/export  (SUPERADMIN ONLY)
router.post('/le-requests/:id/export', adminProtect, superAdminOnly, async (req, res) => {
  try {
    const leRequest = await LawEnforcementRequest.findById(req.params.id);
    if (!leRequest) return res.status(404).json({ success: false, message: 'LE request not found' });
    if (leRequest.status === 'rejected') return res.status(400).json({ success: false, message: 'Cannot export rejected request' });

    const user = await User.findById(leRequest.targetUserId);
    if (!user) return res.status(404).json({ success: false, message: 'Target user not found' });

    // Decrypt IPs for authorized export
    const decryptedRegIp = user.registrationIpEncrypted ? decrypt(user.registrationIpEncrypted) : null;
    const decryptedLastIp = user.lastLoginIpEncrypted ? decrypt(user.lastLoginIpEncrypted) : null;

    // Gather all data
    const sessions = await Session.find({
      $or: [{ user1: user._id }, { user2: user._id }],
      ...(leRequest.dateRangeFrom && { startedAt: { $gte: leRequest.dateRangeFrom } }),
      ...(leRequest.dateRangeTo && { startedAt: { $lte: leRequest.dateRangeTo } })
    });

    const flaggedMessages = await Message.find({
      sessionId: { $in: sessions.map(s => s.sessionId) },
      retainedForCompliance: true
    });

    const reports = await Report.find({ reportedUser: user._id });

    // Build LE export package
    const exportPackage = {
      exportMetadata: {
        requestId: leRequest.requestId,
        exportedAt: new Date().toISOString(),
        exportedBy: req.admin.username,
        agencyName: leRequest.agencyName,
        caseReference: leRequest.caseReference,
        legalBasis: leRequest.legalBasis,
        classification: 'CONFIDENTIAL - LAW ENFORCEMENT USE ONLY'
      },
      user: {
        userId: user._id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        registrationIp: decryptedRegIp,
        lastLoginIp: decryptedLastIp,
        deviceIds: user.deviceIds,
        registrationCountry: user.registrationCountry,
        userAgent: user.userAgent,
        createdAt: user.createdAt,
        lastActiveAt: user.lastActiveAt,
        isBanned: user.isBanned,
        banReason: user.banReason
      },
      sessions: sessions.map(s => ({
        sessionId: s.sessionId,
        partnerId: s.user1?.toString() === user._id.toString() ? s.user2 : s.user1,
        partnerUsername: s.user1?.toString() === user._id.toString() ? s.user2Username : s.user1Username,
        startedAt: s.startedAt,
        endedAt: s.endedAt,
        messageCount: s.messageCount,
        isFlagged: s.isFlagged,
        flagReason: s.flagReason
      })),
      flaggedMessages: flaggedMessages.map(m => ({
        messageId: m._id,
        sessionId: m.sessionId,
        content: m.content,
        type: m.type,
        mediaUrl: m.mediaUrl,
        sentAt: m.createdAt
      })),
      reports: reports.map(r => ({
        reportId: r._id,
        reportedBy: r.reportedBy,
        reason: r.reason,
        description: r.description,
        status: r.status,
        createdAt: r.createdAt
      }))
    };

    // Update LE request record
    await LawEnforcementRequest.findByIdAndUpdate(req.params.id, {
      status: 'exported',
      exportedAt: new Date(),
      exportedBy: req.admin._id,
      exportPackageId: `EXP-${Date.now()}`
    });

    res.json({ success: true, data: { exportPackage } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
