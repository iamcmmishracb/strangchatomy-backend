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
const crypto   = require('crypto');
const BannedIp = require('../models/BannedIp');
const router = express.Router();

// Hash IP for ban registry (matches the hash stored by sessions.js)
const hashIp = (ip) => crypto.createHash('sha256').update(ip).digest('hex');

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
      totalSessions, activeSessions, pendingLERequests, newUsersToday, messagesToday,
      botSessionsCount, sessionMessageStats] =
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
        // Gap 3: count bot-only sessions so admin can see real vs demo traffic
        Session.countDocuments({ isBotSession: true }),
        // Gap 2: sum messageCount and average durationSeconds across ended real sessions
        Session.aggregate([
          { $match: { status: 'ended', isBotSession: { $ne: true } } },
          { $group: {
            _id: null,
            totalSessionMessages: { $sum: '$messageCount' },
            avgDurationSeconds:   { $avg: '$durationSeconds' },
          }},
        ]),
      ]);

    const aggResult            = sessionMessageStats[0] || {};
    const totalSessionMessages = aggResult.totalSessionMessages || 0;
    const avgDurationSeconds   = aggResult.avgDurationSeconds
      ? Math.round(aggResult.avgDurationSeconds) : 0;
    const realSessions         = totalSessions - botSessionsCount;

    res.json({
      success: true, data: {
        stats: {
          totalUsers, onlineUsers, totalMessages, totalReports, pendingReports,
          totalSessions, activeSessions, pendingLERequests,
          newUsersToday, messagesToday,
          // Gap 2: total messages across all real sessions (more accurate than Message.count)
          totalSessionMessages,
          // Gap 2: average session length in seconds (ended real sessions only)
          avgDurationSeconds,
          // Gap 3: split of real vs bot sessions
          realSessions,
          botSessions: botSessionsCount,
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

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/admin/users/by-ip
// Groups users by registration IP hash so admins can spot multi-account abuse.
// IPs are stored encrypted — we group by hash(encrypt(ip)) which is consistent
// across registrations from the same IP.
// ═══════════════════════════════════════════════════════════════════════════

router.get('/users/by-ip', adminProtect, async (req, res) => {
  try {
    const { decrypt } = require('../utils/encryption');

    // Fetch all users that have an encrypted IP
    const users = await User.find(
      { registrationIpEncrypted: { $exists: true, $ne: null } },
      { username: 1, displayName: 1, gender: 1, isAnonymous: 1, isBanned: 1,
        registrationIpEncrypted: 1, lastLoginIpEncrypted: 1,
        deviceIds: 1, createdAt: 1, lastSeen: 1, totalChats: 1, reportedCount: 1 }
    ).lean();

    // Group by decrypted registration IP
    const ipMap = {};
    for (const u of users) {
      let ip = 'unknown';
      try {
        ip = decrypt(u.registrationIpEncrypted) || 'unknown';
      } catch {}
      if (!ipMap[ip]) ipMap[ip] = [];
      ipMap[ip].push({
        _id:           u._id,
        username:      u.username,
        displayName:   u.displayName,
        gender:        u.gender,
        isAnonymous:   u.isAnonymous,
        isBanned:      u.isBanned,
        deviceIds:     u.deviceIds,
        createdAt:     u.createdAt,
        lastSeen:      u.lastSeen,
        totalChats:    u.totalChats,
        reportedCount: u.reportedCount,
      });
    }

    // Build sorted array — most recent activity first, then most accounts per IP
    const groups = Object.entries(ipMap)
      .map(([ip, accounts]) => {
        // Sort accounts within group: newest first
        accounts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        const latestActivity = accounts[0]?.lastSeen || accounts[0]?.createdAt || 0;
        return { ip, count: accounts.length, accounts, latestActivity };
      })
      .sort((a, b) => new Date(b.latestActivity) - new Date(a.latestActivity));

    res.json({ success: true, data: { groups, totalIps: groups.length, totalUsers: users.length } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/admin/users/:id/detail
// Returns every field we collect, with IPs decrypted for admin view only.
// This is the endpoint used by the admin user-detail modal.
router.get('/users/:id/detail', adminProtect, async (req, res) => {
  try {
    const { decrypt } = require('../utils/encryption');
    const u = await User.findById(req.params.id).select('-password').lean();
    if (!u) return res.status(404).json({ success: false, message: 'User not found' });

    // Decrypt IPs for admin display only — never log or store decrypted values
    let registrationIp = null;
    let lastLoginIp    = null;
    try { if (u.registrationIpEncrypted) registrationIp = decrypt(u.registrationIpEncrypted); } catch {}
    try { if (u.lastLoginIpEncrypted)    lastLoginIp    = decrypt(u.lastLoginIpEncrypted);    } catch {}

    // Count sessions for this user
    const sessionCount = await Session.countDocuments({
      $or: [{ user1: u._id }, { user2: u._id }]
    });

    // Count reports filed against this user
    const reportsAgainst = await Report.countDocuments({ reportedUser: u._id });

    res.json({
      success: true,
      data: {
        user: {
          ...u,
          registrationIp,
          lastLoginIp,
          sessionCount,
          reportsAgainst,
        }
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', adminProtect, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/admin/users/:id/ban
// Gap 3 fix: automatically register all known IPs of the banned user in BannedIp
router.post('/users/:id/ban', adminProtect, async (req, res) => {
  try {
    const { reason, banIps = true, expiresAt = null } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id,
      { isBanned: true, banReason: reason || 'Violated terms of service', bannedAt: new Date(), bannedBy: req.admin._id },
      { new: true }).select('-password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    // Register all known IPs of this user in the BannedIp collection for session-creation checks
    if (banIps) {
      const ipsToHash = [];
      // Collect encrypted IPs from User record, decrypt them to hash
      if (user.registrationIpEncrypted) {
        try { ipsToHash.push(decrypt(user.registrationIpEncrypted)); } catch {}
      }
      if (user.lastLoginIpEncrypted && user.lastLoginIpEncrypted !== user.registrationIpEncrypted) {
        try { ipsToHash.push(decrypt(user.lastLoginIpEncrypted)); } catch {}
      }
      // Also pull IPs from all sessions this user participated in
      const sessions = await Session.find({
        $or: [{ user1: user._id }, { user2: user._id }],
        $or: [{ user1IpEncrypted: { $exists: true } }, { user2IpEncrypted: { $exists: true } }]
      }).select('user1 user1IpEncrypted user2IpEncrypted');
      for (const s of sessions) {
        const field = String(s.user1) === String(user._id) ? s.user1IpEncrypted : s.user2IpEncrypted;
        if (field) { try { ipsToHash.push(decrypt(field)); } catch {} }
      }
      // Deduplicate and upsert into BannedIp
      const uniqueIps = [...new Set(ipsToHash.filter(Boolean))];
      for (const ip of uniqueIps) {
        await BannedIp.updateOne(
          { ipHash: hashIp(ip) },
          { $set: { reason: reason || 'Banned user', bannedBy: req.admin._id, relatedUserId: user._id, expiresAt: expiresAt ? new Date(expiresAt) : null } },
          { upsert: true }
        );
      }
      console.log(`🚫 Registered ${uniqueIps.length} IPs in BannedIp for user ${user._id}`);
    }

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
    // Remove their IPs from BannedIp so they can use the platform again
    await BannedIp.deleteMany({ relatedUserId: user._id });
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
    const { page = 1, limit = 20, status = '', search = '' } = req.query;
    const query = {};
    if (status) query.status = status;
    if (search) query.reportedUsername = new RegExp(search, 'i');
    const reports = await Report.find(query)
      .populate('reportedBy',   'username displayName')
      .populate('reportedUser', 'username displayName isBanned')
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
      { new: true }
    );
    // Auto-ban the reported user when admin resolves with ban
    if (status === 'resolved_ban' && report?.reportedUser) {
      await User.findByIdAndUpdate(report.reportedUser, {
        isBanned: true,
        banReason: `Banned via report ${report._id} — ${report.reason}`
      });
    }
    res.json({ success: true, data: { report } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── SESSIONS ────────────────────────────────────────────────────────────────

// GET /api/admin/sessions
router.get('/sessions', adminProtect, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = '', search = '', flagged = '' } = req.query;
    const query = {};
    if (status) query.status = status;
    if (flagged === 'true') query.isFlagged = true;
    if (search) {
      query.$or = [
        { user1Username: new RegExp(search, 'i') },
        { user2Username: new RegExp(search, 'i') },
        { sessionId: new RegExp(search, 'i') }
      ];
    }

    const sessions = await Session.find(query)
      .sort({ startedAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit));
    const total = await Session.countDocuments(query);

    res.json({ success: true, data: { sessions, total, pages: Math.ceil(total / limit) } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/admin/sessions/:id
router.delete('/sessions/:id', adminProtect, async (req, res) => {
  try {
    await Session.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Session deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PATCH /api/admin/sessions/:id/flag
router.patch('/sessions/:id/flag', adminProtect, async (req, res) => {
  try {
    const { flag, reason } = req.body;
    const session = await Session.findByIdAndUpdate(req.params.id,
      { isFlagged: flag !== false, flagReason: reason || '' },
      { new: true });
    res.json({ success: true, data: { session } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PATCH /api/admin/sessions/:id/end
router.patch('/sessions/:id/end', adminProtect, async (req, res) => {
  try {
    const session = await Session.findByIdAndUpdate(req.params.id,
      { status: 'ended', endedAt: new Date(), endReason: 'admin_ended' },
      { new: true });
    res.json({ success: true, data: { session } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── MESSAGES ────────────────────────────────────────────────────────────────

// GET /api/admin/messages
// Returns messages with content decrypted for admin review.
// Decryption happens server-side only — the raw ciphertext is never sent to the client.
router.get('/messages', adminProtect, async (req, res) => {
  try {
    const { decrypt } = require('../utils/encryption');
    const { page = 1, limit = 20, sessionId = '', flagged = '' } = req.query;
    const query = {};
    if (sessionId) query.sessionId = sessionId;
    if (flagged === 'true')  query.isFlagged = true;
    if (flagged === 'false') query.isFlagged = false;
    // Note: full-text search on encrypted content is not possible without decrypting
    // every document. For search, use sessionId to narrow then scroll, or use
    // the LE export endpoint which decrypts a full session at once.

    const raw   = await Message.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .lean();
    const total = await Message.countDocuments(query);

    // Decrypt content for admin display — never store or log plain text
    const messages = raw.map(m => ({
      ...m,
      content: m.contentEncrypted ? (decrypt(m.contentEncrypted) ?? '[decryption failed]') : '[no content]',
      contentEncrypted: undefined, // strip ciphertext from response
    }));

    res.json({ success: true, data: { messages, total, pages: Math.ceil(total / limit) } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/admin/messages/:id
router.delete('/messages/:id', adminProtect, async (req, res) => {
  try {
    await Message.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Message deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PATCH /api/admin/messages/:id/flag
router.patch('/messages/:id/flag', adminProtect, async (req, res) => {
  try {
    const { flag } = req.body;
    const message = await Message.findByIdAndUpdate(req.params.id,
      { isFlagged: flag !== false, retainedForCompliance: flag !== false },
      { new: true });
    res.json({ success: true, data: { message } });
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

    const allMessages = await Message.find({
      sessionId: { $in: sessions.map(s => s.sessionId) },
    }).sort({ sessionId: 1, createdAt: 1 }).lean();

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
      flaggedMessages: allMessages.map(m => ({
        messageId:      m._id,
        sessionId:      m.sessionId,
        senderUsername: m.senderUsername,
        content:        m.contentEncrypted ? (decrypt(m.contentEncrypted) ?? '[decryption failed]') : '[no content]',
        type:           m.type,
        mediaUrl:       m.mediaUrl,
        isFlagged:      m.isFlagged,
        sentAt:         m.createdAt,
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

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/admin/grievance-officer  (public — IT Rules 2021, Rule 3(1)(c))
// Returns published Grievance Officer details as required by law.
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/admin/sessions/:sessionId/messages
// Returns all decrypted messages for a single session (for admin chat viewer)
// ═══════════════════════════════════════════════════════════════════════════

router.get('/sessions/:sessionId/messages', adminProtect, async (req, res) => {
  try {
    const { decrypt } = require('../utils/encryption');
    const raw = await Message.find({ sessionId: req.params.sessionId })
      .sort({ createdAt: 1 })
      .lean();

    const messages = raw.map(m => ({
      _id:            m._id,
      sessionId:      m.sessionId,
      senderUsername: m.senderUsername,
      senderId:       m.senderId,
      content:        m.contentEncrypted ? (decrypt(m.contentEncrypted) ?? '[decryption failed]') : '[no content]',
      type:           m.type,
      isFlagged:      m.isFlagged,
      isDeleted:      m.isDeleted,
      createdAt:      m.createdAt,
    }));

    res.json({ success: true, data: { messages, total: messages.length } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/grievance-officer', (req, res) => {
  res.json({
    success: true,
    data: {
      name:            process.env.GRIEVANCE_OFFICER_NAME    || 'Grievance Officer',
      email:           process.env.GRIEVANCE_OFFICER_EMAIL   || 'grievance@randomchat.app',
      phone:           process.env.GRIEVANCE_OFFICER_PHONE   || '',
      address:         process.env.GRIEVANCE_OFFICER_ADDRESS || 'India',
      acknowledgement: 'Complaints will be acknowledged within 24 hours and resolved within 15 days as per IT Rules 2021, Rule 3(2)(d).',
      workingHours:    'Monday–Friday, 10:00–18:00 IST',
    }
  });
});

module.exports = router;
