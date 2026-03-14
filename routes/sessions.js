const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const Session = require('../models/Session');
const User = require('../models/User');
const { v4: uuidv4 } = require('uuid');
const { encrypt } = require('../utils/encryption');
const BannedIp   = require('../models/BannedIp');
const Report     = require('../models/Report');
const Message    = require('../models/Message');

const getIp = (req) =>
  req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';

// ── Country detection ─────────────────────────────────────────────────────────
// Primary:  geoip-lite (offline, fast — npm install geoip-lite)
// Fallback: ip-api.com free tier (HTTP, no key needed, 45 req/min limit)
// Never uses Accept-Language — that reflects browser/OS language, not location.
let geoip = null;
try { geoip = require('geoip-lite'); } catch { /* package not installed */ }

// In-memory country cache so repeated registrations from the same IP
// don't hammer the external API (cache survives process lifetime only).
const _countryCache = new Map();

async function detectCountry(req) {
  const ip = getIp(req);

  // Loopback — return UNKNOWN rather than hitting an API pointlessly
  if (!ip || ip === '::1' || ip === '127.0.0.1' || ip === 'unknown') return 'UNKNOWN';

  // Check cache first
  if (_countryCache.has(ip)) return _countryCache.get(ip);

  // 1. geoip-lite (offline, no rate limit)
  if (geoip) {
    const geo = geoip.lookup(ip);
    if (geo?.country) { _countryCache.set(ip, geo.country); return geo.country; }
  }

  // 2. ip-api.com free HTTP API (no key, 45 req/min, works on LAN IPs too)
  try {
    const http = require('http');
    const country = await new Promise((resolve, reject) => {
      const req2 = http.get(`http://ip-api.com/json/${ip}?fields=countryCode`, (res) => {
        let body = '';
        res.on('data', d => body += d);
        res.on('end', () => {
          try {
            const json = JSON.parse(body);
            resolve(json.status === 'success' ? json.countryCode : null);
          } catch { resolve(null); }
        });
      });
      req2.on('error', reject);
      req2.setTimeout(3000, () => { req2.destroy(); reject(new Error('timeout')); });
    });
    if (country) { _countryCache.set(ip, country); return country; }
  } catch { /* API unreachable — fall through */ }

  return 'UNKNOWN';
}

const crypto = require('crypto');

// Input sanitiser — strips control chars, trims, limits length
const sanitizeString = (val, maxLen = 100) =>
  typeof val === 'string' ? val.replace(/[\x00-\x1F\x7F]/g, '').trim().slice(0, maxLen) : '';

// ── IP hash for ban-check (Gap 3 fix) ────────────────────────────────────────
// SHA-256 of the raw IP — fast, irreversible, consistent across checks.
const hashIp = (ip) => crypto.createHash('sha256').update(ip).digest('hex');

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/sessions/anonymous - Create Anonymous Session + User
// ═══════════════════════════════════════════════════════════════════════════

router.post('/anonymous', async (req, res) => {
  try {
    const {
      deviceId, displayName, gender, deviceModel, deviceManufacturer,
      latitude, longitude, accuracy,
      consentGiven, consentTimestamp, ageConfirmed,
    } = req.body;

    // DPDP Act 2023, Sec. 6 — consent required before data collection
    if (!consentGiven || consentGiven !== true) {
      return res.status(400).json({
        success: false,
        code: 'CONSENT_REQUIRED',
        message: 'User consent is required before data collection (DPDP Act 2023, Sec. 6)'
      });
    }

    // DPDP Act 2023, Sec. 9 — age verification
    if (!ageConfirmed || ageConfirmed !== true) {
      return res.status(400).json({
        success: false,
        code: 'AGE_CONFIRMATION_REQUIRED',
        message: 'Age confirmation (18+) is required (DPDP Act 2023, Sec. 9)'
      });
    }

    // ── IP ban check — blocks re-entry by banned IPs (IT Act Sec. 79, Gap 3 fix) ──
    const rawIp  = getIp(req);
    const ipHash = hashIp(rawIp);
    const ipBan  = await BannedIp.findOne({ ipHash, $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }] });
    if (ipBan) {
      return res.status(403).json({
        success: false,
        code: 'IP_BANNED',
        message: 'Access denied'   // intentionally vague — don't leak ban details
      });
    }

    if (!deviceId || !displayName || !gender) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: deviceId, displayName, gender'
      });
    }

    // Sanitise & length-limit all string inputs
    const cleanDisplayName = sanitizeString(displayName, 50);
    const cleanDeviceId    = sanitizeString(deviceId, 200);
    const cleanDeviceModel = sanitizeString(deviceModel, 100);
    const cleanDeviceMfr   = sanitizeString(deviceManufacturer, 100);

    if (cleanDisplayName.length < 2) {
      return res.status(400).json({ success: false, message: 'displayName must be at least 2 characters' });
    }

    const validGenders = ['male', 'female', 'other'];
    if (!validGenders.includes(gender.toLowerCase())) {
      return res.status(400).json({ success: false, message: `Invalid gender value: '${gender}'` });
    }

    const ip = rawIp;   // already captured above for ban check
    const sessionId = uuidv4();
    const shortId   = sessionId.slice(0, 6);

    let user = await User.findOne({ deviceIds: cleanDeviceId, isAnonymous: true });

    if (!user) {
      user = await User.create({
        username:                `${cleanDisplayName}_${shortId}`,
        displayName:             cleanDisplayName,
        gender:                  gender.toLowerCase(),
        isAnonymous:             true,
        deviceIds:               [cleanDeviceId],
        deviceModel:             cleanDeviceModel,
        deviceManufacturer:      cleanDeviceMfr,
        registrationIpEncrypted: encrypt(ip),
        lastLoginIpEncrypted:    encrypt(ip),
        registrationCountry:     await detectCountry(req),   // real country via IP geolocation
        userAgent:               sanitizeString(req.headers['user-agent'] || '', 300),
        isOnline:                false,
        consentGiven:            true,
        consentTimestamp:        consentTimestamp ? new Date(consentTimestamp) : new Date(),
        ageConfirmed:            true,
        // Gap 1: persist location when user granted permission
        ...(latitude  != null && longitude != null && {
          location: {
            latitude,
            longitude,
            accuracy: accuracy ?? null,
            capturedAt: new Date(),
          }
        }),
      });
    } else {
      user.displayName          = cleanDisplayName;
      user.lastLoginIpEncrypted = encrypt(ip);
      user.lastActiveAt         = new Date();
      user.consentGiven         = true;
      user.consentTimestamp     = new Date();
      // Gap 1: refresh location on returning users when permission is granted
      if (latitude != null && longitude != null) {
        user.location = { latitude, longitude, accuracy: accuracy ?? null, capturedAt: new Date() };
      }
      await user.save();
    }

    const sessionToken = jwt.sign(
      { sessionId, userId: user._id.toString(), deviceId: cleanDeviceId, displayName: cleanDisplayName, gender: gender.toLowerCase() },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    // Location intentionally omitted — not required for chat (data minimisation, DPDP Act 2023)
    await Session.create({
      sessionId,
      displayName:  cleanDisplayName,
      gender:       gender.toLowerCase(),
      deviceId:     cleanDeviceId,
      // deviceInfo (model/manufacturer) stored on User only, not duplicated on Session
      isAnonymous:  true,
      status:       'active',
      startedAt:    new Date()
    });

    res.status(201).json({
      success: true,
      data: {
        sessionId,
        userId:      user._id,
        sessionToken,
        displayName: cleanDisplayName,
        gender:      gender.toLowerCase(),
        expiresIn:   7200
      }
    });
  } catch (error) {
    console.error('❌ Error creating session:', error);
    res.status(500).json({ success: false, message: 'Failed to create session' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/sessions/anonymous/verify
// ═══════════════════════════════════════════════════════════════════════════

router.get('/anonymous/verify', (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'No token provided' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ success: true, message: 'Session valid', data: decoded });
  } catch {
    res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/sessions/anonymous/end
// ═══════════════════════════════════════════════════════════════════════════

router.post('/anonymous/end', async (req, res) => {
  try {
    const { sessionId, userId, durationSeconds, isBotSession } = req.body;
    if (!sessionId) return res.status(400).json({ success: false, message: 'sessionId required' });

    const sessionUpdate = {
      status:    'ended',
      endedAt:   new Date(),
      // Gap 2: persist duration reported by the Flutter client
      ...(typeof durationSeconds === 'number' && durationSeconds >= 0 && { durationSeconds }),
      // Gap 3: mark whether this was a demo-bot session (no real partner)
      ...(typeof isBotSession === 'boolean' && { isBotSession }),
    };

    await Session.findOneAndUpdate({ sessionId }, sessionUpdate);
    if (userId) await User.findByIdAndUpdate(userId, { isOnline: false, lastSeen: new Date() });
    res.json({ success: true, message: 'Session ended successfully' });
  } catch (error) {
    console.error('❌ Error ending session:', error);
    res.status(500).json({ success: false, message: 'Failed to end session' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// DELETE /api/sessions/account — Right to Erasure (DPDP Act 2023, Sec. 13)
// ═══════════════════════════════════════════════════════════════════════════

router.delete('/account', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Authentication required' });

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }

    const { userId, deviceId } = decoded;

    if (userId) {
      const user = await User.findById(userId);
      if (user?.legalHold) {
        return res.status(403).json({
          success: false,
          code: 'LEGAL_HOLD',
          message: 'Account is subject to a legal hold and cannot be deleted at this time'
        });
      }
      await User.findByIdAndDelete(userId);
      await Session.deleteMany({ $or: [{ user1: userId }, { user2: userId }, { deviceId }] });
      console.log(`🗑️  Account deleted: userId=${userId}`);
    }

    res.json({ success: true, message: 'Your account and all associated data have been permanently deleted' });
  } catch (error) {
    console.error('❌ Error deleting account:', error);
    res.status(500).json({ success: false, message: 'Failed to delete account' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/sessions/report  — User-submitted report
// Gap 4 fix: filing a report immediately auto-flags the Session and all its
// Messages so the 90-day TTL cannot delete evidence before admin review.
// Discovered gap fix: this endpoint did not exist at all before.
// ═══════════════════════════════════════════════════════════════════════════

router.post('/report', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Authentication required' });

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }

    const { reportedUserId, sessionId, reason, description } = req.body;

    const validReasons = ['spam', 'harassment', 'inappropriate_content', 'hate_speech', 'underage', 'threat', 'other'];
    if (!reason) {
      return res.status(400).json({ success: false, message: 'reason is required' });
    }
    if (!validReasons.includes(reason)) {
      return res.status(400).json({ success: false, message: `Invalid reason. Must be one of: ${validReasons.join(', ')}` });
    }

    // ── Resolve the real reported User from the match session ──────────────
    // Flutter sends user2Id = 'device-2' (a placeholder, not a real MongoDB ID).
    // We look up the real partner from the Session document instead.
    let resolvedReportedUser = null;

    if (sessionId) {
      const matchSession = await Session.findOne({ sessionId });
      if (matchSession) {
        // Reporter is user1 or user2 — partner is the other one
        const reporterId = decoded.userId;
        const partnerId  = matchSession.user1?.toString() === reporterId
          ? matchSession.user2
          : matchSession.user1;
        if (partnerId) {
          resolvedReportedUser = await User.findById(partnerId);
        }
      }
    }

    // Fallback: if Flutter sent a valid ObjectId, try that
    if (!resolvedReportedUser && reportedUserId && reportedUserId.match(/^[a-f\d]{24}$/i)) {
      resolvedReportedUser = await User.findById(reportedUserId);
    }

    if (!resolvedReportedUser) {
      // Still flag the session even if we can't identify the user
      if (sessionId) {
        await Promise.all([
          Session.findOneAndUpdate({ sessionId }, { isFlagged: true, flagReason: reason }),
          Message.updateMany({ sessionId }, { retainedForCompliance: true, isFlagged: true }),
        ]);
        console.log(`🚨 Session flagged (anonymous report): ${sessionId}`);
      }
      return res.status(201).json({
        success: true,
        message: 'Report submitted. Our team will review it within 24 hours.',
        data: { reportId: null }
      });
    }

    // ── Reporter's User document (for incrementing reportCount) ───────────
    const reporterUser = await User.findById(decoded.userId);

    // Create the report record
    const report = await Report.create({
      reportedBy:       reporterUser?._id || null,
      reportedUser:     resolvedReportedUser._id,
      reportedUsername: resolvedReportedUser.displayName || resolvedReportedUser.username,
      sessionId:        sessionId || null,
      reason,
      description:      description ? sanitizeString(description, 1000) : '',
      sessionFlagged:   !!sessionId,
      status:           'pending',
    });

    // Flag the Session and all its Messages to prevent TTL deletion
    if (sessionId) {
      await Promise.all([
        Session.findOneAndUpdate({ sessionId }, { isFlagged: true, flagReason: reason }),
        Message.updateMany({ sessionId }, { retainedForCompliance: true, isFlagged: true }),
      ]);
      console.log(`🚨 Report filed — session ${sessionId} flagged for compliance retention`);
    }

    await User.findByIdAndUpdate(resolvedReportedUser._id, { $inc: { reportedCount: 1 } });
    if (reporterUser) {
      await User.findByIdAndUpdate(reporterUser._id, { $inc: { reportCount: 1 } });
    }

    res.status(201).json({
      success: true,
      message: 'Report submitted. Our team will review it within 24 hours.',
      data: { reportId: report._id }
    });
  } catch (error) {
    console.error('❌ Error filing report:', error);
    res.status(500).json({ success: false, message: 'Failed to submit report' });
  }
});

module.exports = router;
