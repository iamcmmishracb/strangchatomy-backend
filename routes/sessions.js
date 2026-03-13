const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const Session = require('../models/Session');
const User = require('../models/User');
const { v4: uuidv4 } = require('uuid');
const { encrypt } = require('../utils/encryption');

const getIp = (req) =>
  req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';

// ═══════════════════════════════════════════════════════════════════════════
// 📱 POST /api/sessions/anonymous - Create Anonymous Session + User
// ═══════════════════════════════════════════════════════════════════════════

router.post('/anonymous', async (req, res) => {
  try {
    const { deviceId, displayName, gender, deviceModel, deviceManufacturer, location } = req.body;

    if (!deviceId || !displayName || !gender) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: deviceId, displayName, gender'
      });
    }

    const validGenders = ['male', 'female', 'other'];
    if (!validGenders.includes(gender.toLowerCase())) {
      return res.status(400).json({
        success: false,
        message: `Invalid gender value: '${gender}'`
      });
    }

    const ip = getIp(req);
    const sessionId = uuidv4();
    const shortId = sessionId.slice(0, 6);

    // Create or reuse User for this device
    // Same device keeps the same user record across reconnects
    let user = await User.findOne({ deviceIds: deviceId, isAnonymous: true });

    if (!user) {
      user = await User.create({
        username:                `${displayName}_${shortId}`,
        displayName:             displayName,
        gender:                  gender.toLowerCase(),
        isAnonymous:             true,
        deviceIds:               [deviceId],
        registrationIpEncrypted: encrypt(ip),
        lastLoginIpEncrypted:    encrypt(ip),
        userAgent:               req.headers['user-agent'] || '',
        isOnline:                false,
      });
      console.log(`✅ User created: ${user.username}`);
    } else {
      user.displayName          = displayName;
      user.lastLoginIpEncrypted = encrypt(ip);
      user.lastActiveAt         = new Date();
      await user.save();
      console.log(`♻️  User reused: ${user.username}`);
    }

    const sessionToken = jwt.sign(
      { sessionId, userId: user._id.toString(), deviceId, displayName, gender: gender.toLowerCase() },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '2h' }
    );

    await Session.create({
      sessionId,
      displayName,
      gender:   gender.toLowerCase(),
      deviceId,
      deviceInfo: {
        model:        deviceModel,
        manufacturer: deviceManufacturer
      },
      location: location ? {
        latitude:  location.latitude,
        longitude: location.longitude,
        accuracy:  location.accuracy,
        timestamp: new Date()
      } : undefined,
      isAnonymous: true,
      status:      'active',
      startedAt:   new Date()
    });

    console.log(`✅ Session created: ${sessionId}`);

    res.status(201).json({
      success: true,
      data: {
        sessionId,
        userId:       user._id,
        sessionToken,
        displayName,
        gender:     gender.toLowerCase(),
        expiresIn:  7200
      }
    });
  } catch (error) {
    console.error('❌ Error creating session:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create session: ' + error.message
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ✅ GET /api/sessions/anonymous/verify - Verify Session Token
// ═══════════════════════════════════════════════════════════════════════════

router.get('/anonymous/verify', (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    res.json({ success: true, message: 'Session valid', data: decoded });
  } catch (error) {
    res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// 🏁 POST /api/sessions/anonymous/end - End Session
// ═══════════════════════════════════════════════════════════════════════════

router.post('/anonymous/end', async (req, res) => {
  try {
    const { sessionId, userId } = req.body;
    if (!sessionId) {
      return res.status(400).json({ success: false, message: 'sessionId required' });
    }
    await Session.findOneAndUpdate(
      { sessionId },
      { status: 'ended', endedAt: new Date() }
    );
    if (userId) {
      await User.findByIdAndUpdate(userId, { isOnline: false, lastSeen: new Date() });
    }
    console.log(`✅ Session ended: ${sessionId}`);
    res.json({ success: true, message: 'Session ended successfully' });
  } catch (error) {
    console.error('❌ Error ending session:', error);
    res.status(500).json({ success: false, message: 'Failed to end session' });
  }
});

module.exports = router;
