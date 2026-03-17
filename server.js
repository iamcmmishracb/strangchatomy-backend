require('dotenv').config();

// ── Startup guard: fail fast if critical env vars are missing in production ──
if (process.env.NODE_ENV === 'production') {
  const required = ['JWT_SECRET', 'ENCRYPTION_KEY', 'MONGODB_URI', 'APP_SECRET'];
  const missing  = required.filter(k => !process.env[k]);
  if (missing.length > 0) {
    console.error(`❌ FATAL: Missing required env vars in production: ${missing.join(', ')}`);
    process.exit(1);
  }
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    console.error('❌ FATAL: JWT_SECRET must be at least 32 characters in production');
    process.exit(1);
  }
  if (process.env.ENCRYPTION_KEY && process.env.ENCRYPTION_KEY.length !== 32) {
    console.error('❌ FATAL: ENCRYPTION_KEY must be exactly 32 characters');
    process.exit(1);
  }
}

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);

// Models - available after mongoose connects
let Session, User, Message;

const isProduction = process.env.NODE_ENV === 'production';

// ═══════════════════════════════════════════════════════════════════════════
// 🔗 WEBSOCKET SERVER
// ═══════════════════════════════════════════════════════════════════════════

const wss = new WebSocket.Server({ server, path: '/ws' });

const waitingQueue  = [];
const activeMatches = {};
const connectedUsers = {}; // sessionId → ws

console.log('🔌 WebSocket server initialized');

wss.on('connection', (ws, req) => {
  let sessionId   = null;
  let userId      = null;
  let displayName = null;
  let gender      = null;
  // Capture IP at connection time for per-session encryption (Gap 1 fix)
  const clientIp  = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';

  // First message must carry the JWT token
  ws.once('message', async (raw) => {
    try {
      const data = JSON.parse(raw);

      // App key check - only enforced in production
      if (isProduction && process.env.APP_SECRET) {
        if (data.appKey !== process.env.APP_SECRET) {
          ws.send(JSON.stringify({ error: 'Invalid app key' }));
          ws.close();
          return;
        }
      }

      if (!data.token) {
        ws.send(JSON.stringify({ error: 'No token provided' }));
        ws.close();
        return;
      }

      const decoded = jwt.verify(data.token, process.env.JWT_SECRET);
      sessionId   = decoded.sessionId;
      userId      = decoded.userId;
      displayName = decoded.displayName;
      gender      = decoded.gender;

      console.log(`✅ WS authenticated: ${displayName} (${sessionId.slice(0, 8)}...)`);

      connectedUsers[sessionId] = ws;

      // Mark user online
      if (User && userId) {
        User.findByIdAndUpdate(userId, { isOnline: true, lastActiveAt: new Date() })
          .catch(e => console.error('User online update error:', e.message));
      }

      ws.send(JSON.stringify({ type: 'authenticated', message: 'Connected successfully' }));

      ws.on('message', (msg) => handleMessage(sessionId, userId, displayName, gender, clientIp, msg));

    } catch (err) {
      console.error('❌ WS auth failed:', err.message);
      ws.send(JSON.stringify({ error: 'Invalid token' }));
      ws.close();
    }
  });

  // Disconnect
  ws.on('close', async () => {
    if (!sessionId) return;
    console.log(`🔌 Disconnected: ${displayName}`);
    delete connectedUsers[sessionId];

    // Mark user offline
    if (User && userId) {
      User.findByIdAndUpdate(userId, { isOnline: false, lastSeen: new Date() })
        .catch(e => console.error('User offline update error:', e.message));
    }

    // Remove from waiting queue
    const qi = waitingQueue.findIndex(u => u.sessionId === sessionId);
    if (qi !== -1) waitingQueue.splice(qi, 1);

    // End active match if any
    const matchId = Object.keys(activeMatches).find(
      id => activeMatches[id].user1.sessionId === sessionId ||
            activeMatches[id].user2.sessionId === sessionId
    );

    if (matchId) {
      const match   = activeMatches[matchId];
      const other   = match.user1.sessionId === sessionId ? match.user2 : match.user1;
      const otherWs = connectedUsers[other.sessionId];

      if (otherWs) {
        otherWs.send(JSON.stringify({
          type:    'chat_ended',
          reason:  'Partner disconnected',
          message: 'Your chat partner left'
        }));
      }

      delete activeMatches[matchId];
      console.log(`🏁 Match ended (disconnect): ${matchId}`);

      if (Session) {
        Session.findOneAndUpdate(
          { sessionId: matchId },
          { status: 'ended', endedAt: new Date(), endReason: 'disconnected' }
        ).catch(e => console.error('Session end error:', e.message));
      }
    }
  });

  ws.on('error', (err) => console.error(`❌ WS error: ${err.message}`));
});

// Message router
function handleMessage(sessionId, userId, displayName, gender, clientIp, raw) {
  try {
    const data      = JSON.parse(raw);
    const eventType = data.type;

    if      (eventType === 'find_match')   handleFindMatch(sessionId, userId, displayName, gender, clientIp);
    else if (eventType === 'send_message') handleSendMessage(sessionId, data);
    else if (eventType === 'cancel_match') handleCancelMatch(sessionId);
    else if (eventType === 'typing')       handleTyping(sessionId, data);
    else if (eventType === 'end_chat')     handleEndChat(sessionId);
    else if (eventType === 'flag_message') handleFlagMessage(sessionId, userId, data); // Gap 5
  } catch (err) {
    console.error('❌ Message handling error:', err.message);
  }
}

// find_match
async function handleFindMatch(sessionId, userId, displayName, gender, clientIp) {
  console.log(`🔍 Finding match: ${displayName}`);

  if (waitingQueue.length > 0) {
    const waiting = waitingQueue.shift();
    const matchId = `match-${Date.now()}`;

    const matchInfo = {
      matchId,
      user1: { sessionId: waiting.sessionId, userId: waiting.userId, displayName: waiting.displayName, gender: waiting.gender },
      user2: { sessionId, userId, displayName, gender },
      startedAt: new Date()
    };
    activeMatches[matchId] = matchInfo;

    console.log(`✅ MATCH: ${waiting.displayName} ↔️ ${displayName}`);

    // Save match session to MongoDB — encrypt both IPs for LE compliance (IT Act Sec. 69)
    if (Session) {
      const { encrypt } = require('./utils/encryption');
      Session.create({
        sessionId:        matchId,
        user1:            waiting.userId || undefined,
        user2:            userId         || undefined,
        user1Username:    waiting.displayName,
        user2Username:    displayName,
        user1IpEncrypted: waiting.clientIp ? encrypt(waiting.clientIp) : undefined,
        user2IpEncrypted: clientIp         ? encrypt(clientIp)         : undefined,
        status:           'active',
        isAnonymous:      true,
        startedAt:        new Date()
      }).catch(e => console.error('Match session save error:', e.message));
    }

    // Update totalChats for both users
    if (User) {
      if (waiting.userId) User.findByIdAndUpdate(waiting.userId, { $inc: { totalChats: 1 } }).catch(() => {});
      if (userId)         User.findByIdAndUpdate(userId,         { $inc: { totalChats: 1 } }).catch(() => {});
    }

    // Notify both users
    const wsWaiting = connectedUsers[waiting.sessionId];
    const wsCurrent = connectedUsers[sessionId];

    if (wsWaiting) {
      wsWaiting.matchId = matchId;
      wsWaiting.send(JSON.stringify({
        type:          'match_found',
        sessionId:     matchId,
        partnerName:   displayName,
        partnerGender: gender,
        message:       `Connected with ${displayName}!`
      }));
    }

    if (wsCurrent) {
      wsCurrent.matchId = matchId;
      wsCurrent.send(JSON.stringify({
        type:          'match_found',
        sessionId:     matchId,
        partnerName:   waiting.displayName,
        partnerGender: waiting.gender,
        message:       `Connected with ${waiting.displayName}!`
      }));
    }

  } else {
    waitingQueue.push({ sessionId, userId, displayName, gender, clientIp, addedAt: new Date() });
    console.log(`⏳ Queued: ${displayName} (queue size: ${waitingQueue.length})`);

    const ws = connectedUsers[sessionId];
    if (ws) {
      ws.send(JSON.stringify({
        type:          'waiting_for_match',
        message:       'Waiting for someone to match with...',
        queuePosition: waitingQueue.length
      }));
    }
  }
}

// send_message
function handleSendMessage(sessionId, data) {
  const ws = connectedUsers[sessionId];
  if (!ws?.matchId) { console.log('⚠️ No active match'); return; }

  const match = activeMatches[ws.matchId];
  if (!match) return;

  const receiver   = match.user1.sessionId === sessionId ? match.user2 : match.user1;
  const receiverWs = connectedUsers[receiver.sessionId];

  // Relay to partner immediately (before DB write so UI feels instant)
  if (receiverWs) {
    receiverWs.send(JSON.stringify({
      type:      'new_message',
      sessionId: ws.matchId,
      content:   data.content,
      senderId:  sessionId,
      timestamp: new Date()
    }));
  }

  // ── Persist encrypted message (every message, not just flagged ones) ──
  if (Message) {
    const { encrypt } = require('./utils/encryption');
    const sender = match.user1.sessionId === sessionId ? match.user1 : match.user2;
    const contentEncrypted = encrypt(data.content || '');
    if (contentEncrypted) {
      Message.create({
        sessionId:        ws.matchId,
        senderId:         sender.userId   || undefined,
        senderUsername:   sender.displayName,
        contentEncrypted,
        type:             data.messageType || 'text',
      }).catch(e => console.error('❌ Message save error:', e.message));
    }
  }

  // Increment counters
  if (Session) {
    Session.findOneAndUpdate({ sessionId: ws.matchId }, { $inc: { messageCount: 1 } }).catch(() => {});
  }
  if (User) {
    const userObj = match.user1.sessionId === sessionId ? match.user1 : match.user2;
    if (userObj.userId) {
      User.findByIdAndUpdate(userObj.userId, { $inc: { totalMessages: 1 } }).catch(() => {});
    }
  }
}

// cancel_match
function handleCancelMatch(sessionId) {
  const qi = waitingQueue.findIndex(u => u.sessionId === sessionId);
  if (qi !== -1) {
    waitingQueue.splice(qi, 1);
    console.log(`❌ Cancelled: ${sessionId.slice(0, 8)}...`);
  }
}

// typing
function handleTyping(sessionId, data) {
  const ws = connectedUsers[sessionId];
  if (!ws?.matchId) return;

  const match = activeMatches[ws.matchId];
  if (!match) return;

  const receiver   = match.user1.sessionId === sessionId ? match.user2 : match.user1;
  const receiverWs = connectedUsers[receiver.sessionId];
  if (receiverWs) {
    receiverWs.send(JSON.stringify({ type: 'partner_typing', isTyping: data.isTyping }));
  }
}

// end_chat
function handleEndChat(sessionId) {
  const ws = connectedUsers[sessionId];
  if (!ws?.matchId) return;

  const matchId = ws.matchId;
  const match   = activeMatches[matchId];
  if (!match) return;

  const receiver   = match.user1.sessionId === sessionId ? match.user2 : match.user1;
  const receiverWs = connectedUsers[receiver.sessionId];

  if (receiverWs) {
    receiverWs.send(JSON.stringify({
      type:    'chat_ended',
      reason:  'User ended chat',
      message: 'Chat ended by partner'
    }));
  }

  delete activeMatches[matchId];
  console.log(`🏁 Chat ended: ${matchId}`);

  if (Session) {
    Session.findOneAndUpdate(
      { sessionId: matchId },
      { status: 'ended', endedAt: new Date(), endReason: 'user_left' }
    ).catch(e => console.error('Session end error:', e.message));
  }
}

// flag_message (Gap 5)
// Marks a specific message as flagged in the database so the admin
// panel can surface it for review and the TTL won't auto-delete it.
async function handleFlagMessage(sessionId, userId, data) {
  try {
    const { messageId } = data;
    if (!messageId) { console.warn('⚠️ flag_message: missing messageId'); return; }
    if (!Message)   { console.warn('⚠️ flag_message: Message model not ready'); return; }

    // Only flag messages that belong to the caller's current match session
    const ws      = connectedUsers[sessionId];
    const matchId = ws?.matchId;

    await Message.findOneAndUpdate(
      { _id: messageId, ...(matchId && { sessionId: matchId }) },
      {
        isFlagged:             true,
        retainedForCompliance: true,
      }
    );

    // Also flag the parent session so admin can find it in Reports view
    if (matchId && Session) {
      Session.findOneAndUpdate(
        { sessionId: matchId },
        { isFlagged: true, flagReason: 'message_flagged_by_user' }
      ).catch(() => {});
    }

    console.log(`🚩 Message flagged: ${messageId}  by session: ${sessionId}`);
  } catch (err) {
    console.error('❌ flag_message handler error:', err.message);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPRESS MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════════

app.use(helmet({ contentSecurityPolicy: false }));

// ── CORS: restrict to known frontend origin in production ──────────────────
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : [];
app.use(cors({
  origin: (origin, callback) => {
    if (!isProduction) return callback(null, true); // dev: allow all
    if (!origin) return callback(null, false);       // disallow no-origin in prod
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: Origin '${origin}' not allowed`));
  },
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: 'Too many requests' });
app.use('/api/', limiter);

// Static admin panel
app.use(express.static(path.join(__dirname, 'admin')));

// Session endpoints - app key only enforced in production
const { appKeyProtect } = require('./middleware/appKey');
app.use('/api/sessions', appKeyProtect, require('./routes/sessions'));

// Admin routes
app.use('/api/admin', require('./routes/admin'));

// Admin panel SPA (secured URL)
app.get('/cbmishra',   (req, res) => res.sendFile(path.join(__dirname, 'admin', 'index.html')));
app.get('/cbmishra/*', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'index.html')));

// Privacy Policy
app.get('/privacy-policy', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Privacy Policy - Strangchatomy</title>
<style>
  body { font-family: Arial, sans-serif; max-width: 860px; margin: 40px auto; padding: 0 24px 60px; color: #333; line-height: 1.8; font-size: 15px; }
  h1 { color: #6c63ff; font-size: 28px; margin-bottom: 4px; }
  h2 { color: #333; font-size: 17px; margin-top: 36px; margin-bottom: 8px; border-left: 4px solid #6c63ff; padding-left: 12px; }
  p { margin: 8px 0; }
  ul { margin: 8px 0 8px 20px; }
  li { margin-bottom: 6px; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 14px; }
  th { background: #6c63ff; color: white; padding: 10px 14px; text-align: left; }
  td { padding: 9px 14px; border-bottom: 1px solid #e0e0e0; vertical-align: top; }
  tr:nth-child(even) td { background: #f9f8ff; }
  .badge { display: inline-block; background: #f0eeff; color: #6c63ff; border-radius: 4px; padding: 2px 8px; font-size: 13px; font-weight: 600; }
  .note { background: #fff8e1; border-left: 4px solid #ffc107; padding: 10px 14px; border-radius: 4px; font-size: 14px; margin: 12px 0; }
  a { color: #6c63ff; }
  .updated { color: #888; font-size: 13px; }
</style>
</head>
<body>

<h1>Privacy Policy</h1>
<p class="updated">Last updated: March 14, 2026</p>

<p>Strangchatomy ("we", "us", or "our") is operated by Learneducamy Apps and provides an anonymous random chat platform available as a mobile application and website (collectively, the "Service"). This Privacy Policy explains what data we collect, why we collect it, how we use and protect it, and your rights over it.</p>

<p>By using the Service, you agree to the collection and use of information as described in this policy.</p>

<div class="note">⚠️ This app is intended for users aged <strong>18 years and above only</strong>. We do not knowingly collect data from anyone under 18.</div>

<h2>1. Data We Collect</h2>
<p>The following table lists every category of data collected by Strangchatomy, why it is collected, and how it is stored:</p>

<table>
  <tr><th>Data Category</th><th>Specific Data Points</th><th>Purpose</th><th>Storage</th></tr>
  <tr>
    <td><strong>Identity</strong></td>
    <td>Display name (nickname chosen by you), gender (chosen by you)</td>
    <td>To identify you in chat sessions and match you with partners</td>
    <td>Plain text, deleted after 90 days</td>
  </tr>
  <tr>
    <td><strong>Device Information</strong></td>
    <td>Device ID (Android ID / iOS Vendor ID), device model, manufacturer, User-Agent string</td>
    <td>To prevent ban evasion, detect multi-accounting, and ensure platform safety</td>
    <td>Plain text, deleted after 90 days</td>
  </tr>
  <tr>
    <td><strong>Network Information</strong></td>
    <td>IP address at registration, IP address at last login</td>
    <td>Platform safety, fraud prevention, legal compliance</td>
    <td>AES-256 encrypted, deleted after 90 days</td>
  </tr>
  <tr>
    <td><strong>Location</strong></td>
    <td>GPS latitude, longitude, accuracy (in metres), timestamp of capture</td>
    <td>Optional feature — only collected if you grant location permission. Used for region-based matching.</td>
    <td>Plain text, deleted after 90 days</td>
  </tr>
  <tr>
    <td><strong>Chat Messages</strong></td>
    <td>All text messages sent during chat sessions</td>
    <td>To deliver messages in real time and store for safety/legal compliance</td>
    <td>AES-256 encrypted at rest, deleted after 90 days</td>
  </tr>
  <tr>
    <td><strong>Session Data</strong></td>
    <td>Session ID, start time, end time, duration, partner display name, message count</td>
    <td>Platform analytics, moderation, and legal compliance</td>
    <td>Plain text, deleted after 90 days</td>
  </tr>
  <tr>
    <td><strong>Reports &amp; Moderation</strong></td>
    <td>Reports filed by or against you, ban records and reasons</td>
    <td>To enforce our Terms of Service and maintain a safe platform</td>
    <td>Retained until resolved, then deleted</td>
  </tr>
  <tr>
    <td><strong>Consent Record</strong></td>
    <td>Timestamp when you accepted our Terms of Service</td>
    <td>Legal compliance under DPDP Act 2023</td>
    <td>Retained for the life of the session record</td>
  </tr>
</table>

<p><strong>We do NOT collect:</strong> email address, phone number, government ID, passwords, payment information, contacts, photos, or microphone/camera data outside of active audio/video call sessions.</p>

<h2>2. Audio and Video Calls</h2>
<p>Strangchatomy uses <strong>Agora RTC Engine</strong> (a third-party service) to power audio and video calls. During a call:</p>
<ul>
  <li>Audio and video streams are transmitted directly via Agora's infrastructure.</li>
  <li>We do not record, store, or process audio or video content.</li>
  <li>Agora may collect technical data such as call quality metrics. Please refer to <a href="https://www.agora.io/en/privacy-policy/" target="_blank">Agora's Privacy Policy</a> for details.</li>
</ul>

<h2>3. How We Use Your Data</h2>
<ul>
  <li>To match you anonymously with a random chat partner</li>
  <li>To deliver real-time chat messages via WebSocket</li>
  <li>To detect and prevent abuse, ban evasion, and policy violations</li>
  <li>To respond to user reports and take moderation action</li>
  <li>To comply with applicable Indian law including the IT Act 2000, CrPC Section 91, and DPDP Act 2023</li>
</ul>

<h2>4. Data Sharing</h2>
<p>We do <strong>not</strong> sell, rent, or share your personal data with third parties for advertising or marketing purposes.</p>
<p>We may share data in the following limited circumstances:</p>
<ul>
  <li><strong>Law Enforcement:</strong> If required by a valid court order, government directive, or legal process under applicable Indian law (IT Act 2000, Section 69; CrPC Section 91; DPDP Act 2023). All such disclosures are logged with timestamp and reason.</li>
  <li><strong>Agora RTC:</strong> Technical call data is processed by Agora solely to deliver audio/video functionality.</li>
</ul>

<h2>5. Data Retention</h2>
<p>All user data, messages, and session records are automatically deleted after <strong>90 days</strong> from creation, unless:</p>
<ul>
  <li>The session or user is under an active legal hold (court order or law enforcement request)</li>
  <li>The session has been flagged for moderation review and the review is not yet complete</li>
</ul>

<h2>6. Data Security</h2>
<ul>
  <li>All chat messages are stored using <span class="badge">AES-256 encryption</span> at rest</li>
  <li>All IP addresses are stored using <span class="badge">AES-256 encryption</span> at rest</li>
  <li>All data is transmitted over <span class="badge">HTTPS / WSS (TLS)</span></li>
  <li>Admin access requires authentication with short-lived JWT tokens</li>
  <li>All law enforcement data exports are logged with admin identity and timestamp</li>
</ul>

<h2>7. Your Rights (DPDP Act 2023)</h2>
<p>Under the Digital Personal Data Protection Act 2023 (India), you have the right to:</p>
<ul>
  <li><strong>Access</strong> — request a copy of data we hold about you</li>
  <li><strong>Correction</strong> — request correction of inaccurate data</li>
  <li><strong>Erasure</strong> — request deletion of your data (processed within 30 days)</li>
  <li><strong>Grievance Redressal</strong> — raise a complaint with our Grievance Officer</li>
</ul>
<p>To exercise any of these rights, contact us at the email below.</p>

<h2>8. Children's Privacy</h2>
<p>Strangchatomy is strictly intended for users <strong>18 years of age and older</strong>. We do not knowingly collect personal data from anyone under 18. If we become aware that a minor has used the Service, we will immediately delete their data and terminate their access.</p>

<h2>9. Changes to This Policy</h2>
<p>We may update this Privacy Policy from time to time. We will notify users of significant changes by updating the "Last updated" date at the top of this page. Continued use of the Service after changes constitutes acceptance of the updated policy.</p>

<h2>10. Contact Us</h2>
<p>For any privacy-related questions, data requests, or grievances, please contact us at:</p>
<p><strong>Email:</strong> <a href="mailto:learneducamy@gmail.com">learneducamy@gmail.com</a></p>
<p>We will respond to all requests within <strong>30 days</strong>.</p>

</body>
</html>`);
});

// Health check
app.get('/', (req, res) => res.json({
  status:  'ok',
  message: '🚀 RandomChat Server Running',
  version: '2.0.0',
  time:    new Date()
}));

// ═══════════════════════════════════════════════════════════════════════════
// DATABASE + SERVER START
// ═══════════════════════════════════════════════════════════════════════════

const seedAdmin = async () => {
  const Admin = require('./models/Admin');
  const existing = await Admin.findOne({ username: process.env.ADMIN_USERNAME || 'admin' });
  if (!existing) {
    await Admin.create({
      username: process.env.ADMIN_USERNAME || 'admin',
      email:    'admin@randomchat.app',
      password: process.env.ADMIN_PASSWORD || 'Admin@123',
      role:     'superadmin'
    });
    console.log('✅ Default superadmin created');
  }
};

const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log('✅ MongoDB connected');
    Session = require('./models/Session');
    User    = require('./models/User');
    Message = require('./models/Message');
    await seedAdmin();
    server.listen(PORT, () => {
      console.log(`🚀 Server running at http://localhost:${PORT}`);
      console.log(`🎛️  Admin panel at http://localhost:${PORT}/admin`);
      console.log(`🔐 App key protection: ${isProduction ? 'ENABLED (production)' : 'DISABLED (development)'}`);
    });
  })
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });
