#!/usr/bin/env node
/**
 * STVOR Managed Relay Server
 *
 * Endpoints:
 *   GET  /health
 *   POST /register          { user_id, publicKeys }
 *   GET  /public-key/:userId
 *   POST /message           { to, from, ciphertext, header }
 *   GET  /messages/:userId
 *   DELETE /message/:id
 *   GET  /stats
 *   GET  /usage             — quota check
 *
 * Auth: Authorization: Bearer stvor_<token>
 *
 * Env:
 *   PORT              — listen port (default 4444)
 *   STVOR_VERBOSE     — "1" for verbose logs
 *   MAX_MSG_PER_USER  — max queued messages per user (default 500)
 *   MAX_USERS_TOTAL   — max total registered users (default 50000)
 */

import http from 'node:http';
import crypto from 'node:crypto';

const PORT           = parseInt(process.env.PORT || '4444', 10);
const VERBOSE        = process.env.STVOR_VERBOSE === '1';
const MAX_MSG        = parseInt(process.env.MAX_MSG_PER_USER || '500', 10);
const MAX_USERS      = parseInt(process.env.MAX_USERS_TOTAL  || '50000', 10);

const STARTED_AT = new Date().toISOString();

function log(...args) {
  if (VERBOSE) console.log('[relay]', new Date().toISOString(), ...args);
}

// projectId → userId → { publicKeys, messages[], lastActivity, msgCount }
const registry = new Map();
let totalMessages = 0;
let totalUsers = 0;

// Per-project message counters for quota
const projectStats = new Map(); // projectId → { sent, users }

// projectId → groupId → { members: Set, messages[] }
const groupRegistry = new Map();

// ── helpers ──────────────────────────────────────────────────────────────────

function getToken(req) {
  const auth = req.headers['authorization'] ?? '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

function validateToken(token) {
  if (!token || !token.startsWith('stvor_')) return null;
  // Use first 24 chars as project namespace (stable across requests)
  return `proj_${token.replace(/[^a-zA-Z0-9_]/g, '').slice(0, 24)}`;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; if (raw.length > 1_000_000) reject(new Error('Too large')); });
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  });
  res.end(payload);
}

function corsHeaders(res) {
  res.writeHead(204, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  });
  res.end();
}

// ── server ───────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return corsHeaders(res);

  const url   = new URL(req.url ?? '/', `http://localhost:${PORT}`);
  const path  = url.pathname;
  const token = getToken(req);

  try {
    // GET /health
    if (req.method === 'GET' && path === '/health') {
      return send(res, 200, {
        status: 'ok',
        server: 'stvor-relay',
        version: '1.0.0',
        uptime: Math.floor((Date.now() - new Date(STARTED_AT).getTime()) / 1000),
        users: totalUsers,
        messages: totalMessages,
      });
    }

    // GET /usage  — quota info for this token
    if (req.method === 'GET' && path === '/usage') {
      const projectId = validateToken(token);
      if (!projectId) return send(res, 401, { error: 'Invalid token' });
      const stats = projectStats.get(projectId) || { sent: 0, users: 0 };
      return send(res, 200, { used: stats.sent, limit: -1, users: stats.users });
    }

    // GET /stats
    if (req.method === 'GET' && path === '/stats') {
      const projectId = validateToken(token);
      if (!projectId) return send(res, 401, { error: 'Invalid token' });
      let users = 0, pending = 0;
      const project = registry.get(projectId);
      if (project) {
        for (const u of project.values()) { users++; pending += u.messages.length; }
      }
      const ps = projectStats.get(projectId) || { sent: 0, users };
      return send(res, 200, {
        status: 'ok',
        project: { users, pendingMessages: pending, totalSent: ps.sent },
        global: { projects: registry.size, users: totalUsers, messages: totalMessages },
      });
    }

    // POST /register
    if (req.method === 'POST' && path === '/register') {
      const projectId = validateToken(token);
      if (!projectId) return send(res, 401, { error: 'Invalid token' });

      let body;
      try { body = await readBody(req); } catch { return send(res, 400, { error: 'Invalid JSON' }); }

      const { user_id, publicKeys } = body;
      if (!user_id || typeof user_id !== 'string' || user_id.length > 256) {
        return send(res, 400, { error: 'Invalid user_id' });
      }

      if (!registry.has(projectId)) registry.set(projectId, new Map());
      const project = registry.get(projectId);

      const isNew = !project.has(user_id);
      if (isNew && totalUsers >= MAX_USERS) {
        return send(res, 503, { error: 'Server at capacity' });
      }

      const registeredAt = project.has(user_id) ? project.get(user_id).registeredAt : Date.now();
      project.set(user_id, { publicKeys, messages: [], lastActivity: Date.now(), msgCount: 0, registeredAt });

      if (isNew) {
        totalUsers++;
        const ps = projectStats.get(projectId) || { sent: 0, users: 0 };
        ps.users++;
        projectStats.set(projectId, ps);
      }

      log(`register: ${user_id} @ ${projectId}`);
      return send(res, 200, { status: 'registered' });
    }

    // GET /public-key/:userId
    const pkMatch = path.match(/^\/public-key\/(.+)$/);
    if (req.method === 'GET' && pkMatch) {
      const projectId = validateToken(token);
      if (!projectId) return send(res, 401, { error: 'Invalid token' });

      const userId = decodeURIComponent(pkMatch[1]);
      const user = registry.get(projectId)?.get(userId);
      if (!user) return send(res, 404, { error: 'User not found' });

      return send(res, 200, { publicKeys: user.publicKeys });
    }

    // POST /message
    if (req.method === 'POST' && path === '/message') {
      const projectId = validateToken(token);
      if (!projectId) return send(res, 401, { error: 'Invalid token' });

      let body;
      try { body = await readBody(req); } catch { return send(res, 400, { error: 'Invalid JSON' }); }

      const { to, from, ciphertext, header, pqcCt } = body;
      if (!to || !from || !ciphertext || header === undefined) {
        return send(res, 400, { error: 'Missing fields: to, from, ciphertext, header' });
      }
      if (to === from) return send(res, 400, { error: 'Cannot send to yourself' });

      const project = registry.get(projectId);
      const recipient = project?.get(to);
      if (!recipient) return send(res, 404, { error: 'Recipient not found' });

      if (recipient.messages.length >= MAX_MSG) {
        return send(res, 429, { error: 'Recipient inbox full' });
      }

      const id = crypto.randomBytes(12).toString('hex');
      const msg = { id, from, ciphertext, header, timestamp: new Date().toISOString() };
      if (pqcCt) msg.pqcCt = pqcCt;
      recipient.messages.push(msg);
      recipient.lastActivity = Date.now();
      totalMessages++;

      const ps = projectStats.get(projectId) || { sent: 0, users: 0 };
      ps.sent++;
      projectStats.set(projectId, ps);

      log(`msg: ${from} → ${to}`);
      return send(res, 200, { status: 'delivered', messageId: id });
    }

    // GET /messages/:userId
    const msgsMatch = path.match(/^\/messages\/(.+)$/);
    if (req.method === 'GET' && msgsMatch) {
      const projectId = validateToken(token);
      if (!projectId) return send(res, 401, { error: 'Invalid token' });

      const userId = decodeURIComponent(msgsMatch[1]);
      const user = registry.get(projectId)?.get(userId);
      if (!user) return send(res, 404, { error: 'User not found' });

      const messages = user.messages.splice(0);
      user.lastActivity = Date.now();

      log(`fetch: ${messages.length} msgs for ${userId}`);
      return send(res, 200, { messages, count: messages.length });
    }

    // DELETE /message/:id
    const delMatch = path.match(/^\/message\/(.+)$/);
    if (req.method === 'DELETE' && delMatch) {
      const projectId = validateToken(token);
      if (!projectId) return send(res, 401, { error: 'Invalid token' });

      const msgId = decodeURIComponent(delMatch[1]);
      const project = registry.get(projectId);
      if (project) {
        for (const user of project.values()) {
          const idx = user.messages.findIndex((m) => m.id === msgId);
          if (idx !== -1) {
            user.messages.splice(idx, 1);
            return send(res, 200, { status: 'deleted' });
          }
        }
      }
      // 200 even if not found — idempotent delete
      return send(res, 200, { status: 'not_found' });
    }

    // DELETE /user/:userId — GDPR right to erasure
    // Deletes all user data: public keys, queued messages, registration record
    const deleteUserMatch = path.match(/^\/user\/([^/]+)$/);
    if (req.method === 'DELETE' && deleteUserMatch) {
      const projectId = validateToken(token);
      if (!projectId) return send(res, 401, { error: 'Invalid token' });

      const userId = decodeURIComponent(deleteUserMatch[1]);
      const project = registry.get(projectId);
      const user = project?.get(userId);

      if (!user) return send(res, 404, { error: 'User not found' });

      const pendingMessages = user.messages.length;
      project.delete(userId);
      totalUsers = Math.max(0, totalUsers - 1);

      const ps = projectStats.get(projectId);
      if (ps) ps.users = Math.max(0, ps.users - 1);

      log(`GDPR erasure: ${userId} @ ${projectId} (${pendingMessages} messages deleted)`);
      return send(res, 200, {
        status: 'erased',
        userId,
        deletedAt: new Date().toISOString(),
        messagesDeleted: pendingMessages,
      });
    }

    // GET /user/:userId/export — GDPR data portability (Art. 20)
    // Returns what the relay stores about this user (metadata only, no plaintext)
    const exportUserMatch = path.match(/^\/user\/([^/]+)\/export$/);
    if (req.method === 'GET' && exportUserMatch) {
      const projectId = validateToken(token);
      if (!projectId) return send(res, 401, { error: 'Invalid token' });

      const userId = decodeURIComponent(exportUserMatch[1]);
      const user = registry.get(projectId)?.get(userId);

      if (!user) return send(res, 404, { error: 'User not found' });

      return send(res, 200, {
        userId,
        exportedAt: new Date().toISOString(),
        relay: 'relay.stvor.xyz',
        data: {
          // Public keys are public — not sensitive
          publicKeys: user.publicKeys,
          // Metadata the relay holds
          pendingMessages: user.messages.length,
          registeredAt: new Date(user.registeredAt).toISOString(),
          lastActivity: new Date(user.lastActivity).toISOString(),
          // What the relay does NOT store:
          // - Message content (E2EE — relay only has ciphertext)
          // - Sender identity (if sealedSender: true)
          // - Any plaintext data
        },
        notice: 'Message content is end-to-end encrypted. The relay cannot access or export it.',
      });
    }

    // POST /group/:groupId/message — broadcast encrypted message to group members
    const groupMsgMatch = path.match(/^\/group\/([^/]+)\/message$/);
    if (req.method === 'POST' && groupMsgMatch) {
      const projectId = validateToken(token);
      if (!projectId) return send(res, 401, { error: 'Invalid token' });

      let body;
      try { body = await readBody(req); } catch { return send(res, 400, { error: 'Invalid JSON' }); }

      const groupId = decodeURIComponent(groupMsgMatch[1]);
      const { from, members, ciphertext, groupHeader } = body;

      if (!from || !members || !Array.isArray(members) || !ciphertext || !groupHeader) {
        return send(res, 400, { error: 'Missing fields: from, members, ciphertext, groupHeader' });
      }

      const project = registry.get(projectId);
      if (!project) return send(res, 404, { error: 'No users registered' });

      // Deliver to each member's inbox (except sender)
      const delivered = [];
      const failed = [];
      for (const memberId of members) {
        if (memberId === from) continue;
        const member = project.get(memberId);
        if (!member) { failed.push(memberId); continue; }
        if (member.messages.length >= MAX_MSG) { failed.push(memberId); continue; }
        const id = crypto.randomBytes(12).toString('hex');
        member.messages.push({
          id,
          from,
          ciphertext,
          header: '',        // not used for group messages
          groupId,
          groupHeader,
          timestamp: new Date().toISOString(),
        });
        member.lastActivity = Date.now();
        totalMessages++;
        delivered.push(memberId);
      }

      const ps = projectStats.get(projectId) || { sent: 0, users: 0 };
      ps.sent += delivered.length;
      projectStats.set(projectId, ps);

      log(`group msg: ${from} → group:${groupId} (${delivered.length} delivered, ${failed.length} failed)`);
      return send(res, 200, { status: 'delivered', delivered, failed });
    }

    return send(res, 404, { error: 'Not found' });

  } catch (err) {
    console.error('[relay] error:', err);
    return send(res, 500, { error: 'Internal server error' });
  }
});

// Cleanup stale users every 30 minutes (older than 24h with no activity)
setInterval(() => {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const [projectId, project] of registry.entries()) {
    for (const [userId, user] of project.entries()) {
      if (user.lastActivity < cutoff && user.messages.length === 0) {
        project.delete(userId);
        totalUsers = Math.max(0, totalUsers - 1);
      }
    }
    if (project.size === 0) registry.delete(projectId);
  }
}, 30 * 60 * 1000);

server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ╔════════════════════════════════════╗');
  console.log('  ║     STVOR Managed Relay v1.0       ║');
  console.log('  ╚════════════════════════════════════╝');
  console.log('');
  console.log(`  Listening:  http://0.0.0.0:${PORT}`);
  console.log(`  Health:     http://0.0.0.0:${PORT}/health`);
  console.log(`  Started:    ${STARTED_AT}`);
  console.log('');
});

process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
process.on('SIGINT',  () => { server.close(() => process.exit(0)); });
