import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import express, { type NextFunction, type Request, type Response } from 'express';
import { WebSocket, WebSocketServer } from 'ws';
import 'dotenv/config';
import {
  deleteAllMessages,
  deleteMessagesByIds,
  insertMessage,
  listActiveMessages,
  purgeExpiredMessages,
  RETENTION_DAYS,
  type UserRole,
} from './server/db.ts';
import {
  areDbCodesOverridingEnv,
  canClaimOverride,
  claimInitialAccessCodes,
  createSessionToken,
  hasResetSecret,
  isEnvConfigured,
  isSetupRequired,
  reconfigureAccessCodes,
  revertToEnvAccessCodes,
  sanitizeUsername,
  verifyAccessCode,
  verifyOwnerOrResetCredential,
  verifySessionToken,
  type SessionUser,
} from './server/auth.ts';

interface AuthenticatedRequest extends Request {
  user?: SessionUser;
}

interface ConnectedClient {
  connectionId: string;
  socket: WebSocket;
  user: SessionUser;
  lastMessageAt: number;
}

const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

// Sliding-window rate limiter for auth endpoints
const authAttempts = new Map<string, number[]>();
const AUTH_WINDOW_MS = 5 * 60 * 1000;
const AUTH_MAX_ATTEMPTS = 20;

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const timestamps = (authAttempts.get(ip) ?? []).filter((t) => now - t < AUTH_WINDOW_MS);
  if (timestamps.length >= AUTH_MAX_ATTEMPTS) {
    authAttempts.set(ip, timestamps);
    return true;
  }
  timestamps.push(now);
  authAttempts.set(ip, timestamps);
  return false;
}

function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }
  const token = authHeader.slice(7).trim();
  const user = verifySessionToken(token);
  if (!user) {
    res.status(401).json({ error: 'Session expired or invalid.' });
    return;
  }
  req.user = user;
  next();
}

function requireOwner(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  if (!req.user || req.user.role !== 'owner') {
    res.status(403).json({ error: 'Owner permissions are required for this action.' });
    return;
  }
  next();
}

function sanitizeMessageContent(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const cleaned = raw.replace(/\r\n/g, '\n').trim();
  if (cleaned.length === 0 || cleaned.length > 2000) {
    return null;
  }
  return cleaned;
}

function validateNewCodePair(
  memberCode: unknown,
  ownerCode: unknown
): { ok: true; memberCode: string; ownerCode: string } | { ok: false; error: string } {
  const trimmedMember = typeof memberCode === 'string' ? memberCode.trim() : '';
  const trimmedOwner = typeof ownerCode === 'string' ? ownerCode.trim() : '';
  if (trimmedMember.length < 4) {
    return { ok: false, error: 'Member access code must be at least 4 characters.' };
  }
  if (trimmedOwner.length < 6) {
    return { ok: false, error: 'Owner admin code must be at least 6 characters.' };
  }
  if (trimmedMember === trimmedOwner) {
    return {
      ok: false,
      error: 'Owner admin code must be different from the member access code.',
    };
  }
  return { ok: true, memberCode: trimmedMember, ownerCode: trimmedOwner };
}

async function startServer() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '64kb' }));

  // Purge any expired messages on startup and every 15 minutes
  purgeExpiredMessages();
  const cleanupTimer = setInterval(() => {
    purgeExpiredMessages();
  }, 15 * 60 * 1000);
  cleanupTimer.unref();

  const clients = new Map<WebSocket, ConnectedClient>();

  function getOnlineUsers(): { connectionId: string; username: string; role: UserRole }[] {
    return Array.from(clients.values()).map((c) => ({
      connectionId: c.connectionId,
      username: c.user.username,
      role: c.user.role,
    }));
  }

  function broadcastToAll(payload: unknown): void {
    const serialized = JSON.stringify(payload);
    for (const [ws] of clients) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(serialized);
      }
    }
  }

  // Health check
  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  // Public auth status (never returns codes or hashes)
  app.get('/api/auth/status', (_req, res) => {
    res.json({
      needsSetup: isSetupRequired(),
      envConfigured: isEnvConfigured(),
      canClaimOverride: canClaimOverride(),
      hasResetSecret: hasResetSecret(),
      usingCustomOverride: areDbCodesOverridingEnv(),
      retentionDays: RETENTION_DAYS,
    });
  });

  // One-time first-run setup when environment secrets are not yet configured
  app.post('/api/auth/bootstrap', (req, res) => {
    const ip = getClientIp(req);
    if (isRateLimited(ip)) {
      res.status(429).json({ error: 'Too many attempts. Please wait a few minutes.' });
      return;
    }

    if (!isSetupRequired()) {
      res.status(409).json({ error: 'Access codes are already configured.' });
      return;
    }

    const { username, memberCode, ownerCode } = req.body ?? {};
    const validated = validateNewCodePair(memberCode, ownerCode);
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const claimed = claimInitialAccessCodes(validated.memberCode, validated.ownerCode, false);
    if (!claimed) {
      res.status(409).json({ error: 'Access codes were already claimed.' });
      return;
    }

    const finalUsername = sanitizeUsername(username);
    const token = createSessionToken(finalUsername, 'owner');
    res.status(201).json({
      token,
      user: {
        username: finalUsername,
        role: 'owner' as UserRole,
      },
      retentionDays: RETENTION_DAYS,
    });
  });

  // One-time claim override when environment secrets are present and no DB codes have been claimed yet
  app.post('/api/auth/claim-override', (req, res) => {
    const ip = getClientIp(req);
    if (isRateLimited(ip)) {
      res.status(429).json({ error: 'Too many attempts. Please wait a few minutes.' });
      return;
    }

    if (!canClaimOverride()) {
      res.status(409).json({
        error: 'Custom access codes have already been claimed. Verify with the current owner code to reconfigure.',
      });
      return;
    }

    const { username, memberCode, ownerCode } = req.body ?? {};
    const validated = validateNewCodePair(memberCode, ownerCode);
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const claimed = claimInitialAccessCodes(validated.memberCode, validated.ownerCode, true);
    if (!claimed) {
      res.status(409).json({ error: 'Access codes were already claimed.' });
      return;
    }

    const finalUsername = sanitizeUsername(username);
    const token = createSessionToken(finalUsername, 'owner');
    res.status(201).json({
      token,
      user: {
        username: finalUsername,
        role: 'owner' as UserRole,
      },
      retentionDays: RETENTION_DAYS,
    });
  });

  // Reconfigure both codes from login screen by verifying current owner code or NEXUS_RESET_CODE
  app.post('/api/auth/reconfigure-with-owner', (req, res) => {
    const ip = getClientIp(req);
    if (isRateLimited(ip)) {
      res.status(429).json({ error: 'Too many attempts. Please wait a few minutes.' });
      return;
    }

    const { username, currentCredential, memberCode, ownerCode } = req.body ?? {};
    if (typeof currentCredential !== 'string' || currentCredential.trim().length === 0) {
      res.status(400).json({ error: 'Current owner or reset code is required.' });
      return;
    }

    if (!verifyOwnerOrResetCredential(currentCredential)) {
      res.status(401).json({ error: 'Current owner or reset code is invalid.' });
      return;
    }

    const validated = validateNewCodePair(memberCode, ownerCode);
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const saved = reconfigureAccessCodes(validated.memberCode, validated.ownerCode);
    if (!saved) {
      res.status(500).json({ error: 'Failed to save new access codes.' });
      return;
    }

    const finalUsername = sanitizeUsername(username);
    const token = createSessionToken(finalUsername, 'owner');
    res.json({
      token,
      user: {
        username: finalUsername,
        role: 'owner' as UserRole,
      },
      retentionDays: RETENTION_DAYS,
    });
  });

  // Authenticated owner-only reconfiguration inside the chat workspace
  app.post('/api/auth/reconfigure', requireAuth, requireOwner, (req: AuthenticatedRequest, res) => {
    const { memberCode, ownerCode } = req.body ?? {};
    const validated = validateNewCodePair(memberCode, ownerCode);
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const saved = reconfigureAccessCodes(validated.memberCode, validated.ownerCode);
    if (!saved) {
      res.status(500).json({ error: 'Failed to save new access codes.' });
      return;
    }

    res.json({ ok: true, usingCustomOverride: areDbCodesOverridingEnv() });
  });

  // Authenticated owner-only revert back to environment secrets
  app.post('/api/auth/revert-env-codes', requireAuth, requireOwner, (_req, res) => {
    if (!isEnvConfigured()) {
      res.status(400).json({ error: 'No environment access codes are configured.' });
      return;
    }
    revertToEnvAccessCodes();
    res.json({ ok: true, usingCustomOverride: false });
  });

  // Login with optional username + access code
  app.post('/api/auth/login', (req, res) => {
    const ip = getClientIp(req);
    if (isRateLimited(ip)) {
      res.status(429).json({ error: 'Too many login attempts. Please wait a few minutes.' });
      return;
    }

    if (isSetupRequired()) {
      res.status(409).json({ error: 'Room access codes have not been initialized yet.' });
      return;
    }

    const { username, accessCode } = req.body ?? {};
    if (typeof accessCode !== 'string' || accessCode.trim().length === 0) {
      res.status(400).json({ error: 'Access code is required.' });
      return;
    }

    const role = verifyAccessCode(accessCode);
    if (!role) {
      res.status(401).json({ error: 'Invalid access code.' });
      return;
    }

    const finalUsername = sanitizeUsername(username);
    const token = createSessionToken(finalUsername, role);
    res.json({
      token,
      user: {
        username: finalUsername,
        role,
      },
      retentionDays: RETENTION_DAYS,
    });
  });

  // Verify active token
  app.get('/api/auth/me', requireAuth, (req: AuthenticatedRequest, res) => {
    res.json({
      user: {
        username: req.user!.username,
        role: req.user!.role,
      },
      retentionDays: RETENTION_DAYS,
    });
  });

  // Fetch non-expired messages
  app.get('/api/messages', requireAuth, (_req, res) => {
    const messages = listActiveMessages();
    res.json({ messages, retentionDays: RETENTION_DAYS });
  });

  // REST fallback for sending a message (also broadcasts to all WS clients)
  app.post('/api/messages', requireAuth, (req: AuthenticatedRequest, res) => {
    const content = sanitizeMessageContent(req.body?.content);
    if (!content) {
      res.status(400).json({ error: 'Message must be between 1 and 2,000 characters.' });
      return;
    }

    const message = insertMessage({
      id: crypto.randomUUID(),
      senderName: req.user!.username,
      senderRole: req.user!.role,
      content,
    });

    broadcastToAll({ type: 'message:created', message });
    res.status(201).json({ message });
  });

  // Owner-only: delete selected messages
  app.post(
    '/api/messages/bulk-delete',
    requireAuth,
    requireOwner,
    (req: AuthenticatedRequest, res) => {
      const rawIds = req.body?.ids;
      if (!Array.isArray(rawIds) || rawIds.length === 0 || rawIds.length > 500) {
        res.status(400).json({ error: 'Select between 1 and 500 messages to delete.' });
        return;
      }

      const ids = rawIds.filter((id): id is string => typeof id === 'string' && id.length <= 64);
      if (ids.length === 0) {
        res.status(400).json({ error: 'No valid message IDs provided.' });
        return;
      }

      const deletedCount = deleteMessagesByIds(ids);
      broadcastToAll({ type: 'messages:deleted', ids });
      res.json({ deletedCount, ids });
    }
  );

  // Owner-only: delete all messages
  app.delete('/api/messages', requireAuth, requireOwner, (_req, res) => {
    const deletedCount = deleteAllMessages();
    broadcastToAll({ type: 'messages:deleted', all: true });
    res.json({ deletedCount, all: true });
  });

  const httpServer = http.createServer(app);
  const wss = new WebSocketServer({ noServer: true });

  httpServer.on('upgrade', (request, socket, head) => {
    const urlPath = request.url?.split('?')[0];
    if (urlPath === '/ws') {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    } else if (isProduction) {
      socket.destroy();
    }
  });

  wss.on('connection', (ws) => {
    const authTimeout = setTimeout(() => {
      if (!clients.has(ws) && ws.readyState === WebSocket.OPEN) {
        ws.close(4001, 'Authentication timeout');
      }
    }, 5000);

    ws.on('message', (rawData) => {
      let data: { type?: unknown; token?: unknown; content?: unknown };
      try {
        data = JSON.parse(rawData.toString('utf8'));
      } catch {
        ws.send(JSON.stringify({ type: 'error', message: 'Malformed JSON payload.' }));
        return;
      }

      // First frame must authenticate
      if (!clients.has(ws)) {
        if (data.type !== 'auth' || typeof data.token !== 'string') {
          ws.close(4001, 'Authentication required');
          return;
        }
        const user = verifySessionToken(data.token);
        if (!user) {
          ws.close(4003, 'Invalid or expired session');
          return;
        }
        clearTimeout(authTimeout);
        clients.set(ws, {
          connectionId: crypto.randomUUID(),
          socket: ws,
          user,
          lastMessageAt: 0,
        });

        const messages = listActiveMessages();
        ws.send(
          JSON.stringify({
            type: 'init',
            messages,
            onlineUsers: getOnlineUsers(),
            retentionDays: RETENTION_DAYS,
          })
        );
        broadcastToAll({
          type: 'presence:update',
          onlineUsers: getOnlineUsers(),
        });
        return;
      }

      const client = clients.get(ws)!;

      if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }

      if (data.type === 'message:send') {
        const now = Date.now();
        if (now - client.lastMessageAt < 250) {
          ws.send(
            JSON.stringify({
              type: 'error',
              message: 'You are sending messages too quickly. Please pause briefly.',
            })
          );
          return;
        }

        const content = sanitizeMessageContent(data.content);
        if (!content) {
          ws.send(
            JSON.stringify({
              type: 'error',
              message: 'Message must be between 1 and 2,000 characters.',
            })
          );
          return;
        }

        client.lastMessageAt = now;
        const message = insertMessage({
          id: crypto.randomUUID(),
          senderName: client.user.username,
          senderRole: client.user.role,
          content,
          createdAt: now,
        });

        broadcastToAll({ type: 'message:created', message });
      }
    });

    ws.on('close', () => {
      clearTimeout(authTimeout);
      if (clients.delete(ws)) {
        broadcastToAll({
          type: 'presence:update',
          onlineUsers: getOnlineUsers(),
        });
      }
    });
  });

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== 'true',
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`NEXUS server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start NEXUS server:', err);
  process.exit(1);
});
