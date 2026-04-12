// Redeploy test: trivial comment for Railway

// ═══════════════════════════════════════════════════════════════
//  Fallen Bot API — Express + SQLite
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const EventEmitter = require('events');

const app = express();
const PORT = process.env.PORT || 3200;
const API_KEY = process.env.API_KEY || '';
const eventEmitter = new EventEmitter();

// ── Middleware ────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// Session storage (declared early so requireKey can use it)
const sessions = new Map();

// Simple API key guard for internal routes
function requireKey(req, res, next) {
    // Accept API key (bot → API calls)
    if (API_KEY && req.headers['x-api-key'] === API_KEY) return next();
    // Accept session token (dashboard → API calls)
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (token && sessions.get(token)) return next();
    // If no API_KEY is set, allow all (dev mode)
    if (!API_KEY) return next();
    return res.status(401).json({ error: 'Unauthorized' });
}

// ── Database Setup ───────────────────────────────────────────
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'fallen.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Guild configs
db.exec(`CREATE TABLE IF NOT EXISTS guild_configs (
    guild_id TEXT PRIMARY KEY,
    config TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT DEFAULT (datetime('now'))
)`);

// Moderation logs
db.exec(`CREATE TABLE IF NOT EXISTS mod_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_name TEXT,
    moderator_id TEXT NOT NULL,
    moderator_name TEXT,
    reason TEXT,
    duration TEXT,
    created_at TEXT DEFAULT (datetime('now'))
)`);

// Warnings
db.exec(`CREATE TABLE IF NOT EXISTS warnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_name TEXT,
    moderator_id TEXT NOT NULL,
    moderator_name TEXT,
    reason TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
)`);

// Tickets
db.exec(`CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id TEXT NOT NULL,
    channel_id TEXT,
    user_id TEXT NOT NULL,
    user_name TEXT,
    status TEXT DEFAULT 'open',
    created_at TEXT DEFAULT (datetime('now')),
    closed_at TEXT
)`);

// Webhook registrations for config events
 db.exec(`CREATE TABLE IF NOT EXISTS webhooks (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     guild_id TEXT NOT NULL,
     url TEXT NOT NULL,
     event TEXT NOT NULL,
     created_at TEXT DEFAULT (datetime('now'))
 )`);

function dispatchWebhooks(guildId, event, payload) {
    const hooks = db.prepare('SELECT url FROM webhooks WHERE guild_id = ? AND event = ?').all(guildId, event);
    for (const hook of hooks) {
        fetch(hook.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ guildId, event, payload }),
        }).catch(err => console.error('[Webhook] Dispatch failed', hook.url, err.message));
    }
}

// Get guild config
app.get('/api/guilds/:guildId/config', (req, res) => {
    const row = db.prepare('SELECT config FROM guild_configs WHERE guild_id = ?').get(req.params.guildId);
    if (!row) return res.json({});
    try { res.json(JSON.parse(row.config)); }
    catch { res.json({}); }
});

// Get list of linked guilds and saved configs
app.get('/api/guilds', requireKey, (req, res) => {
    const rows = db.prepare('SELECT guild_id, config, updated_at FROM guild_configs ORDER BY updated_at DESC').all();
    const guilds = rows.map(row => ({
        guildId: row.guild_id,
        updatedAt: row.updated_at,
        config: (() => { try { return JSON.parse(row.config); } catch { return {}; } })(),
    }));
    res.json({ guilds });
});

// Get guild state summary
app.get('/api/guilds/:guildId/state', requireKey, (req, res) => {
    const row = db.prepare('SELECT guild_id, config, updated_at FROM guild_configs WHERE guild_id = ?').get(req.params.guildId);
    const state = {
        guildId: req.params.guildId,
        linked: !!row,
        updatedAt: row?.updated_at || null,
        config: row ? (() => { try { return JSON.parse(row.config); } catch { return {}; } })() : {},
    };
    res.json(state);
});

// Get guild stats
app.get('/api/guilds/:guildId/stats', requireKey, (req, res) => {
    const guildId = req.params.guildId;
    const warnCount = db.prepare('SELECT COUNT(*) AS c FROM warnings WHERE guild_id = ?').get(guildId).c;
    const modCount = db.prepare('SELECT COUNT(*) AS c FROM mod_logs WHERE guild_id = ?').get(guildId).c;
    const ticketCount = db.prepare('SELECT COUNT(*) AS c FROM tickets WHERE guild_id = ?').get(guildId).c;
    res.json({ guildId, warns: warnCount, modActions: modCount, tickets: ticketCount });
});

// Get saved panels for a guild
app.get('/api/guilds/:guildId/panels', requireKey, (req, res) => {
    const row = db.prepare('SELECT config FROM guild_configs WHERE guild_id = ?').get(req.params.guildId);
    if (!row) return res.json({ panels: [] });
    let cfg = {};
    try { cfg = JSON.parse(row.config); } catch {}
    res.json({ panels: cfg.panels || [] });
});

// Preview a panel payload
app.post('/api/guilds/:guildId/panels/preview', requireKey, (req, res) => {
    const panel = req.body.panel;
    if (!panel) return res.status(400).json({ error: 'Panel payload required' });
    res.json({
        guildId: req.params.guildId,
        preview: {
            title: panel.title || 'Panel Preview',
            description: panel.description || 'This is a preview of your panel configuration.',
            fields: panel.fields || [],
        },
    });
});

// Register a webhook for config events
app.post('/api/guilds/:guildId/webhooks', requireKey, (req, res) => {
    const { url, event } = req.body;
    if (!url || !event) return res.status(400).json({ error: 'Missing url or event' });
    const r = db.prepare('INSERT INTO webhooks (guild_id, url, event) VALUES (?, ?, ?)').run(req.params.guildId, url, event);
    res.json({ ok: true, webhookId: r.lastInsertRowid });
});

// List webhooks for a guild
app.get('/api/guilds/:guildId/webhooks', requireKey, (req, res) => {
    const hooks = db.prepare('SELECT id, url, event, created_at FROM webhooks WHERE guild_id = ?').all(req.params.guildId);
    res.json({ webhooks: hooks });
});

// Live events via SSE
app.get('/api/guilds/:guildId/events', requireKey, (req, res) => {
    const guildId = req.params.guildId;
    res.writeHead(200, {
        Connection: 'keep-alive',
        'Cache-Control': 'no-cache',
        'Content-Type': 'text/event-stream',
        'Access-Control-Allow-Origin': '*',
    });
    res.write('retry: 2000\n\n');

    const listener = (data) => {
        res.write(`event: ${data.event}\n`);
        res.write(`data: ${JSON.stringify(data.payload)}\n\n`);
    };

    eventEmitter.on(`guild:${guildId}:event`, listener);
    const keepAlive = setInterval(() => res.write(': keepalive\n\n'), 20000);
    req.on('close', () => {
        clearInterval(keepAlive);
        eventEmitter.off(`guild:${guildId}:event`, listener);
    });
});

// Update guild config
app.patch('/api/guilds/:guildId/config', requireKey, (req, res) => {
    const { guildId } = req.params;
    const existing = db.prepare('SELECT config FROM guild_configs WHERE guild_id = ?').get(guildId);
    let cfg = {};
    if (existing) { try { cfg = JSON.parse(existing.config); } catch {} }
    Object.assign(cfg, req.body);
    db.prepare(`INSERT INTO guild_configs (guild_id, config, updated_at) VALUES (?, ?, datetime('now'))
        ON CONFLICT(guild_id) DO UPDATE SET config=excluded.config, updated_at=datetime('now')`)
        .run(guildId, JSON.stringify(cfg));
    res.json({ ok: true, config: cfg });
    console.log('[PATCH /api/guilds/:guildId/config] Headers:', req.headers);
    console.log('[PATCH /api/guilds/:guildId/config] Body:', req.body);
    eventEmitter.emit(`guild:${guildId}:event`, { event: 'config.updated', payload: { guildId, config: cfg } });
    dispatchWebhooks(guildId, 'config.updated', { guildId, config: cfg });
});

// ═══════════════════════════════════════════════════════════════

// Add mod log entry
app.post('/api/guilds/:guildId/modlogs', requireKey, (req, res) => {
    const { guildId } = req.params;
    const { action, target_id, target_name, moderator_id, moderator_name, reason, duration } = req.body;
    const r = db.prepare('INSERT INTO mod_logs (guild_id, action, target_id, target_name, moderator_id, moderator_name, reason, duration) VALUES (?,?,?,?,?,?,?,?)')
        .run(guildId, action, target_id, target_name || null, moderator_id, moderator_name || null, reason || null, duration || null);
    res.json({ ok: true, id: r.lastInsertRowid });
});

// Get mod logs for a guild
app.get('/api/guilds/:guildId/modlogs', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const offset = parseInt(req.query.offset) || 0;
    const action = req.query.action;
    const target = req.query.target;

    let query = 'SELECT * FROM mod_logs WHERE guild_id = ?';
    const params = [req.params.guildId];
    if (action) { query += ' AND action = ?'; params.push(action); }
    if (target) { query += ' AND target_id = ?'; params.push(target); }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const logs = db.prepare(query).all(...params);
    const total = db.prepare('SELECT COUNT(*) as c FROM mod_logs WHERE guild_id = ?').get(req.params.guildId).c;
    res.json({ logs, total });
});

// ═══════════════════════════════════════════════════════════════
//  WARNING ROUTES
// ═══════════════════════════════════════════════════════════════

// Add warning
app.post('/api/guilds/:guildId/warns', requireKey, (req, res) => {
    const { guildId } = req.params;
    const { target_id, target_name, moderator_id, moderator_name, reason } = req.body;
    db.prepare('INSERT INTO warnings (guild_id, target_id, target_name, moderator_id, moderator_name, reason) VALUES (?,?,?,?,?,?)')
        .run(guildId, target_id, target_name || null, moderator_id, moderator_name || null, reason);
    const total = db.prepare('SELECT COUNT(*) as c FROM warnings WHERE guild_id = ? AND target_id = ?').get(guildId, target_id).c;
    res.json({ ok: true, total });
});

// Get warnings for a user
app.get('/api/guilds/:guildId/warns/:userId', (req, res) => {
    const warns = db.prepare('SELECT * FROM warnings WHERE guild_id = ? AND target_id = ? ORDER BY created_at DESC').all(req.params.guildId, req.params.userId);
    res.json({ warns });
});

// Clear warnings for a user
app.delete('/api/guilds/:guildId/warns/:userId', requireKey, (req, res) => {
    db.prepare('DELETE FROM warnings WHERE guild_id = ? AND target_id = ?').run(req.params.guildId, req.params.userId);
    res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════
//  DASHBOARD ROUTES (OAuth2)
// ═══════════════════════════════════════════════════════════════

const DISCORD_CLIENT_ID = process.env.CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.CLIENT_SECRET || '';
const REDIRECT_URI = process.env.REDIRECT_URI || '';
const WEBSITE_URL = process.env.WEBSITE_URL || 'http://localhost:5173';

// OAuth2 login redirect
app.get('/auth/login', (req, res) => {
    const scopes = 'identify guilds';
    const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=${encodeURIComponent(scopes)}`;
    res.redirect(url);
});

// OAuth2 callback
app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).json({ error: 'No code provided' });
    try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID, client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
            }),
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) return res.status(400).json({ error: 'Failed to get token' });

        // Store token in simple in-memory sessions (for production, use a proper session store)
        const sessionId = require('crypto').randomBytes(32).toString('hex');
        sessions.set(sessionId, { token: tokenData.access_token, refresh: tokenData.refresh_token, expires: Date.now() + tokenData.expires_in * 1000 });

        res.redirect(`${WEBSITE_URL}/dashboard.html?token=${sessionId}`);
    } catch (err) {
        console.error('[Auth] callback error:', err);
        res.status(500).json({ error: 'Authentication failed' });
    }
});

// Session storage (see top of file)

// Get authenticated user
app.get('/auth/user', async (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const session = sessions.get(token);
    if (!session) return res.status(401).json({ error: 'Not authenticated' });
    try {
        const r = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${session.token}` } });
        const user = await r.json();
        res.json(user);
    } catch { res.status(401).json({ error: 'Token invalid' }); }
});

// Get user's guilds
app.get('/auth/guilds', async (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const session = sessions.get(token);
    if (!session) return res.status(401).json({ error: 'Not authenticated' });
    try {
        const r = await fetch('https://discord.com/api/users/@me/guilds', { headers: { Authorization: `Bearer ${session.token}` } });
        const guilds = await r.json();
        // Filter to guilds where user has MANAGE_GUILD (0x20) or ADMINISTRATOR (0x8)
        const managed = guilds.filter(g => {
            const perms = BigInt(g.permissions);
            return (perms & 0x8n) === 0x8n || (perms & 0x20n) === 0x20n;
        });
        res.json({ guilds: managed });
    } catch { res.status(401).json({ error: 'Token invalid' }); }
});

// ═══════════════════════════════════════════════════════════════
//  STATS
// ═══════════════════════════════════════════════════════════════
app.get('/api/stats', (req, res) => {
    const totalWarns = db.prepare('SELECT COUNT(*) as c FROM warnings').get().c;
    const totalModActions = db.prepare('SELECT COUNT(*) as c FROM mod_logs').get().c;
    const totalGuilds = db.prepare('SELECT COUNT(*) as c FROM guild_configs').get().c;
    res.json({ guilds: totalGuilds, warnings: totalWarns, modActions: totalModActions });
});

// ═══════════════════════════════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════════════════════════════
app.get('/', (_, res) => res.json({ status: 'ok', name: 'Fallen Bot API', version: '1.0.0' }));
app.get('/health', (_, res) => res.json({ status: 'ok' }));

// ═══════════════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════════════
app.listen(PORT, () => console.log(`[Fallen API] Running on port ${PORT}`));
