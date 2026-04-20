// Redeploy test: trivial comment for Railway

// ═══════════════════════════════════════════════════════════════
//  FS Bot API — Express + SQLite
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const EventEmitter = require('events');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3200;
const API_KEY = process.env.API_KEY || '';
// JWT secret — derive from API_KEY for Railway stability; override with JWT_SECRET env var
const JWT_SECRET = process.env.JWT_SECRET || (process.env.API_KEY ? `jwt_${process.env.API_KEY}` : crypto.randomBytes(32).toString('hex'));

// ── Minimal stateless JWT (HS256, no external deps) ───────────
function jwtEncode(payload) {
    const h = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url');
    const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const s = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${b}`).digest('base64url');
    return `${h}.${b}.${s}`;
}

function jwtDecode(token) {
    const parts = (token || '').split('.');
    if (parts.length !== 3) return null;
    const [h, b, s] = parts;
    try {
        const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${b}`).digest('base64url');
        if (s.length !== expected.length ||
            !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expected))) return null;
        return JSON.parse(Buffer.from(b, 'base64url').toString());
    } catch { return null; }
}

async function refreshSessionTokens(session) {
    if (!session?.refresh_token) return null;
    try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'refresh_token',
                refresh_token: session.refresh_token,
            }),
        });
        const data = await tokenRes.json();
        if (!data.access_token) return null;
        const newPayload = {
            access_token: data.access_token,
            refresh_token: data.refresh_token || session.refresh_token,
            expires_at: Date.now() + (data.expires_in || 604800) * 1000,
        };
        return { session: newPayload, newToken: jwtEncode(newPayload) };
    } catch (err) {
        console.error('[Auth] refreshSessionTokens failed:', err.message);
        return null;
    }
}
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || process.env.BOT_TOKEN || process.env.TOKEN || '';
const DISCORD_CLIENT_ID = process.env.CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.CLIENT_SECRET || '';
const REDIRECT_URI = process.env.REDIRECT_URI || '';
const WEBSITE_URL = process.env.WEBSITE_URL || 'http://localhost:5173';
const DATA_DIR = process.env.DATA_DIR || '/app/data';
const eventEmitter = new EventEmitter();

try { if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) { console.warn('[FS API] Could not create DATA_DIR:', e.message); }

// ── Middleware ────────────────────────────────────────────────
app.use(cors({ exposedHeaders: ['X-New-Token'] }));
app.use(express.json());

// Session storage helpers
function getSession(sessionId) {
    return db.prepare('SELECT * FROM oauth_sessions WHERE session_id = ?').get(sessionId);
}

function saveSession(sessionId, data) {
    db.prepare(`INSERT INTO oauth_sessions (session_id, access_token, refresh_token, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
            access_token = excluded.access_token,
            refresh_token = excluded.refresh_token,
            expires_at = excluded.expires_at
    `).run(sessionId, data.access_token, data.refresh_token, data.expires_at, data.created_at);
}

function deleteSession(sessionId) {
    db.prepare('DELETE FROM oauth_sessions WHERE session_id = ?').run(sessionId);
}

async function refreshDiscordSession(sessionId, session) {
    if (!session || !session.refresh_token) return null;
    try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'refresh_token',
                refresh_token: session.refresh_token,
            }),
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) return null;

        const expiresAt = Date.now() + (tokenData.expires_in || 3600) * 1000;
        saveSession(sessionId, {
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token || session.refresh_token,
            expires_at: expiresAt,
            created_at: new Date().toISOString(),
        });
        return getSession(sessionId);
    } catch (err) {
        console.error('[Auth] refresh session failed:', err);
        return null;
    }
}

async function getValidSession(token) {
    if (!token) return null;
    // Try JWT-based session first (stateless — survives Railway redeploys)
    const jwt = jwtDecode(token);
    if (jwt?.access_token) {
        if (jwt.expires_at && Date.now() > jwt.expires_at) {
            // Expired — flag for refresh; caller is responsible for issuing X-New-Token
            return jwt.refresh_token ? { ...jwt, _needsRefresh: true } : null;
        }
        return jwt;
    }
    // Legacy DB-based session fallback
    const session = getSession(token);
    if (!session) return null;
    if (session.expires_at && Date.now() > session.expires_at) {
        return await refreshDiscordSession(token, session);
    }
    return session;
}

// Simple API key guard for internal routes
async function requireKey(req, res, next) {
    // Accept API key (bot → API calls)
    if (API_KEY && req.headers['x-api-key'] === API_KEY) return next();
    // Accept session token (dashboard → API calls)
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (token) {
        // JWT session (stateless, no DB needed)
        const jwt = jwtDecode(token);
        if (jwt?.access_token) return next();
        // Legacy DB session
        if (getSession(token)) return next();
    }
    // If no API_KEY is set, allow all (dev mode)
    if (!API_KEY) return next();
    return res.status(401).json({ error: 'Unauthorized' });
}

const FALLEN_BOT_API = process.env.FALLEN_BOT_API || '';

// ── Database Setup ───────────────────────────────────────────
const dbPath = process.env.DATABASE_PATH || path.join(DATA_DIR, 'fallen.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Guild configs
db.exec(`CREATE TABLE IF NOT EXISTS guild_configs (
    guild_id TEXT PRIMARY KEY,
    config TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT DEFAULT (datetime('now'))
)`);

db.exec(`CREATE TABLE IF NOT EXISTS oauth_sessions (
    session_id TEXT PRIMARY KEY,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    expires_at INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
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

// Saved embeds
db.exec(`CREATE TABLE IF NOT EXISTS embeds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
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

// ── Embed helpers ─────────────────────────────────────────────
function buildDiscordEmbed(embed) {
    const colorHex = (embed.color || '#5865F2').replace('#', '');
    const d = { color: parseInt(colorHex, 16) || 0x5865F2 };
    if (embed.title?.trim())        d.title       = embed.title.trim();
    if (embed.titleUrl?.trim())     d.url         = embed.titleUrl.trim();
    if (embed.description?.trim())  d.description = embed.description.trim();
    if (embed.footer?.trim())       d.footer      = { text: embed.footer.trim(), icon_url: embed.footerIconUrl?.trim() || undefined };
    if (embed.thumbnail?.trim())    d.thumbnail   = { url: embed.thumbnail.trim() };
    if (embed.image?.trim())        d.image       = { url: embed.image.trim() };
    if (embed.author?.trim())       d.author      = { name: embed.author.trim(), icon_url: embed.authorIconUrl?.trim() || undefined, url: embed.authorUrl?.trim() || undefined };
    if (embed.timestamp)            d.timestamp   = new Date().toISOString();
    if (embed.fields?.length)       d.fields      = embed.fields.filter(f => f.name?.trim() && f.value?.trim()).map(f => ({ name: f.name.trim(), value: f.value.trim(), inline: !!f.inline }));
    return d;
}

async function sendToDiscord(channelId, payload) {
    const res = await fetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
        method: 'POST',
        headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.message || `Discord ${res.status}`);
    }
    return res.json();
}

// ── Embeds CRUD ───────────────────────────────────────────────

// List all saved embeds for a guild
app.get('/api/guilds/:guildId/embeds', requireKey, (req, res) => {
    const rows = db.prepare('SELECT id, data, created_at, updated_at FROM embeds WHERE guild_id = ? ORDER BY updated_at DESC').all(req.params.guildId);
    const embeds = rows.map(r => {
        try { return { id: r.id, ...JSON.parse(r.data), createdAt: r.created_at, updatedAt: r.updated_at }; }
        catch { return { id: r.id, createdAt: r.created_at, updatedAt: r.updated_at }; }
    });
    res.json(embeds);
});

// Create a new saved embed
app.post('/api/guilds/:guildId/embeds', requireKey, (req, res) => {
    const r = db.prepare(`INSERT INTO embeds (guild_id, data, created_at, updated_at) VALUES (?, ?, datetime('now'), datetime('now'))`).run(req.params.guildId, JSON.stringify(req.body));
    res.json({ success: true, id: r.lastInsertRowid, embed: { id: r.lastInsertRowid, ...req.body } });
});

// Update a saved embed
app.put('/api/guilds/:guildId/embeds/:id', requireKey, async (req, res) => {
    const row = db.prepare('SELECT data FROM embeds WHERE id = ? AND guild_id = ?').get(req.params.id, req.params.guildId);
    if (!row) return res.status(404).json({ error: 'Embed not found' });
    const existing = (() => { try { return JSON.parse(row.data); } catch { return {}; } })();
    const updated = { ...existing, ...req.body };
    db.prepare(`UPDATE embeds SET data = ?, updated_at = datetime('now') WHERE id = ? AND guild_id = ?`).run(JSON.stringify(updated), req.params.id, req.params.guildId);
    // If already sent to Discord, patch it in-place
    let patched = false;
    if (updated.messageId && updated.channelId) {
        try {
            const discordEmbed = buildDiscordEmbed(updated);
            await fetch(`https://discord.com/api/v10/channels/${updated.channelId}/messages/${updated.messageId}`, {
                method: 'PATCH',
                headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: updated.content?.trim() || '', embeds: [discordEmbed] }),
            });
            patched = true;
        } catch (e) { console.warn('[Embed] Patch failed:', e.message); }
    }
    res.json({ success: true, embed: { id: Number(req.params.id), ...updated }, patched });
});

// Delete a saved embed
app.delete('/api/guilds/:guildId/embeds/:id', requireKey, (req, res) => {
    const info = db.prepare('DELETE FROM embeds WHERE id = ? AND guild_id = ?').run(req.params.id, req.params.guildId);
    if (info.changes === 0) return res.status(404).json({ error: 'Embed not found' });
    res.json({ success: true });
});

// Send an embed to a Discord channel
app.post('/api/guilds/:guildId/send-embed', requireKey, async (req, res) => {
    const { channelId, embed } = req.body;
    if (!channelId) return res.status(400).json({ error: 'No channelId provided' });
    if (!embed) return res.status(400).json({ error: 'No embed data provided' });
    const discordEmbed = buildDiscordEmbed(embed);
    if (!discordEmbed.title && !discordEmbed.description && !discordEmbed.fields?.length)
        return res.status(400).json({ error: 'Embed must have at least a title, description, or fields.' });
    try {
        const msg = await sendToDiscord(channelId, { content: embed.content?.trim() || undefined, embeds: [discordEmbed] });
        // Save / update the embed in DB with channelId + messageId
        const guildId = req.params.guildId;
        const embedData = { ...embed, channelId, messageId: msg.id };
        if (embed.id) {
            const existing = db.prepare('SELECT data FROM embeds WHERE id = ? AND guild_id = ?').get(embed.id, guildId);
            if (existing) {
                const prev = (() => { try { return JSON.parse(existing.data); } catch { return {}; } })();
                db.prepare(`UPDATE embeds SET data = ?, updated_at = datetime('now') WHERE id = ? AND guild_id = ?`).run(JSON.stringify({ ...prev, ...embedData }), embed.id, guildId);
            }
        } else {
            db.prepare(`INSERT INTO embeds (guild_id, data, created_at, updated_at) VALUES (?, ?, datetime('now'), datetime('now'))`).run(guildId, JSON.stringify(embedData));
        }
        res.json({ success: true, messageId: msg.id, channelId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ── Ticket Settings ───────────────────────────────────────────
function getTicketSettings(guildId) {
    const row = db.prepare('SELECT config FROM guild_configs WHERE guild_id = ?').get(guildId);
    if (!row) return {};
    try { return JSON.parse(row.config).ticketSettings || {}; } catch { return {}; }
}

function saveTicketSettings(guildId, settings) {
    const row = db.prepare('SELECT config FROM guild_configs WHERE guild_id = ?').get(guildId);
    let cfg = {};
    if (row) { try { cfg = JSON.parse(row.config); } catch {} }
    cfg.ticketSettings = settings;
    db.prepare(`INSERT INTO guild_configs (guild_id, config, updated_at) VALUES (?, ?, datetime('now'))
        ON CONFLICT(guild_id) DO UPDATE SET config=excluded.config, updated_at=datetime('now')`).run(guildId, JSON.stringify(cfg));
}

app.get('/api/guilds/:guildId/tickets/settings', requireKey, (req, res) => {
    res.json(getTicketSettings(req.params.guildId));
});

app.post('/api/guilds/:guildId/tickets/settings', requireKey, async (req, res) => {
    const { guildId } = req.params;
    saveTicketSettings(guildId, req.body);
    // Push to bot if available
    if (FALLEN_BOT_API) {
        fetch(`${FALLEN_BOT_API}/bot/ticket-settings/${guildId}`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body),
        }).catch(() => {});
    }
    res.json({ success: true });
});

// Send a ticket panel to Discord
app.post('/api/guilds/:guildId/tickets/send-panel', requireKey, async (req, res) => {
    const { guildId } = req.params;
    const settings = req.body;
    saveTicketSettings(guildId, settings);
    if (FALLEN_BOT_API) {
        fetch(`${FALLEN_BOT_API}/bot/ticket-settings/${guildId}`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings),
        }).catch(() => {});
    }

    const { panelChannelId, panelEmbed = {}, buttons = [], panelType = 'buttons' } = settings;
    if (!panelChannelId) return res.status(400).json({ error: 'No panel channel configured.' });
    if (!panelEmbed.title?.trim() && !panelEmbed.description?.trim())
        return res.status(400).json({ error: 'Panel embed needs at least a title or description.' });
    if (!buttons.length) return res.status(400).json({ error: 'Add at least one button.' });

    const discordEmbed = buildDiscordEmbed(panelEmbed);

    // Build components
    let components;
    if (panelType === 'dropdown') {
        const options = buttons.slice(0, 25).map((btn, i) => {
            const opt = { label: (btn.label || 'Open Ticket').slice(0, 100), value: String(i) };
            if (btn.description) opt.description = btn.description.slice(0, 100);
            if (btn.emoji?.trim()) {
                const custom = btn.emoji.trim().match(/^<a?:(\w+):(\d+)>$/);
                opt.emoji = custom ? { name: custom[1], id: custom[2] } : { name: btn.emoji.trim() };
            }
            return opt;
        });
        components = [{ type: 1, components: [{ type: 3, custom_id: `tckt_sel_${guildId}`, placeholder: 'Select an option to open a ticket…', options }] }];
    } else {
        const styleMap = { Primary: 1, Secondary: 2, Success: 3, Danger: 4 };
        const allBtns = buttons.slice(0, 25).map((btn, i) => {
            const b = { type: 2, style: styleMap[btn.color] || 1, label: btn.label || 'Open Ticket', custom_id: `tckt_btn_${guildId}_${i}` };
            if (btn.emoji?.trim()) {
                try {
                    const custom = btn.emoji.trim().match(/^<a?:(\w+):(\d+)>$/);
                    b.emoji = custom ? { name: custom[1], id: custom[2] } : { name: btn.emoji.trim() };
                } catch {}
            }
            return b;
        });
        components = [];
        for (let i = 0; i < allBtns.length; i += 5) {
            components.push({ type: 1, components: allBtns.slice(i, i + 5) });
        }
    }

    try {
        const msg = await sendToDiscord(panelChannelId, { embeds: [discordEmbed], components });
        res.json({ success: true, messageId: msg.id, channelId: panelChannelId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

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

// Get Discord guild roles, channels, and categories for the selected server
app.get('/api/guilds/:guildId/discord', requireKey, async (req, res) => {
    if (!DISCORD_BOT_TOKEN) return res.status(500).json({ error: 'Discord bot token not configured (set BOT_TOKEN or DISCORD_BOT_TOKEN)' });
    const guildId = req.params.guildId;
    try {
        const [rolesRes, channelsRes] = await Promise.all([
            fetch(`https://discord.com/api/v10/guilds/${guildId}/roles`, { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }),
            fetch(`https://discord.com/api/v10/guilds/${guildId}/channels`, { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }),
        ]);
        if (!rolesRes.ok) return res.status(rolesRes.status).json({ error: 'Failed to fetch roles' });
        if (!channelsRes.ok) return res.status(channelsRes.status).json({ error: 'Failed to fetch channels' });
        const roles = await rolesRes.json();
        const channels = await channelsRes.json();
        const categories = channels.filter(c => c.type === 4);
        res.json({ roles, channels, categories });
    } catch (err) {
        console.error('[Discord] fetch guild data failed:', err);
        res.status(500).json({ error: 'Failed to fetch guild data' });
    }
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

// Publish a ticket panel via bot
app.post('/api/guilds/:guildId/panels/publish', requireKey, (req, res) => {
    const { panel, channelId } = req.body;
    if (!panel || !channelId) return res.status(400).json({ error: 'Panel and channelId are required' });
    const guildId = req.params.guildId;
    const existing = db.prepare('SELECT config FROM guild_configs WHERE guild_id = ?').get(guildId);
    let cfg = {};
    if (existing) { try { cfg = JSON.parse(existing.config); } catch {} }
    cfg.panels = cfg.panels || [];
    const alreadySaved = cfg.panels.some(p => p.title === panel.title && p.description === panel.description && p.buttonText === panel.buttonText && p.buttonEmoji === panel.buttonEmoji);
    if (!alreadySaved) cfg.panels.push(panel);
    cfg.pendingTicketPanel = { panel, channelId, createdAt: new Date().toISOString() };
    db.prepare(`INSERT INTO guild_configs (guild_id, config, updated_at) VALUES (?, ?, datetime('now'))
        ON CONFLICT(guild_id) DO UPDATE SET config=excluded.config, updated_at=datetime('now')`)
        .run(guildId, JSON.stringify(cfg));
    eventEmitter.emit(`guild:${guildId}:event`, { event: 'ticket.panel.publish', payload: { guildId, panel, channelId } });
    dispatchWebhooks(guildId, 'ticket.panel.publish', { guildId, panel, channelId });
    res.json({ ok: true, pending: true, config: cfg });
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

// Get all warnings for a guild (dashboard)
app.get('/api/guilds/:guildId/warns', requireKey, (req, res) => {
    const warns = db.prepare('SELECT * FROM warnings WHERE guild_id = ? ORDER BY created_at DESC').all(req.params.guildId);
    res.json({ warns });
});

// Get warnings for a user
app.get('/api/guilds/:guildId/warns/:userId', (req, res) => {
    const warns = db.prepare('SELECT * FROM warnings WHERE guild_id = ? AND target_id = ? ORDER BY created_at DESC').all(req.params.guildId, req.params.userId);
    res.json({ warns });
});

// Delete a single warning by id
app.delete('/api/guilds/:guildId/warns/:userId/:warnId', requireKey, (req, res) => {
    const { guildId, userId, warnId } = req.params;
    const result = db.prepare('DELETE FROM warnings WHERE id = ? AND guild_id = ? AND target_id = ?').run(warnId, guildId, userId);
    if (result.changes === 0) return res.status(404).json({ ok: false, error: 'Warn not found' });
    const total = db.prepare('SELECT COUNT(*) as c FROM warnings WHERE guild_id = ? AND target_id = ?').get(guildId, userId).c;
    res.json({ ok: true, total });
});

// Clear warnings for a user
app.delete('/api/guilds/:guildId/warns/:userId', requireKey, (req, res) => {
    db.prepare('DELETE FROM warnings WHERE guild_id = ? AND target_id = ?').run(req.params.guildId, req.params.userId);
    res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════
//  DASHBOARD ROUTES (OAuth2)
// ═══════════════════════════════════════════════════════════════

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

        // Issue a signed JWT — stateless, survives Railway redeploys
        const sessionToken = jwtEncode({
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token,
            expires_at: Date.now() + tokenData.expires_in * 1000,
        });

        res.redirect(`${WEBSITE_URL}/dashboard.html?token=${encodeURIComponent(sessionToken)}`);
    } catch (err) {
        console.error('[Auth] callback error:', err);
        res.status(500).json({ error: 'Authentication failed' });
    }
});

// Session storage (see top of file)

// Get authenticated user
app.get('/auth/user', async (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    let session = await getValidSession(token);
    if (!session) return res.status(401).json({ error: 'Not authenticated' });
    // Auto-refresh expired JWT session and send new token back transparently
    if (session._needsRefresh) {
        const refreshed = await refreshSessionTokens(session);
        if (!refreshed) return res.status(401).json({ error: 'Session expired, please log in again' });
        session = refreshed.session;
        res.setHeader('X-New-Token', refreshed.newToken);
    }
    try {
        const r = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${session.access_token}` } });
        if (!r.ok) return res.status(401).json({ error: 'Discord token invalid' });
        const user = await r.json();
        res.json(user);
    } catch {
        res.status(401).json({ error: 'Token invalid' });
    }
});

// Get user's guilds
app.get('/auth/guilds', async (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    let session = await getValidSession(token);
    if (!session) return res.status(401).json({ error: 'Not authenticated' });
    if (session._needsRefresh) {
        const refreshed = await refreshSessionTokens(session);
        if (!refreshed) return res.status(401).json({ error: 'Session expired, please log in again' });
        session = refreshed.session;
        res.setHeader('X-New-Token', refreshed.newToken);
    }
    try {
        const r = await fetch('https://discord.com/api/users/@me/guilds', { headers: { Authorization: `Bearer ${session.access_token}` } });
        if (!r.ok) return res.status(401).json({ error: 'Discord token invalid' });
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
//  PROFILES + ROBLOX
// ═══════════════════════════════════════════════════════════════

// Create profiles table if not exists
db.exec(`CREATE TABLE IF NOT EXISTS profiles (
    discord_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    roblox_username TEXT,
    roblox_display_name TEXT,
    main_character TEXT,
    roblox_id TEXT,
    roblox_avatar_url TEXT,
    custom_color TEXT,
    banner_url TEXT,
    region TEXT,
    country TEXT,
    country_flag TEXT,
    verified INTEGER DEFAULT 0,
    verify_code TEXT,
    verify_expires TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
)`);

try { db.exec(`ALTER TABLE profiles ADD COLUMN custom_color TEXT`); } catch {}
try { db.exec(`ALTER TABLE profiles ADD COLUMN banner_url TEXT`); } catch {}
try { db.exec(`ALTER TABLE profiles ADD COLUMN roblox_display_name TEXT`); } catch {}
try { db.exec(`ALTER TABLE profiles ADD COLUMN main_character TEXT`); } catch {}

app.get('/api/profiles/roblox/:username', (req, res) => {
    const profile = db.prepare(`
        SELECT * FROM profiles
        WHERE lower(roblox_username) = lower(?)
           OR lower(roblox_display_name) = lower(?)
        LIMIT 1
    `).get(req.params.username, req.params.username);
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    res.json({ profile, player: null, rank: null, recentMatches: [] });
});

// Get profile by discord ID
app.get('/api/profiles/:userId', (req, res) => {
    const profile = db.prepare('SELECT * FROM profiles WHERE discord_id = ?').get(req.params.userId);
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    res.json({ profile, player: null, rank: null, recentMatches: [] });
});

// Create profile
app.post('/internal/profiles', requireKey, (req, res) => {
    const { discord_id, display_name, roblox_username, roblox_display_name, main_character } = req.body;
    if (!discord_id || !display_name) return res.status(400).json({ error: 'discord_id and display_name required' });
    const existing = db.prepare('SELECT * FROM profiles WHERE discord_id = ?').get(discord_id);
    if (existing) return res.status(409).json({ error: 'Profile already exists', profile: existing });
    db.prepare('INSERT INTO profiles (discord_id, display_name, roblox_username, roblox_display_name, main_character) VALUES (?, ?, ?, ?, ?)').run(discord_id, display_name, roblox_username || null, roblox_display_name || null, main_character || null);
    const profile = db.prepare('SELECT * FROM profiles WHERE discord_id = ?').get(discord_id);
    res.json({ success: true, profile });
});

// Update profile fields
app.patch('/internal/profiles/:userId', requireKey, (req, res) => {
    const profile = db.prepare('SELECT * FROM profiles WHERE discord_id = ?').get(req.params.userId);
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    const allowed = ['display_name', 'roblox_username', 'roblox_display_name', 'main_character', 'roblox_id', 'roblox_avatar_url', 'custom_color', 'banner_url', 'region', 'country', 'country_flag', 'verified', 'verify_code', 'verify_expires'];
    const sets = [], vals = [];
    for (const key of allowed) {
        if (req.body[key] !== undefined) { sets.push(`${key}=?`); vals.push(req.body[key]); }
    }
    if (sets.length === 0) return res.status(400).json({ error: 'No valid fields to update' });
    sets.push("updated_at=datetime('now')");
    vals.push(req.params.userId);
    db.prepare(`UPDATE profiles SET ${sets.join(',')} WHERE discord_id=?`).run(...vals);
    const updated = db.prepare('SELECT * FROM profiles WHERE discord_id = ?').get(req.params.userId);
    res.json({ success: true, profile: updated });
});

// Delete profile
app.delete('/internal/profiles/:userId', requireKey, (req, res) => {
    const profile = db.prepare('SELECT * FROM profiles WHERE discord_id = ?').get(req.params.userId);
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    db.prepare('DELETE FROM profiles WHERE discord_id = ?').run(req.params.userId);
    res.json({ success: true });
});

// Roblox username → user ID + avatar lookup
app.get('/api/roblox/resolve/:username', async (req, res) => {
    try {
        const r1 = await fetch('https://users.roblox.com/v1/usernames/users', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usernames: [req.params.username], excludeBannedUsers: false }),
        });
        const d1 = await r1.json();
        if (!d1.data || d1.data.length === 0) return res.status(404).json({ error: 'Roblox user not found' });
        const rUser = d1.data[0];
        const r2 = await fetch(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${rUser.id}&size=150x150&format=Png`);
        const d2 = await r2.json();
        const avatarUrl = d2.data?.[0]?.imageUrl || null;
        res.json({ id: rUser.id, name: rUser.name, displayName: rUser.displayName, avatarUrl });
    } catch {
        res.status(500).json({ error: 'Roblox API error' });
    }
});

// Check if Roblox bio contains verification code
app.get('/api/roblox/verify-bio/:robloxId/:code', async (req, res) => {
    try {
        const r = await fetch(`https://users.roblox.com/v1/users/${encodeURIComponent(req.params.robloxId)}`);
        if (!r.ok) return res.status(404).json({ error: 'Roblox user not found' });
        const u = await r.json();
        const bio = (u.description || '').trim();
        const found = bio.includes(req.params.code);
        res.json({ found, bio: bio.slice(0, 200) });
    } catch {
        res.status(500).json({ error: 'Roblox API error' });
    }
});

// ═══════════════════════════════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════════════════════════════
app.get('/', (_, res) => res.json({ status: 'ok', name: 'FS Bot API', version: '1.0.0' }));
app.get('/health', (_, res) => res.json({ status: 'ok' }));

// ═══════════════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════════════
app.listen(PORT, () => console.log(`[FS API] Running on port ${PORT}`));
