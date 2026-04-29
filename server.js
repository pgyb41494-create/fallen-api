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
const configuredWebsiteUrl = (process.env.WEBSITE_URL || '').trim().replace(/\/$/, '');
const WEBSITE_URL = configuredWebsiteUrl && !/clansky\.vercel\.app/i.test(configuredWebsiteUrl)
    ? configuredWebsiteUrl
    : (process.env.NODE_ENV === 'development' ? 'http://localhost:5173' : 'https://fsbot-website.vercel.app');
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
const guildLeaderboardMemberCache = new Map();
const GUILD_LEADERBOARD_MEMBER_CACHE_TTL = 5 * 60 * 1000;

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

const LEADERBOARD_REGION_LABELS = {
    sao_paulo: 'São Paulo, Brasil',
    miami: 'Miami, Florida',
    dallas: 'Dallas, Texas',
    los_angeles: 'Los Angeles, California',
    virginia: 'Virginia, USA',
    chicago: 'Chicago, USA',
    santiago: 'Santiago, Chile',
    buenos_aires: 'Buenos Aires, Argentina',
    lima: 'Lima, Perú',
    bogota: 'Bogotá, Colombia',
    mexico_city: 'Ciudad de México, México',
    london: 'London, UK',
    frankfurt: 'Frankfurt, Germany',
    amsterdam: 'Amsterdam, Netherlands',
    paris: 'Paris, France',
    madrid: 'Madrid, Spain',
    warsaw: 'Warsaw, Poland',
    tokyo: 'Tokyo, Japan',
    seoul: 'Seoul, South Korea',
    singapore: 'Singapore',
    sydney: 'Sydney, Australia',
    mumbai: 'Mumbai, India',
    dubai: 'Dubai, UAE',
    johannesburg: 'Johannesburg, South Africa',
};

function normalizeRoleName(name) {
    return String(name || '').toLowerCase().trim().replace(/\s+/g, ' ');
}

function rankKindFromRoleName(roleName) {
    const name = String(roleName || '');
    const full = name.match(/\b(phase|stage|tier)\b/i)?.[1];
    if (full) return full.charAt(0).toUpperCase() + full.slice(1).toLowerCase();
    const short = name.match(/\b(ph|p|st|t)\b/i)?.[1]?.toLowerCase();
    if (short === 'st') return 'Stage';
    if (short === 't') return 'Tier';
    if (short === 'p' || short === 'ph') return 'Phase';
    return null;
}

function findPhaseRoleByRoles(roles, phaseNum) {
    const patterns = [`phase ${phaseNum}`, `phase${phaseNum}`, `stage ${phaseNum}`, `stage${phaseNum}`, `ph${phaseNum}`, `st${phaseNum}`, `tier ${phaseNum}`, `tier${phaseNum}`, `t${phaseNum}`].map(pattern => pattern.toLowerCase());
    const exact = roles.find(role => {
        if (role.managed) return false;
        if (/(?:stage|phase|tier)\s*1\s*applicant/i.test(role.name)) return false;
        return patterns.some(pattern => normalizeRoleName(role.name) === pattern);
    });
    if (exact) return exact;
    return roles.find(role => {
        if (role.managed) return false;
        if (/(?:stage|phase|tier)\s*1\s*applicant/i.test(role.name)) return false;
        return patterns.some(pattern => normalizeRoleName(role.name).includes(pattern));
    }) || null;
}

function formatLeaderboardPhaseText(phaseSummary) {
    if (!phaseSummary) return 'Sin phase';
    if (phaseSummary.text && phaseSummary.text !== 'Sin phase') return phaseSummary.text;
    const parts = [];
    if (phaseSummary.rankLabel) parts.push(phaseSummary.rankLabel);
    if (phaseSummary.tier) parts.push(phaseSummary.tier);
    if (phaseSummary.subTier) parts.push(phaseSummary.subTier);
    return parts.length ? parts.join(' · ') : 'Sin phase';
}

function normalizeProfileColor(input, fallback = '#2B2D31') {
    if (!input) return fallback;
    const clean = String(input).trim().replace(/^#/, '').replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]{6}$/.test(clean)) return fallback;
    return `#${clean.toUpperCase()}`;
}

function normalizeMediaUrl(input) {
    if (!input) return '';
    try {
        const parsed = new URL(String(input).trim());
        if (!['http:', 'https:'].includes(parsed.protocol)) return '';
        return parsed.toString();
    } catch {
        return '';
    }
}

const DEFAULT_LEADERBOARD_DESCRIPTION_TEMPLATE = [
    '{{mention}}',
    '**#{{spot}}. {{roblox_link}}**',
    '┌ Rank: {{rank}}',
    '├ Host: {{host}}',
    '├ País: {{country}}',
    '└ Región: {{region}}',
].join('\n');

function renderLeaderboardTemplate(template, variables = {}) {
    const source = String(template || '').trim() || DEFAULT_LEADERBOARD_DESCRIPTION_TEMPLATE;
    return source.replace(/{{\s*([a-z0-9_]+)\s*}}/gi, (_, key) => {
        const value = variables[key] ?? variables[key.toLowerCase()] ?? '';
        return value === null || value === undefined ? '' : String(value);
    });
}

function buildLeaderboardTemplateVariables(profile, options = {}) {
    const displayName = options.displayName || profile.roblox_display_name || profile.roblox_username || profile.display_name || 'Perfil';
    const spot = Math.max(1, parseInt(options.spot, 10) || 1);
    const rankText = options.rankText || 'Sin phase';
    const host = options.host?.trim() || profile.roblox_username || displayName || 'Unknown';
    const country = profile.country ? [profile.country, profile.country_flag || ''].filter(Boolean).join(' ').trim() : '—';
    const region = getLeaderboardRegionLabel(profile.region);
    const roblox = profile.roblox_username || '—';
    const mention = profile.discord_id ? `<@${profile.discord_id}>` : '';
    const robloxLink = profile.roblox_id ? `[${roblox}](https://www.roblox.com/users/${profile.roblox_id}/profile)` : roblox;
    return {
        mention,
        spot: String(spot),
        spot_label: `#${spot}.`,
        spot_hash: `#${spot}`,
        rank: rankText,
        host,
        country,
        region,
        roblox,
        roblox_link: robloxLink,
        display_name: displayName,
        score: String(options.profileScore ?? profile.profile_score ?? '—'),
        vacant: '',
        guild_name: options.guildName || '',
    };
}

async function fetchJsonWithTimeout(url, options = {}, timeoutMs = 4000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, { ...options, signal: controller.signal });
    } finally {
        clearTimeout(timer);
    }
}

async function getManageableRolesForGuild(guildId, roles, botUserId = null) {
    if (!DISCORD_BOT_TOKEN) return [];
    try {
        let resolvedBotUserId = botUserId;
        if (!resolvedBotUserId) {
            const botUserRes = await fetch('https://discord.com/api/v10/users/@me', {
                headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
            });
            if (!botUserRes.ok) return [];
            const botUser = await botUserRes.json();
            resolvedBotUserId = botUser?.id;
        }
        if (!resolvedBotUserId) return [];

        const botMemberRes = await fetch(`https://discord.com/api/v10/guilds/${guildId}/members/${resolvedBotUserId}`, {
            headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
        });
        if (!botMemberRes.ok) return [];
        const botMember = await botMemberRes.json();

        const botRoleIds = new Set(Array.isArray(botMember.roles) ? botMember.roles : []);
        const botTopPosition = (roles || []).reduce((highest, role) => (
            botRoleIds.has(role.id) ? Math.max(highest, Number(role.position || 0)) : highest
        ), 0);

        return (roles || []).filter(role => role.id !== guildId && !role.managed && Number(role.position || 0) < botTopPosition);
    } catch (err) {
        console.warn('[Discord] manageable role lookup failed:', err.message);
        return [];
    }
}

function getLeaderboardRegionLabel(region) {
    if (!region) return '—';
    return LEADERBOARD_REGION_LABELS[region] || region;
}

function buildLeaderboardCardData(profile, options = {}) {
    const displayName = options.displayName || profile.roblox_display_name || profile.roblox_username || profile.display_name || 'Perfil';
    const spot = Math.max(1, parseInt(options.spot, 10) || 1);
    const rankText = options.rankText || 'Sin phase';
    const host = options.host?.trim() || profile.roblox_username || displayName || 'Unknown';
    const country = profile.country ? [profile.country, profile.country_flag || ''].filter(Boolean).join(' ').trim() : '—';
    const region = getLeaderboardRegionLabel(profile.region);
    const roblox = profile.roblox_username || '—';
    const mention = profile.discord_id ? `<@${profile.discord_id}>` : '';
    const robloxLink = profile.roblox_id ? `[${roblox}](https://www.roblox.com/users/${profile.roblox_id}/profile)` : roblox;
    const color = normalizeProfileColor(options.globalColor || profile.custom_color);
    const introGifUrl = options.showIntroGif ? normalizeMediaUrl(options.globalIntroGifUrl || '') : '';
    const topImageUrl = normalizeMediaUrl(options.showTopImage ? (options.globalTopImageUrl || profile.leaderboard_top_image_url) : '');
    const description = renderLeaderboardTemplate(options.descriptionTemplate, buildLeaderboardTemplateVariables(profile, {
        displayName,
        spot,
        rankText,
        host,
        profileScore: options.profileScore,
        guildName: options.guildName,
    })).replace(/\n{3,}/g, '\n\n').trim();

    return {
        profile,
        spot,
        rankText,
        displayName,
        host,
        country,
        region,
        mention,
        roblox,
        color,
        introGifUrl,
        topImageUrl,
        description,
        embed: {
            color,
            description,
            footer: profile.display_name ? `FS · ${profile.display_name}` : 'FS Bot',
            thumbnail: profile.roblox_avatar_url || '',
        },
        messageEmbeds: [
            ...(topImageUrl ? [{ color, image: topImageUrl }] : []),
            {
                color,
                description,
                footer: profile.display_name ? `FS · ${profile.display_name}` : 'FS Bot',
                thumbnail: profile.roblox_avatar_url || '',
            },
            ...(introGifUrl ? [{ color, image: introGifUrl }] : []),
        ],
    };
}

function buildLeaderboardVacantCardData(spot, options = {}) {
    const color = normalizeProfileColor(options.globalColor || '#6B7280');
    const description = `**#${spot}. Vacant**\nNo profile assigned to this spot.`;
    return {
        isVacant: true,
        spot,
        rankText: 'Vacant',
        displayName: 'Vacant',
        host: 'Vacant',
        country: '—',
        region: '—',
        mention: '',
        roblox: '—',
        color,
        description,
        profile: {
            discord_id: '',
            display_name: 'Vacant',
            profile_score: '',
            roblox_username: '',
            roblox_display_name: '',
            roblox_avatar_url: '',
        },
        embed: {
            color,
            description,
            footer: 'FS Bot',
        },
        messageEmbeds: [{
            color,
            description,
            footer: 'FS Bot',
        }],
    };
}

async function getLeaderboardCardsForGuild(guildId, { resolveRanks = false } = {}) {
    const rows = db.prepare('SELECT * FROM profiles ORDER BY COALESCE(leaderboard_position, 999999), updated_at DESC').all();
    const profiles = rows.filter(profile => profile.leaderboard_position !== null && profile.leaderboard_position !== undefined);
    if (!profiles.length) return [];

    let roleById = new Map();
    let phaseMap = {};
    let leaderboardSettings = {};

    const cfgRow = db.prepare('SELECT config FROM guild_configs WHERE guild_id = ?').get(guildId);
    if (cfgRow?.config) {
        try {
            const cfg = JSON.parse(cfgRow.config);
            phaseMap = cfg.verifyPhaseRoleMap || {};
            leaderboardSettings = cfg.leaderboardSettings || {};
        } catch {
            phaseMap = {};
            leaderboardSettings = {};
        }
    }

    if (resolveRanks) {
        if (!DISCORD_BOT_TOKEN) throw new Error('Discord bot token not configured (set BOT_TOKEN or DISCORD_BOT_TOKEN)');
        const rolesRes = await fetch(`https://discord.com/api/v10/guilds/${guildId}/roles`, { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } });
        if (!rolesRes.ok) throw new Error('Failed to fetch roles');
        const roles = await rolesRes.json();
        roleById = new Map(roles.map(role => [role.id, role]));
    }

    const occupiedBySpot = new Map();
    let occupiedIndex = 0;
    for (const profile of profiles) {
        const spot = parseInt(profile.leaderboard_position, 10);
        if (!Number.isInteger(spot) || spot < 1 || spot > 10 || occupiedBySpot.has(spot)) continue;
        let rankText = 'Sin phase';
        if (resolveRanks && profile.discord_id) {
            try {
                const memberRes = await fetch(`https://discord.com/api/v10/guilds/${guildId}/members/${profile.discord_id}`, {
                    headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
                });
                if (memberRes.ok) {
                    const member = await memberRes.json();
                    const memberRoleIds = Array.isArray(member.roles) ? member.roles : [];
                    const memberRoles = memberRoleIds.map(id => roleById.get(id)).filter(Boolean);

                    let phaseNum = null;
                    let rankKind = null;
                    for (let i = 0; i <= 5; i++) {
                        const mappedRoleId = phaseMap[String(i)];
                        if (mappedRoleId && memberRoleIds.includes(mappedRoleId)) {
                            phaseNum = i;
                            rankKind = rankKindFromRoleName(roleById.get(mappedRoleId)?.name);
                            break;
                        }
                    }

                    if (phaseNum === null) {
                        const phaseRole = findPhaseRoleByRoles(memberRoles, 0) || findPhaseRoleByRoles(memberRoles, 1) || findPhaseRoleByRoles(memberRoles, 2) || findPhaseRoleByRoles(memberRoles, 3) || findPhaseRoleByRoles(memberRoles, 4) || findPhaseRoleByRoles(memberRoles, 5);
                        if (phaseRole) {
                            const match = phaseRole.name.match(/(?:phase|stage|tier)\s*(\d)/i) || phaseRole.name.match(/\b(ph|p|st|t)\s*(\d)/i) || phaseRole.name.match(/(\d)/);
                            if (match) {
                                phaseNum = Number(match[match.length > 2 ? 2 : 1]);
                                rankKind = rankKindFromRoleName(phaseRole.name);
                            }
                        }
                    }

                    if (phaseNum === null) {
                        const roleMatch = memberRoles.find(role => !role.managed && /(?:phase|stage|tier)\s*[0-5]/i.test(role.name) && !/(?:stage|phase|tier)\s*1\s*applicant/i.test(role.name));
                        if (roleMatch) {
                            const match = roleMatch.name.match(/(?:phase|stage|tier)\s*(\d)/i) || roleMatch.name.match(/\b(ph|p|st|t)\s*(\d)/i) || roleMatch.name.match(/(\d)/);
                            if (match) {
                                phaseNum = Number(match[match.length > 2 ? 2 : 1]);
                                rankKind = rankKindFromRoleName(roleMatch.name);
                            }
                        }
                    }

                    const tierRole = memberRoles.find(role => !role.managed && /\b(high|mid|low)\b/i.test(role.name));
                    const subTierRole = memberRoles.find(role => !role.managed && /\b(strong|stable|weak)\b/i.test(role.name));
                    const phaseText = phaseNum !== null ? `${rankKind || 'Phase'} ${phaseNum}` : null;
                    const tierText = tierRole ? (tierRole.name.match(/\b(high|mid|low)\b/i)?.[1].toUpperCase() || tierRole.name.toUpperCase()) : null;
                    const subTierText = subTierRole ? (subTierRole.name.match(/\b(strong|stable|weak)\b/i)?.[1].toUpperCase() || subTierRole.name.toUpperCase()) : null;
                    const parts = [phaseText, tierText, subTierText].filter(Boolean);
                    rankText = parts.length ? parts.join(' · ') : 'Sin phase';
                }
            } catch {
                rankText = 'Sin phase';
            }
        }

        occupiedBySpot.set(spot, buildLeaderboardCardData(profile, {
            showTopImage: occupiedIndex === 0,
            showIntroGif: occupiedIndex > 0,
            spot,
            rankText,
            globalColor: leaderboardSettings.color || leaderboardSettings.embedColor || leaderboardSettings.leaderboardColor || '',
            globalTopImageUrl: leaderboardSettings.topImageUrl || leaderboardSettings.topImage || leaderboardSettings.top || '',
            globalIntroGifUrl: leaderboardSettings.introGifUrl || leaderboardSettings.startGifUrl || leaderboardSettings.startGif || '',
            descriptionTemplate: leaderboardSettings.descriptionTemplate || leaderboardSettings.cardTemplate || leaderboardSettings.description || DEFAULT_LEADERBOARD_DESCRIPTION_TEMPLATE,
        }));
        occupiedIndex += 1;
    }

    const cards = [];
    for (let spot = 1; spot <= 10; spot += 1) {
        const occupied = occupiedBySpot.get(spot);
        if (occupied) {
            cards.push(occupied);
        } else {
            cards.push(buildLeaderboardVacantCardData(spot, {
                globalColor: leaderboardSettings.color || leaderboardSettings.embedColor || leaderboardSettings.leaderboardColor || '',
            }));
        }
    }

    return cards;
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

app.post('/api/guilds/:guildId/leaderboard/send', requireKey, async (req, res) => {
    const { channelId } = req.body;
    if (!channelId) return res.status(400).json({ error: 'No channelId provided' });
    try {
        const cards = await getLeaderboardCardsForGuild(req.params.guildId, { resolveRanks: true });
        if (!cards.length) return res.status(400).json({ error: 'No registered leaderboard profiles found.' });

        let messagesSent = 0;
        let queuedEmbeds = [];
        for (const card of cards) {
            const messageEmbeds = (card.messageEmbeds?.length ? card.messageEmbeds : [card.embed]).map(buildDiscordEmbed);
            if (messageEmbeds.length > 10) {
                return res.status(400).json({ error: 'One leaderboard card exceeds Discord embed limits.' });
            }
            if (queuedEmbeds.length && queuedEmbeds.length + messageEmbeds.length > 10) {
                await sendToDiscord(channelId, { embeds: queuedEmbeds });
                messagesSent += 1;
                queuedEmbeds = [];
            }
            queuedEmbeds.push(...messageEmbeds);
        }
        if (queuedEmbeds.length) {
            await sendToDiscord(channelId, { embeds: queuedEmbeds });
            messagesSent += 1;
        }

        res.json({ success: true, channelId, profiles: cards.length, messages: messagesSent });
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
        const [rolesRes, channelsRes, botMemberRes] = await Promise.all([
            fetch(`https://discord.com/api/v10/guilds/${guildId}/roles`, { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }),
            fetch(`https://discord.com/api/v10/guilds/${guildId}/channels`, { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }),
            fetch('https://discord.com/api/v10/users/@me', { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }),
        ]);
        if (!rolesRes.ok) return res.status(rolesRes.status).json({ error: 'Failed to fetch roles' });
        if (!channelsRes.ok) return res.status(channelsRes.status).json({ error: 'Failed to fetch channels' });
        const roles = await rolesRes.json();
        const channels = await channelsRes.json();
        const categories = channels.filter(c => c.type === 4);
        let manageableRoles = [];
        if (botMemberRes?.ok) {
            const botUser = await botMemberRes.json();
            manageableRoles = await getManageableRolesForGuild(guildId, roles, botUser?.id);
        }
        res.json({ roles, manageableRoles, channels, categories });
    } catch (err) {
        console.error('[Discord] fetch guild data failed:', err);
        res.status(500).json({ error: 'Failed to fetch guild data' });
    }
});

app.get('/api/guilds/:guildId/members/:userId', requireKey, async (req, res) => {
    if (!DISCORD_BOT_TOKEN) return res.status(500).json({ error: 'Discord bot token not configured (set BOT_TOKEN or DISCORD_BOT_TOKEN)' });
    try {
        const r = await fetch(`https://discord.com/api/v10/guilds/${req.params.guildId}/members/${req.params.userId}`, {
            headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
        });
        if (!r.ok) return res.status(r.status).json({ error: 'Failed to fetch member' });
        const member = await r.json();
        res.json({ member, roles: member.roles || [] });
    } catch (err) {
        console.error('[Discord] fetch member failed:', err);
        res.status(500).json({ error: 'Failed to fetch member' });
    }
});

app.patch('/api/guilds/:guildId/members/:userId', requireKey, async (req, res) => {
    if (!DISCORD_BOT_TOKEN) return res.status(500).json({ error: 'Discord bot token not configured (set BOT_TOKEN or DISCORD_BOT_TOKEN)' });
    try {
        const roleIds = Array.isArray(req.body.roles) ? [...new Set(req.body.roles.map(roleId => String(roleId).trim()).filter(Boolean))] : null;
        if (!roleIds) return res.status(400).json({ error: 'roles array required' });

        const rolesRes = await fetch(`https://discord.com/api/v10/guilds/${req.params.guildId}/roles`, {
            headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
        });
        if (!rolesRes.ok) return res.status(rolesRes.status).json({ error: 'Failed to fetch guild roles' });
        const guildRoles = await rolesRes.json();
        const manageableRoles = await getManageableRolesForGuild(req.params.guildId, guildRoles);
        const validRoleIds = new Set(manageableRoles.map(role => role.id).filter(roleId => roleId && roleId !== req.params.guildId));
        const safeRoles = roleIds.filter(roleId => validRoleIds.has(roleId));

        const patchRes = await fetch(`https://discord.com/api/v10/guilds/${req.params.guildId}/members/${req.params.userId}`, {
            method: 'PATCH',
            headers: {
                Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ roles: safeRoles }),
        });
        if (!patchRes.ok) {
            const errorText = await patchRes.text().catch(() => 'Failed to update member roles');
            return res.status(patchRes.status).json({ error: errorText || 'Failed to update member roles' });
        }
        const member = await patchRes.json();
        res.json({ success: true, member, roles: member.roles || safeRoles });
    } catch (err) {
        console.error('[Discord] update member roles failed:', err);
        res.status(500).json({ error: 'Failed to update member roles' });
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
    if (FALLEN_BOT_API) {
        fetch(`${FALLEN_BOT_API}/bot/config/${guildId}`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(cfg),
        }).catch(() => {});
    }
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
    const safeReason = typeof reason === 'string' && reason.trim() ? reason.trim() : 'Sin motivo';
    db.prepare('INSERT INTO warnings (guild_id, target_id, target_name, moderator_id, moderator_name, reason) VALUES (?,?,?,?,?,?)')
        .run(guildId, target_id, target_name || null, moderator_id, moderator_name || null, safeReason);
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
    leaderboard_position INTEGER,
    leaderboard_top_image_url TEXT,
    leaderboard_bottom_image_url TEXT,
    profile_score TEXT,
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
try { db.exec(`ALTER TABLE profiles ADD COLUMN leaderboard_position INTEGER`); } catch {}
try { db.exec(`ALTER TABLE profiles ADD COLUMN leaderboard_top_image_url TEXT`); } catch {}
try { db.exec(`ALTER TABLE profiles ADD COLUMN leaderboard_bottom_image_url TEXT`); } catch {}
try { db.exec(`ALTER TABLE profiles ADD COLUMN profile_score TEXT`); } catch {}

// Get all profiles
app.get('/api/profiles', requireKey, (req, res) => {
    const profiles = db.prepare('SELECT * FROM profiles ORDER BY COALESCE(leaderboard_position, 999999), updated_at DESC').all();
    res.json({ profiles });
});

app.get('/api/guilds/:guildId/leaderboard', requireKey, async (req, res) => {
    try {
        const resolveRanks = !!DISCORD_BOT_TOKEN;
        const cards = await getLeaderboardCardsForGuild(req.params.guildId, { resolveRanks });
        res.json({
            guildId: req.params.guildId,
            count: cards.length,
            cards,
            rankResolutionAvailable: resolveRanks,
        });
    } catch (err) {
        try {
            const cards = await getLeaderboardCardsForGuild(req.params.guildId, { resolveRanks: false });
            res.json({
                guildId: req.params.guildId,
                count: cards.length,
                cards,
                rankResolutionAvailable: false,
                warning: err.message,
            });
        } catch (fallbackErr) {
            res.status(500).json({ error: fallbackErr.message });
        }
    }
});

app.get('/api/guilds/:guildId/leaderboard/profiles', requireKey, async (req, res) => {
    const guildId = req.params.guildId;
    const query = String(req.query.query || req.query.q || '').trim().toLowerCase();

    try {
        let memberRows = [];
        if (FALLEN_BOT_API) {
            const memberRes = await fetchJsonWithTimeout(`${FALLEN_BOT_API}/bot/guilds/${guildId}/members`, {}, 4000).catch(() => null);
            if (memberRes?.ok) {
                const memberData = await memberRes.json().catch(() => null);
                memberRows = Array.isArray(memberData?.members) ? memberData.members : [];
            }
        }

        if (memberRows.length) {
            guildLeaderboardMemberCache.set(guildId, { updatedAt: Date.now(), members: memberRows });
        } else {
            const cached = guildLeaderboardMemberCache.get(guildId);
            if (cached && (Date.now() - cached.updatedAt) < GUILD_LEADERBOARD_MEMBER_CACHE_TTL) {
                memberRows = Array.isArray(cached.members) ? cached.members : [];
            }
        }

        const memberMap = new Map(memberRows.map(member => [String(member.id || ''), member]));
        let profiles;
        if (memberMap.size) {
            const memberIds = [...memberMap.keys()];
            const placeholders = memberIds.map(() => '?').join(',');
            profiles = db.prepare(`
                SELECT * FROM profiles
                WHERE discord_id IN (${placeholders})
                ORDER BY COALESCE(leaderboard_position, 999999), updated_at DESC
            `).all(...memberIds);
        } else {
            return res.json({
                guildId,
                profiles: [],
                count: 0,
                source: 'guild-unavailable',
                warning: 'Guild member snapshot unavailable',
            });
        }

        const enriched = profiles.map(profile => {
            const member = memberMap.get(String(profile.discord_id || '')) || null;
            return {
                ...profile,
                member_display_name: member?.displayName || member?.username || '',
                member_username: member?.username || '',
                member_global_name: member?.globalName || '',
                member_avatar_url: member?.avatarUrl || '',
            };
        });

        const filtered = query ? enriched.filter(profile => {
            const haystack = [
                profile.member_display_name,
                profile.member_username,
                profile.member_global_name,
                profile.display_name,
                profile.roblox_username,
                profile.roblox_display_name,
                profile.main_character,
                profile.discord_id,
            ].filter(Boolean).join(' ').toLowerCase();
            return haystack.includes(query);
        }) : enriched;

        res.json({
            guildId,
            profiles: filtered,
            count: filtered.length,
            source: 'guild',
        });
    } catch (err) {
        res.status(503).json({ error: err.message, source: 'guild-unavailable' });
    }
});

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
    const { discord_id, display_name, roblox_username, roblox_display_name, main_character, profile_score } = req.body;
    if (!discord_id || !display_name) return res.status(400).json({ error: 'discord_id and display_name required' });
    const existing = db.prepare('SELECT * FROM profiles WHERE discord_id = ?').get(discord_id);
    if (existing) return res.status(409).json({ error: 'Profile already exists', profile: existing });
    db.prepare('INSERT INTO profiles (discord_id, display_name, roblox_username, roblox_display_name, main_character, profile_score) VALUES (?, ?, ?, ?, ?, ?)').run(discord_id, display_name, roblox_username || null, roblox_display_name || null, main_character || null, profile_score || null);
    const profile = db.prepare('SELECT * FROM profiles WHERE discord_id = ?').get(discord_id);
    res.json({ success: true, profile });
});

// Update profile fields
app.patch('/internal/profiles/:userId', requireKey, (req, res) => {
    const profile = db.prepare('SELECT * FROM profiles WHERE discord_id = ?').get(req.params.userId);
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    const allowed = ['display_name', 'roblox_username', 'roblox_display_name', 'main_character', 'roblox_id', 'roblox_avatar_url', 'custom_color', 'banner_url', 'region', 'country', 'country_flag', 'leaderboard_position', 'leaderboard_top_image_url', 'leaderboard_bottom_image_url', 'profile_score', 'verified', 'verify_code', 'verify_expires'];
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
