// FinTrack — Express server
// Auth: bcrypt + httpOnly cookie sessions
// DB: JSON file with .bak rotation, write-mutex serialization, async I/O
// Hardened: strict static, schema validation, rate-limits, audit log

const express = require('express');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_DIR = process.env.DB_DIR || path.join(__dirname, 'db');
const DB_PATH = path.join(DB_DIR, 'db.json');
const DB_BAK_PATH = path.join(DB_DIR, 'db.json.bak');
const SESSIONS_PATH = path.join(DB_DIR, 'sessions.json');
const AUDIT_PATH = path.join(DB_DIR, 'audit.log');
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
const MAX_PASSWORD_LEN = 72; // bcrypt truncates anyway
const COOKIE_SECURE = process.env.COOKIE_SECURE !== 'false'; // secure by default
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || 'strict';
const TRUST_PROXY = parseInt(process.env.TRUST_PROXY || '1', 10);
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@fintrack.local').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const SHOW_DEFAULT_CREDS = !process.env.ADMIN_PASSWORD; // only log default if no env override

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const VALID_ROLES = new Set(['admin', 'user', 'custom']);

fs.mkdirSync(DB_DIR, { recursive: true });
app.set('trust proxy', TRUST_PROXY);

// ── Audit log ────────────────────────────────────────────────
function audit(action, ctx = {}) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    action,
    ...ctx
  }) + '\n';
  fs.appendFile(AUDIT_PATH, line, err => {
    if (err) console.error('audit write failed:', err.message);
  });
}

// ── Default DB ───────────────────────────────────────────────
function defaultDB() {
  return {
    users: [{
      id: 1,
      email: ADMIN_EMAIL,
      passwordHash: bcrypt.hashSync(ADMIN_PASSWORD, BCRYPT_ROUNDS),
      name: 'Адміністратор',
      role: 'admin',
      createdAt: new Date().toISOString()
    }],
    sites: {},
    transactions: [],
    seos: {},
    teams: ['Fortuna', 'Phoenix', 'Baza', 'Brand', 'Review'],
    categories: [],
    catIncome: ['Hybrid', 'RevShare', 'CPA', 'Flat', 'Bonus'],
    catExpense: ['Domain', 'Links', 'Host', 'Content', 'Services', 'Other'],
    currency: 'USD',
    nextTxId: 1
  };
}

// ── Async DB load with backup recovery ───────────────────────
async function loadDB() {
  // Try main file first
  try {
    const raw = await fsp.readFile(DB_PATH, 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    if (e.code === 'ENOENT') {
      // First-run: create default
      const db = defaultDB();
      await saveDBRaw(db);
      audit('db.first_run', { dbPath: DB_PATH });
      return db;
    }
    // Parse error or read error — try backup
    console.error(`DB read/parse error (${e.message}), trying backup...`);
    audit('db.main_corrupted', { error: e.message });
    try {
      const raw = await fsp.readFile(DB_BAK_PATH, 'utf-8');
      const db = JSON.parse(raw);
      console.error('Recovered from backup');
      audit('db.recovered_from_backup', {});
      return db;
    } catch (e2) {
      // No backup or backup also broken — fail HARD, never silently reset
      console.error(`DB backup also unavailable: ${e2.message}`);
      audit('db.fatal', { error: e.message, backupError: e2.message });
      throw new Error(
        `DB read failed and no backup available: ${e.message}. ` +
        `Refusing to proceed (would otherwise overwrite data with defaults). ` +
        `Manually inspect ${DB_PATH} or restore from backup.`
      );
    }
  }
}

async function saveDBRaw(db) {
  // Write to .new, copy current to .bak, atomic-rename .new → main
  const newPath = DB_PATH + '.new.' + crypto.randomBytes(6).toString('hex');
  await fsp.writeFile(newPath, JSON.stringify(db, null, 2));
  // Backup current (best effort)
  try {
    await fsp.copyFile(DB_PATH, DB_BAK_PATH);
  } catch (e) {
    if (e.code !== 'ENOENT') console.warn('backup copy failed:', e.message);
  }
  await fsp.rename(newPath, DB_PATH);
}

// ── Write-serializing mutex ──────────────────────────────────
// All read-modify-write ops must go through `withDB(fn)` to avoid races.
let _dbChain = Promise.resolve();
function withDB(fn) {
  const next = _dbChain.then(async () => {
    const db = await loadDB();
    const result = await fn(db);
    if (result && result.save !== false) await saveDBRaw(db);
    return result ? result.value : undefined;
  });
  // Don't propagate errors to next chain; isolate
  _dbChain = next.catch(() => {});
  return next;
}

// ── Sessions (file-backed, in-memory cache) ──────────────────
let SESSIONS = {};
function loadSessions() {
  try {
    const raw = fs.readFileSync(SESSIONS_PATH, 'utf-8');
    const obj = JSON.parse(raw);
    const now = Date.now();
    // Drop expired on load
    let cleaned = 0;
    for (const t in obj) if (obj[t].expiresAt < now) { delete obj[t]; cleaned++; }
    if (cleaned) console.log(`Sessions: dropped ${cleaned} expired on load`);
    return obj;
  } catch { return {}; }
}
SESSIONS = loadSessions();

let _sessionsChain = Promise.resolve();
function saveSessions() {
  _sessionsChain = _sessionsChain.then(async () => {
    const newPath = SESSIONS_PATH + '.new.' + crypto.randomBytes(6).toString('hex');
    await fsp.writeFile(newPath, JSON.stringify(SESSIONS, null, 2));
    await fsp.rename(newPath, SESSIONS_PATH);
  }).catch(e => console.error('saveSessions failed:', e.message));
  return _sessionsChain;
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  SESSIONS[token] = { userId, expiresAt: Date.now() + SESSION_TTL, createdAt: Date.now() };
  saveSessions();
  return token;
}

function destroySession(token) {
  if (token && SESSIONS[token]) {
    delete SESSIONS[token];
    saveSessions();
  }
}

function destroySessionsForUser(userId) {
  let n = 0;
  for (const t in SESSIONS) if (SESSIONS[t].userId === userId) { delete SESSIONS[t]; n++; }
  if (n) saveSessions();
  return n;
}

async function getSessionUser(token) {
  if (!token || typeof token !== 'string') return null;
  const s = SESSIONS[token];
  if (!s) return null;
  if (s.expiresAt < Date.now()) { destroySession(token); return null; }
  // Read user without holding the write-lock
  let db;
  try { db = await loadDB(); } catch { return null; }
  return db.users.find(u => u.id === s.userId) || null;
}

function sanitizeUser(u) {
  if (!u) return null;
  const { passwordHash, ...rest } = u;
  return rest;
}

function sanitizeDB(db) {
  return { ...db, users: (db.users || []).map(sanitizeUser) };
}

// ── Validation helpers ───────────────────────────────────────
function isValidEmail(s) {
  return typeof s === 'string' && EMAIL_REGEX.test(s) && s.length <= 254;
}

function isValidPassword(s) {
  return typeof s === 'string' && s.length >= 4 && s.length <= MAX_PASSWORD_LEN;
}

function isValidRole(r) {
  return typeof r === 'string' && VALID_ROLES.has(r);
}

// Whitelist user fields a client can set on a user
function pickUserFields(input) {
  if (!input || typeof input !== 'object') return {};
  const out = {};
  if (typeof input.name === 'string') out.name = input.name.slice(0, 200);
  if (isValidRole(input.role)) out.role = input.role;
  // Permissions
  if (Array.isArray(input.teams)) out.teams = input.teams.filter(t => typeof t === 'string').slice(0, 200);
  if (Array.isArray(input.categories)) out.categories = input.categories.filter(c => typeof c === 'string').slice(0, 200);
  if (Array.isArray(input.seos)) out.seos = input.seos.filter(s => typeof s === 'string').slice(0, 500);
  if (Array.isArray(input.sites)) out.sites = input.sites.filter(s => typeof s === 'string').slice(0, 5000);
  for (const flag of ['canAdd', 'canEdit', 'canDelete', 'canAnalytics', 'canImport']) {
    if (typeof input[flag] === 'boolean') out[flag] = input[flag];
  }
  return out;
}

// ── Middleware ───────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// Body limit override for /api/import (large bulk inserts)
const importJson = express.json({ limit: '60mb' });

async function requireAuth(req, res, next) {
  const user = await getSessionUser(req.cookies.ft_session);
  if (!user) return res.status(401).json({ error: 'Не авторизовано' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Тільки для адміністратора' });
  next();
}

// ── Rate limits ──────────────────────────────────────────────
function makeRateLimiter({ windowMs, max, key }) {
  const buckets = new Map();
  return (req, res, next) => {
    const k = key(req);
    const now = Date.now();
    let rec = buckets.get(k);
    if (!rec || rec.resetAt < now) {
      rec = { count: 0, resetAt: now + windowMs };
      buckets.set(k, rec);
    }
    rec.count++;
    if (rec.count > max) {
      audit('ratelimit.exceeded', { key: k, route: req.path, ip: req.ip });
      return res.status(429).json({ error: 'Забагато запитів. Спробуйте пізніше.' });
    }
    next();
  };
}

const loginRateLimit = makeRateLimiter({
  windowMs: 60_000,
  max: 10,
  key: req => 'login:' + (req.ip || 'unknown')
});

const writeRateLimit = makeRateLimiter({
  windowMs: 60_000,
  max: 120,
  key: req => 'write:' + ((req.user && req.user.id) || req.ip || 'unknown')
});

const importRateLimit = makeRateLimiter({
  windowMs: 5 * 60_000,
  max: 5,
  key: req => 'import:' + ((req.user && req.user.id) || req.ip || 'unknown')
});

// Pre-allocated dummy hash for constant-time login (prevents email enumeration)
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing-' + Math.random(), BCRYPT_ROUNDS);

// ── Auth API ─────────────────────────────────────────────────
app.post('/api/login', loginRateLimit, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    // Type guards FIRST — never trust input shape
    if (!isValidEmail(email) || !isValidPassword(password)) {
      // Burn timing budget anyway to prevent enum
      bcrypt.compareSync(String(password || '').slice(0, MAX_PASSWORD_LEN), DUMMY_HASH);
      return res.status(401).json({ error: 'Невірні облікові дані' });
    }
    const db = await loadDB();
    const user = (db.users || []).find(u => typeof u.email === 'string' && u.email.toLowerCase() === email.toLowerCase());
    const hash = (user && typeof user.passwordHash === 'string') ? user.passwordHash : DUMMY_HASH;
    const ok = bcrypt.compareSync(password, hash);
    if (!user || !ok) {
      audit('login.fail', { email: email.toLowerCase(), ip: req.ip });
      return res.status(401).json({ error: 'Невірні облікові дані' });
    }
    const token = createSession(user.id);
    res.cookie('ft_session', token, {
      httpOnly: true,
      sameSite: COOKIE_SAMESITE,
      maxAge: SESSION_TTL,
      secure: COOKIE_SECURE,
      path: '/'
    });
    audit('login.ok', { userId: user.id, email: user.email, ip: req.ip });
    res.json({ user: sanitizeUser(user) });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ error: 'Внутрішня помилка' });
  }
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies.ft_session;
  destroySession(token);
  res.clearCookie('ft_session', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', async (req, res) => {
  const user = await getSessionUser(req.cookies.ft_session);
  if (!user) return res.status(401).json({ error: 'Не авторизовано' });
  res.json({ user: sanitizeUser(user) });
});

app.post('/api/change-password', requireAuth, writeRateLimit, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body || {};
    if (!isValidPassword(oldPassword) || !isValidPassword(newPassword)) {
      return res.status(400).json({ error: 'Пароль 4–72 символи' });
    }
    await withDB(async (db) => {
      const user = (db.users || []).find(u => u.id === req.user.id);
      if (!user || !bcrypt.compareSync(oldPassword, user.passwordHash || '')) {
        const err = new Error('Невірний поточний пароль');
        err.status = 401;
        throw err;
      }
      user.passwordHash = bcrypt.hashSync(newPassword, BCRYPT_ROUNDS);
      audit('password.change', { userId: req.user.id });
      // Invalidate all OTHER sessions of this user; keep current
      const cur = req.cookies.ft_session;
      let dropped = 0;
      for (const t in SESSIONS) {
        if (SESSIONS[t].userId === user.id && t !== cur) { delete SESSIONS[t]; dropped++; }
      }
      if (dropped) saveSessions();
      return { value: { ok: true } };
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Помилка' });
  }
});

// ── DB API ───────────────────────────────────────────────────
app.get('/api/db', requireAuth, async (req, res) => {
  try {
    const db = await loadDB();
    res.json(sanitizeDB(db));
  } catch (e) {
    res.status(500).json({ error: 'Помилка читання БД: ' + e.message });
  }
});

// PUT /api/db — admin only. Strict whitelist: cannot manipulate users
// through this endpoint (use /api/users for that).
app.put('/api/db', requireAuth, requireAdmin, writeRateLimit, async (req, res) => {
  try {
    const incoming = req.body;
    if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
      return res.status(400).json({ error: 'Невалідне тіло запиту' });
    }
    await withDB(async (db) => {
      // Whitelist top-level keys we accept from client
      const allowed = ['sites', 'transactions', 'seos', 'teams', 'categories', 'catIncome', 'catExpense', 'currency', 'nextTxId', 'eurRate'];
      for (const k of allowed) {
        if (k in incoming) db[k] = incoming[k];
      }
      // NOTE: users intentionally not accepted here.
      // Use /api/users{,/:id} for user CRUD so passwords are properly hashed
      // and role/email are validated.
      audit('db.put', { userId: req.user.id, keys: Object.keys(incoming).filter(k => allowed.includes(k)) });
      return { value: { ok: true } };
    });
    res.json({ ok: true });
  } catch (e) {
    console.error('PUT /api/db:', e);
    res.status(500).json({ error: e.message || 'Помилка' });
  }
});

// ── Users API ────────────────────────────────────────────────
app.post('/api/users', requireAuth, requireAdmin, writeRateLimit, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const fields = pickUserFields(req.body);
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Некоректний email' });
    if (!isValidPassword(password)) return res.status(400).json({ error: 'Пароль 4–72 символи' });
    const result = await withDB(async (db) => {
      db.users = db.users || [];
      if (db.users.find(u => typeof u.email === 'string' && u.email.toLowerCase() === email.toLowerCase())) {
        const err = new Error('Користувач з таким email вже існує');
        err.status = 400;
        throw err;
      }
      const newUser = {
        id: db.users.reduce((m, u) => Math.max(m, u.id || 0), 0) + 1,
        email: email.toLowerCase(),
        passwordHash: bcrypt.hashSync(password, BCRYPT_ROUNDS),
        createdAt: new Date().toISOString(),
        ...fields,
        role: fields.role || 'user'
      };
      db.users.push(newUser);
      audit('user.create', { actor: req.user.id, target: newUser.id, email: newUser.email, role: newUser.role });
      return { value: { user: sanitizeUser(newUser) } };
    });
    res.json(result);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Помилка' });
  }
});

app.put('/api/users/:id', requireAuth, requireAdmin, writeRateLimit, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Невалідний id' });
    const fields = pickUserFields(req.body || {});
    const newPass = req.body && req.body.password;
    if (newPass != null && !isValidPassword(newPass)) {
      return res.status(400).json({ error: 'Пароль 4–72 символи' });
    }
    const result = await withDB(async (db) => {
      const user = (db.users || []).find(u => u.id === id);
      if (!user) {
        const err = new Error('Користувача не знайдено'); err.status = 404; throw err;
      }
      // Block last-admin demotion (including self-demotion)
      if (fields.role && fields.role !== 'admin' && user.role === 'admin') {
        const adminCount = db.users.filter(u => u.role === 'admin').length;
        if (adminCount <= 1) {
          const err = new Error('Не можна понизити роль останнього адміністратора');
          err.status = 400; throw err;
        }
      }
      const auditFields = {};
      for (const k of Object.keys(fields)) {
        if (user[k] !== fields[k]) auditFields[k] = { from: user[k], to: fields[k] };
        user[k] = fields[k];
      }
      if (newPass) {
        user.passwordHash = bcrypt.hashSync(newPass, BCRYPT_ROUNDS);
        // invalidate other sessions of this user
        destroySessionsForUser(id);
        auditFields.password = 'changed';
      }
      audit('user.update', { actor: req.user.id, target: id, changes: auditFields });
      return { value: { user: sanitizeUser(user) } };
    });
    res.json(result);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Помилка' });
  }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, writeRateLimit, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Невалідний id' });
    if (id === req.user.id) return res.status(400).json({ error: 'Не можна видалити власний акаунт' });
    await withDB(async (db) => {
      const user = (db.users || []).find(u => u.id === id);
      if (!user) {
        const err = new Error('Користувача не знайдено'); err.status = 404; throw err;
      }
      // Block deleting the last admin
      if (user.role === 'admin') {
        const adminCount = db.users.filter(u => u.role === 'admin').length;
        if (adminCount <= 1) {
          const err = new Error('Не можна видалити останнього адміністратора');
          err.status = 400; throw err;
        }
      }
      db.users = db.users.filter(u => u.id !== id);
      destroySessionsForUser(id);
      audit('user.delete', { actor: req.user.id, target: id, email: user.email });
      return { value: { ok: true } };
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Помилка' });
  }
});

// ── Bulk import ──────────────────────────────────────────────
app.post('/api/import', requireAuth, requireAdmin, importRateLimit, importJson, async (req, res) => {
  try {
    const { transactions = [], sites = {}, teams = [], categories = [], dedupe = true } = req.body || {};
    if (!Array.isArray(transactions)) return res.status(400).json({ error: 'transactions має бути масивом' });
    if (transactions.length > 200000) return res.status(400).json({ error: 'Забагато транзакцій (>200k)' });

    const result = await withDB(async (db) => {
      db.transactions = db.transactions || [];
      db.sites = db.sites || {};
      db.teams = db.teams || [];
      db.categories = db.categories || [];
      db.nextTxId = db.nextTxId || (db.transactions.reduce((m, t) => Math.max(m, t.id || 0), 0) + 1);

      let addedTeams = 0, addedCats = 0, addedSites = 0;
      for (const t of teams) {
        if (typeof t === 'string' && t && !db.teams.includes(t)) { db.teams.push(t); addedTeams++; }
      }
      for (const c of categories) {
        if (typeof c === 'string' && c && !db.categories.includes(c)) { db.categories.push(c); addedCats++; }
      }
      for (const [domain, info] of Object.entries(sites || {})) {
        if (typeof domain !== 'string' || !domain) continue;
        if (!db.sites[domain]) {
          // Whitelist info fields to avoid prototype/property pollution
          const safe = {};
          if (info && typeof info === 'object') {
            if (typeof info.team === 'string') safe.team = info.team;
            if (typeof info.seo === 'string') safe.seo = info.seo;
            if (typeof info.seoName === 'string') safe.seoName = info.seoName;
          }
          safe.createdAt = new Date().toISOString();
          db.sites[domain] = safe;
          addedSites++;
        }
      }

      const hash = t => `${t.date}|${Number(t.amount).toFixed(2)}|${t.site || ''}|${(t.description || '').trim().slice(0, 200)}`;
      const existingHashes = dedupe ? new Set(db.transactions.map(hash)) : null;

      let added = 0, skipped = 0;
      for (const t of transactions) {
        if (!t || typeof t !== 'object') { skipped++; continue; }
        if (!t.date || t.amount == null) { skipped++; continue; }
        if (dedupe && existingHashes.has(hash(t))) { skipped++; continue; }
        // Whitelist transaction fields
        const tx = {
          id: db.nextTxId++,
          date: String(t.date),
          amount: Number(t.amount),
          description: typeof t.description === 'string' ? t.description.slice(0, 1000) : '',
          category: typeof t.category === 'string' ? t.category : '',
          team: typeof t.team === 'string' ? t.team : '',
          site: typeof t.site === 'string' ? t.site : '',
          counterparty: typeof t.counterparty === 'string' ? t.counterparty : '',
          tags: typeof t.tags === 'string' ? t.tags : '',
          splitGroup: Number.isInteger(t.splitGroup) ? t.splitGroup : null,
          source: 'finmap-import',
          importedAt: new Date().toISOString(),
          createdBy: req.user.id
        };
        db.transactions.push(tx);
        if (existingHashes) existingHashes.add(hash(tx));
        added++;
      }
      audit('import', { actor: req.user.id, added, skipped, addedSites, addedTeams, addedCats });
      return { value: { ok: true, added, skipped, addedSites, addedTeams, addedCats } };
    });
    res.json(result);
  } catch (e) {
    console.error('import error:', e);
    res.status(e.status || 500).json({ error: e.message || 'Помилка імпорту' });
  }
});

// ── Static (strictly limited to specific files) ──────────────
// IMPORTANT: do NOT use express.static(__dirname). That would expose
// server.js, package.json, db/db.json with password hashes, etc.
const ALLOWED_STATIC = new Set(['/', '/index.html', '/favicon.ico']);
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/index.html', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/favicon.ico', (_req, res) => {
  // Tiny inline favicon, no real file needed
  res.set('Content-Type', 'image/svg+xml');
  res.send('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><rect width="16" height="16" rx="3" fill="#00e5a0"/><text x="3" y="12" font-family="sans-serif" font-size="10" fill="#000" font-weight="700">FT</text></svg>');
});

// SPA fallback for client-side routes (refresh on /sites, /tx, etc.)
// Anything starting with /api falls through to 404.
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  // Refuse path traversal attempts
  if (req.path.includes('..') || /[^a-zA-Z0-9_\-./?#]/.test(req.path)) {
    return res.status(400).send('Bad path');
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// 404 for /api/*
app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found' }));

// Generic error handler — never leak stack traces in prod
app.use((err, _req, res, _next) => {
  console.error('unhandled:', err);
  res.status(500).json({ error: 'Internal error' });
});

// Periodic cleanup of expired sessions
setInterval(() => {
  const now = Date.now();
  let n = 0;
  for (const t in SESSIONS) if (SESSIONS[t].expiresAt < now) { delete SESSIONS[t]; n++; }
  if (n) saveSessions();
}, 60 * 60 * 1000);

// ── Start ─────────────────────────────────────────────────────
async function ensureFirstRun() {
  try {
    await loadDB();
  } catch (e) {
    console.error('FATAL: cannot load DB at startup:', e.message);
    console.error('Refusing to start. Inspect/restore db/db.json manually.');
    process.exit(1);
  }
}

ensureFirstRun().then(() => {
  app.listen(PORT, () => {
    console.log(`FinTrack listening on :${PORT}`);
    console.log(`DB dir: ${DB_DIR}`);
    if (SHOW_DEFAULT_CREDS) {
      console.log('');
      console.log('  ⚠  DEFAULT ADMIN: ' + ADMIN_EMAIL + ' / ' + ADMIN_PASSWORD);
      console.log('  ⚠  Set ADMIN_PASSWORD env var on next deploy and change in UI immediately.');
      console.log('');
    }
    if (!COOKIE_SECURE) console.warn('  ⚠  Cookies are NOT secure (HTTP allowed). Set COOKIE_SECURE=true behind HTTPS.');
  });
});
