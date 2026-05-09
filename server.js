// FinTrack — Express server with bcrypt + cookie sessions
// JSON-file DB. Mount /db as a persistent disk in production.

const express = require('express');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_DIR = process.env.DB_DIR || path.join(__dirname, 'db');
const DB_PATH = path.join(DB_DIR, 'db.json');
const SESSIONS_PATH = path.join(DB_DIR, 'sessions.json');
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000; // 7 днів
const BCRYPT_ROUNDS = 10;

fs.mkdirSync(DB_DIR, { recursive: true });

// ── DB helpers ────────────────────────────────────────────────
function defaultDB() {
  return {
    users: [{
      id: 1,
      email: 'admin@fintrack.local',
      passwordHash: bcrypt.hashSync('admin', BCRYPT_ROUNDS),
      name: 'Адміністратор',
      role: 'admin',
      createdAt: new Date().toISOString()
    }],
    sites: {},
    transactions: [],
    seos: [],
    teams: ['Fortuna', 'Phoenix', 'Baza', 'Brand', 'Review'],
    categories: ['Salary', 'Hosting', 'Domain', 'Tools', 'Other'],
    currency: 'USD',
    nextTxId: 1
  };
}

function loadDB() {
  if (!fs.existsSync(DB_PATH)) {
    const db = defaultDB();
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
    return db;
  }
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
  } catch (e) {
    console.error('DB read error:', e);
    return defaultDB();
  }
}

function saveDB(db) {
  const tmp = DB_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_PATH);
}

function loadSessions() {
  if (!fs.existsSync(SESSIONS_PATH)) return {};
  try { return JSON.parse(fs.readFileSync(SESSIONS_PATH, 'utf-8')); }
  catch { return {}; }
}

function saveSessions(s) {
  const tmp = SESSIONS_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(s, null, 2));
  fs.renameSync(tmp, SESSIONS_PATH);
}

let SESSIONS = loadSessions();

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  SESSIONS[token] = { userId, expiresAt: Date.now() + SESSION_TTL };
  saveSessions(SESSIONS);
  return token;
}

function destroySession(token) {
  if (SESSIONS[token]) {
    delete SESSIONS[token];
    saveSessions(SESSIONS);
  }
}

function getSessionUser(token) {
  if (!token) return null;
  const s = SESSIONS[token];
  if (!s) return null;
  if (s.expiresAt < Date.now()) { destroySession(token); return null; }
  const db = loadDB();
  return db.users.find(u => u.id === s.userId) || null;
}

function sanitizeUser(u) {
  if (!u) return null;
  const { passwordHash, ...rest } = u;
  return rest;
}

function sanitizeDB(db) {
  return { ...db, users: db.users.map(sanitizeUser) };
}

// ── Middleware ────────────────────────────────────────────────
app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());

function requireAuth(req, res, next) {
  const user = getSessionUser(req.cookies.ft_session);
  if (!user) return res.status(401).json({ error: 'Не авторизовано' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ лише адміністратору' });
  next();
}

// Прості rate-limits на /api/login
const loginAttempts = new Map();
function loginRateLimit(req, res, next) {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const now = Date.now();
  const rec = loginAttempts.get(ip) || { count: 0, resetAt: now + 60_000 };
  if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + 60_000; }
  rec.count++;
  loginAttempts.set(ip, rec);
  if (rec.count > 10) return res.status(429).json({ error: 'Забагато спроб. Спробуйте за хвилину.' });
  next();
}

// ── Auth API ──────────────────────────────────────────────────
app.post('/api/login', loginRateLimit, (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email і пароль обов\'язкові' });
  const db = loadDB();
  const user = db.users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Невірні облікові дані' });
  }
  const token = createSession(user.id);
  res.cookie('ft_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: SESSION_TTL,
    secure: process.env.NODE_ENV === 'production'
  });
  res.json({ user: sanitizeUser(user) });
});

app.post('/api/logout', (req, res) => {
  destroySession(req.cookies.ft_session);
  res.clearCookie('ft_session');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const user = getSessionUser(req.cookies.ft_session);
  if (!user) return res.status(401).json({ error: 'Не авторизовано' });
  res.json({ user: sanitizeUser(user) });
});

app.post('/api/change-password', requireAuth, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Заповніть всі поля' });
  if (newPassword.length < 4) return res.status(400).json({ error: 'Пароль має бути не менше 4 символів' });
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user || !bcrypt.compareSync(oldPassword, user.passwordHash)) {
    return res.status(401).json({ error: 'Невірний поточний пароль' });
  }
  user.passwordHash = bcrypt.hashSync(newPassword, BCRYPT_ROUNDS);
  saveDB(db);
  res.json({ ok: true });
});

// ── DB API (захищено) ─────────────────────────────────────────
app.get('/api/db', requireAuth, (req, res) => {
  res.json(sanitizeDB(loadDB()));
});

// Тільки адмін має право переписувати весь DB
app.put('/api/db', requireAuth, requireAdmin, (req, res) => {
  const incoming = req.body;
  if (!incoming || typeof incoming !== 'object') {
    return res.status(400).json({ error: 'Невалідне тіло запиту' });
  }
  const current = loadDB();
  // Зберігаємо хеші паролів існуючих юзерів — клієнт їх не отримує
  if (Array.isArray(incoming.users)) {
    incoming.users = incoming.users.map(u => {
      const existing = current.users.find(x => x.id === u.id);
      if (existing) {
        return { ...u, passwordHash: existing.passwordHash };
      }
      // Новий юзер без хешу — пропускаємо (треба використовувати /api/users)
      return null;
    }).filter(Boolean);
  } else {
    incoming.users = current.users;
  }
  saveDB(incoming);
  res.json({ ok: true });
});

// ── User management (admin) ───────────────────────────────────
app.post('/api/users', requireAuth, requireAdmin, (req, res) => {
  const { email, password, name, role, ...perms } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email і пароль обов\'язкові' });
  if (password.length < 4) return res.status(400).json({ error: 'Пароль має бути не менше 4 символів' });
  const db = loadDB();
  if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ error: 'Користувач з таким email вже існує' });
  }
  const newUser = {
    id: (db.users.reduce((m, u) => Math.max(m, u.id), 0) + 1),
    email,
    passwordHash: bcrypt.hashSync(password, BCRYPT_ROUNDS),
    name: name || email,
    role: role === 'admin' ? 'admin' : 'user',
    createdAt: new Date().toISOString(),
    ...perms
  };
  db.users.push(newUser);
  saveDB(db);
  res.json({ user: sanitizeUser(newUser) });
});

app.put('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const db = loadDB();
  const user = db.users.find(u => u.id === id);
  if (!user) return res.status(404).json({ error: 'Користувача не знайдено' });
  const { password, passwordHash: _ph, id: _id, ...rest } = req.body || {};
  Object.assign(user, rest);
  if (password) user.passwordHash = bcrypt.hashSync(password, BCRYPT_ROUNDS);
  saveDB(db);
  res.json({ user: sanitizeUser(user) });
});

app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: 'Не можна видалити власний акаунт' });
  const db = loadDB();
  const before = db.users.length;
  db.users = db.users.filter(u => u.id !== id);
  if (db.users.length === before) return res.status(404).json({ error: 'Не знайдено' });
  // Видаляємо активні сесії цього юзера
  for (const t in SESSIONS) if (SESSIONS[t].userId === id) delete SESSIONS[t];
  saveSessions(SESSIONS);
  saveDB(db);
  res.json({ ok: true });
});

// ── Bulk import (Finmap) ──────────────────────────────────────
// Body: { transactions: [...], sites: {domain: {team,...}}, teams: [str], categories: [str], dedupe: true }
app.post('/api/import', requireAuth, requireAdmin, (req, res) => {
  const { transactions = [], sites = {}, teams = [], categories = [], dedupe = true } = req.body || {};
  if (!Array.isArray(transactions)) return res.status(400).json({ error: 'transactions має бути масивом' });

  const db = loadDB();
  db.transactions = db.transactions || [];
  db.sites = db.sites || {};
  db.teams = db.teams || [];
  db.categories = db.categories || [];
  db.nextTxId = db.nextTxId || (db.transactions.reduce((m, t) => Math.max(m, t.id || 0), 0) + 1);

  // Add new teams / categories
  let addedTeams = 0, addedCats = 0;
  for (const t of teams) if (t && !db.teams.includes(t)) { db.teams.push(t); addedTeams++; }
  for (const c of categories) if (c && !db.categories.includes(c)) { db.categories.push(c); addedCats++; }

  // Add new sites
  let addedSites = 0;
  for (const [domain, info] of Object.entries(sites)) {
    if (!domain) continue;
    if (!db.sites[domain]) {
      db.sites[domain] = { ...(info || {}), createdAt: new Date().toISOString() };
      addedSites++;
    }
  }

  // Build dedupe index
  const hash = t => `${t.date}|${Number(t.amount).toFixed(2)}|${t.site || ''}|${(t.description || '').trim()}`;
  const existingHashes = dedupe ? new Set(db.transactions.map(hash)) : null;

  let added = 0, skipped = 0;
  for (const t of transactions) {
    if (!t || typeof t !== 'object') { skipped++; continue; }
    if (!t.date || t.amount == null) { skipped++; continue; }
    if (dedupe && existingHashes.has(hash(t))) { skipped++; continue; }
    const tx = {
      id: db.nextTxId++,
      date: t.date,
      amount: Number(t.amount),
      description: t.description || '',
      category: t.category || '',
      team: t.team || '',
      site: t.site || '',
      counterparty: t.counterparty || '',
      tags: t.tags || '',
      source: 'finmap-import',
      importedAt: new Date().toISOString(),
      createdBy: req.user.id
    };
    db.transactions.push(tx);
    if (existingHashes) existingHashes.add(hash(tx));
    added++;
  }

  saveDB(db);
  res.json({ ok: true, added, skipped, addedSites, addedTeams, addedCats });
});

// ── Static / SPA ──────────────────────────────────────────────
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.use(express.static(__dirname, { index: false }));

// Будь-який інший GET повертає SPA (для рефрешу)
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Cleanup expired sessions ──────────────────────────────────
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const t in SESSIONS) {
    if (SESSIONS[t].expiresAt < now) { delete SESSIONS[t]; changed = true; }
  }
  if (changed) saveSessions(SESSIONS);
}, 60 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`FinTrack listening on :${PORT}`);
  console.log(`Default login (зміни одразу!): admin@fintrack.local / admin`);
  console.log(`DB dir: ${DB_DIR}`);
});
