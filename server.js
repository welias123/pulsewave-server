const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3333;

// ── JWT Secret ────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  const f = path.join(__dirname, 'data', '.secret');
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8').trim();
  const s = crypto.randomBytes(48).toString('hex');
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, s);
  return s;
})();

// ── Database: PostgreSQL (Render) or JSON file (local) ────────────────────
let pool = null;
if (process.env.DATABASE_URL) {
  const { Pool } = require('pg');
  pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id           SERIAL PRIMARY KEY,
      email        TEXT UNIQUE NOT NULL,
      username     TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    )
  `).then(() => console.log('✅ PostgreSQL connected')).catch(console.error);
}

// JSON file fallback (local dev)
const DB_FILE = path.join(__dirname, 'data', 'users.json');
function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { users: [] };
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return { users: [] }; }
}
function saveDB(db) {
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function nextId(arr) { return arr.length ? Math.max(...arr.map(x => x.id)) + 1 : 1; }

// ── DB helpers (work for both PG and JSON) ────────────────────────────────
async function findByEmail(email) {
  if (pool) {
    const r = await pool.query('SELECT * FROM users WHERE lower(email)=$1', [email.toLowerCase()]);
    return r.rows[0] || null;
  }
  return loadDB().users.find(u => u.email.toLowerCase() === email.toLowerCase()) || null;
}
async function findByUsername(username) {
  if (pool) {
    const r = await pool.query('SELECT * FROM users WHERE lower(username)=$1', [username.toLowerCase()]);
    return r.rows[0] || null;
  }
  return loadDB().users.find(u => u.username.toLowerCase() === username.toLowerCase()) || null;
}
async function findById(id) {
  if (pool) {
    const r = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
    return r.rows[0] || null;
  }
  return loadDB().users.find(u => u.id === id) || null;
}
async function insertUser(email, username, hash) {
  if (pool) {
    const r = await pool.query(
      'INSERT INTO users (email,username,password_hash) VALUES ($1,$2,$3) RETURNING id,email,username,created_at',
      [email.toLowerCase().trim(), username.trim(), hash]
    );
    return r.rows[0];
  }
  const db = loadDB();
  const user = { id: nextId(db.users), email: email.toLowerCase().trim(), username: username.trim(), passwordHash: hash, createdAt: new Date().toISOString() };
  db.users.push(user);
  saveDB(db);
  return user;
}
async function deleteById(id) {
  if (pool) { await pool.query('DELETE FROM users WHERE id=$1', [id]); return; }
  const db = loadDB();
  db.users = db.users.filter(u => u.id !== id);
  saveDB(db);
}

// ── Middleware ────────────────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(auth.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── Validation ────────────────────────────────────────────────────────────
function isValidEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }
function isValidUsername(u) { return /^[a-zA-Z0-9_]{3,20}$/.test(u); }

// ── POST /api/register ────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password)
    return res.status(400).json({ error: 'E-Mail, Benutzername und Passwort erforderlich' });
  if (!isValidEmail(email))
    return res.status(400).json({ error: 'Ungültige E-Mail-Adresse' });
  if (!isValidUsername(username))
    return res.status(400).json({ error: 'Benutzername: 3–20 Zeichen, nur Buchstaben/Zahlen/_' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Passwort muss mindestens 6 Zeichen haben' });

  try {
    if (await findByEmail(email))    return res.status(409).json({ error: 'E-Mail bereits registriert' });
    if (await findByUsername(username)) return res.status(409).json({ error: 'Benutzername bereits vergeben' });

    const hash = await bcrypt.hash(password, 12);
    const user = await insertUser(email, username, hash);
    const token = jwt.sign({ userId: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ token, user: { id: user.id, username: user.username, email: user.email } });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server-Fehler' }); }
});

// ── POST /api/login ───────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich' });

  try {
    const user = await findByEmail(email);
    if (!user) return res.status(401).json({ error: 'E-Mail oder Passwort falsch' });

    const pwHash = user.password_hash || user.passwordHash;
    const ok = await bcrypt.compare(password, pwHash);
    if (!ok) return res.status(401).json({ error: 'E-Mail oder Passwort falsch' });

    const token = jwt.sign({ userId: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server-Fehler' }); }
});

// ── GET /api/me ───────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: { id: req.user.userId, username: req.user.username, email: req.user.email } });
});

// ── DELETE /api/account ───────────────────────────────────────────────────
app.delete('/api/account', requireAuth, async (req, res) => {
  await deleteById(req.user.userId);
  res.json({ ok: true });
});

// ── SPA fallback ──────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🎵 Pulsewave server on http://localhost:${PORT}`);
  console.log(`   Mode: ${pool ? 'PostgreSQL (production)' : 'JSON file (local dev)'}`);
});
